'use strict';

const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');

const { SnowflakeGenerator } = require('./snowflake');
const { AccessControlList, DB_PERMISSIONS } = require('./rbac');
const { deriveManifestKeyFromKek, randomKey, wrapKey, unwrapKey, aesGcmEncrypt, aesGcmDecrypt } = require('./crypto-core');
const { ClientSecretKeyProvider, randomClientSecret } = require('./key-provider');
const { Database } = require('./database');
const { mk } = require('./logger');

// Manifest = small, infrequently-read structural metadata (schema definitions, ACL, wrapped
// DDK). Encrypted as a whole with AES-256-GCM under manifestKey, plaintext JSON before
// encryption — this is the one deliberate JSON use in the whole engine: it's tiny, not on
// the hot path, and using JSON here buys real implementation simplicity for zero measurable
// cost. Every actual DATA record, by contrast, goes through the binary TLV codec
// (lib/binary-codec.js) and is what the "more efficient than JSON" requirement is about.
class DatabaseManager {
  constructor({ baseDir, snowflake, sessionTtlMs = 15 * 60 * 1000, logger = null }) {
    this.baseDir = baseDir;
    this.log = logger || mk('fitdb:manager');
    this.snowflake = snowflake || new SnowflakeGenerator();
    this.sessionTtlMs = sessionTtlMs;
    this.sessions = new Map(); // dbId -> { ddk, timer }
    this.openDatabases = new Map(); // dbId -> Database
    // dbId -> Promise<Database> for an open that is currently in flight.
    //
    // Without this, `openDatabases.has(dbId)` is a check-then-act across an await: every
    // request that arrives while a database is being opened misses the check and starts its
    // own open. Each one builds a second Database, and with it a second CollectionStorage per
    // collection -- a second append file handle, a second read-FD pool, a second in-memory
    // index. Only the last one to finish ends up in `openDatabases`; the rest are unreachable,
    // so closeDatabase() cannot close them and their descriptors survive until GC.
    //
    // Both consequences are severe. The descriptors accumulate per burst of concurrent
    // requests, and once the process hits its file-descriptor limit every open() AND every
    // accept() on the TLS listener fails, so the server stops answering all clients at once
    // and only a restart clears it. Meanwhile any handle that is not the registered one tracks
    // its own `activeSegmentOffset` over the same segment file, so writes through it record
    // locations that do not match what is on disk and reads come back as AEAD authentication
    // failures. Sharing one in-flight promise makes concurrent openers converge on a single
    // handle, which is the invariant the rest of the engine already assumes.
    this._opening = new Map();
    this._manifestWrites = new Map(); // dbId -> tail of the serialized manifest write chain
    this._catalogWrites = new Map();  // ownerId -> tail of the serialized catalog write chain
  }

  _dbDir(ownerId, dbId) { return path.join(this.baseDir, String(ownerId), String(dbId)); }
  _catalogPath(ownerId) { return path.join(this.baseDir, String(ownerId), '_catalog.json'); }
  _idGen() { return () => this.snowflake.nextIdString(); }

  _cacheSession(dbId, ddk) {
    const existing = this.sessions.get(dbId);
    if (existing?.timer) clearTimeout(existing.timer);
    const timer = this.sessionTtlMs > 0
      ? setTimeout(() => this.sessions.delete(dbId), this.sessionTtlMs).unref()
      : null;
    this.sessions.set(dbId, { ddk, timer });
  }

  // ---- manifest I/O ----------------------------------------------------------------------

  /**
   * Encrypts and atomically replaces a database's manifest.
   *
   * Serialized per database, and via a temp file whose name is unique per write. A single
   * shared `manifest.bin.tmp` was safe only while one caller could ever be writing: with
   * several clients defining collections and granting access on the same database, two writes
   * interleave into that one file and the rename publishes whichever bytes happen to be there.
   * Serializing also removes the lost-update window where a writer that serialized its
   * snapshot first renames last and discards a newer change.
   */
  async _writeManifest(dir, manifestKey, manifest) {
    const dbId = manifest?.dbId || dir;
    const previous = this._manifestWrites.get(dbId) || Promise.resolve();
    const task = previous.then(async () => {
      const plaintext = Buffer.from(JSON.stringify(manifest), 'utf8');
      const enc = aesGcmEncrypt(manifestKey, plaintext);
      const tmp = path.join(dir, `manifest.bin.${crypto.randomBytes(6).toString('hex')}.tmp`);
      try {
        await fsp.writeFile(tmp, enc);
        await fsp.rename(tmp, path.join(dir, 'manifest.bin'));
      } catch (err) {
        await fsp.unlink(tmp).catch(() => {});
        throw err;
      }
    });
    const tail = task.then(() => undefined, () => undefined);
    this._manifestWrites.set(dbId, tail);
    try {
      await task;
    } finally {
      if (this._manifestWrites.get(dbId) === tail) this._manifestWrites.delete(dbId);
    }
  }

  async _readManifest(dir, manifestKey) {
    const buf = await fsp.readFile(path.join(dir, 'manifest.bin'));
    const plaintext = aesGcmDecrypt(manifestKey, buf); // throws on wrong key (auth tag mismatch)
    return JSON.parse(plaintext.toString('utf8'));
  }

  // Read-modify-write, so it is serialized per owner: two clients creating a database at the
  // same time would otherwise both read the same list and the second write would drop the
  // first one's entry. Written through a temp file for the same reason as the manifest.
  async _appendCatalog(ownerId, entry) {
    const previous = this._catalogWrites.get(String(ownerId)) || Promise.resolve();
    const task = previous.then(async () => {
      const p = this._catalogPath(ownerId);
      let list = [];
      try { list = JSON.parse(await fsp.readFile(p, 'utf8')); } catch (_) {}
      if (!Array.isArray(list)) list = [];
      list.push(entry);
      await fsp.mkdir(path.dirname(p), { recursive: true });
      const tmp = `${p}.${crypto.randomBytes(6).toString('hex')}.tmp`;
      try {
        await fsp.writeFile(tmp, JSON.stringify(list));
        await fsp.rename(tmp, p);
      } catch (err) {
        await fsp.unlink(tmp).catch(() => {});
        throw err;
      }
    });
    const tail = task.then(() => undefined, () => undefined);
    this._catalogWrites.set(String(ownerId), tail);
    try {
      await task;
    } finally {
      if (this._catalogWrites.get(String(ownerId)) === tail) this._catalogWrites.delete(String(ownerId));
    }
  }

  // Non-authoritative convenience listing (dbId/name/createdAt only — no schema, no ACL, no
  // key material). Deliberately plaintext: this is a discovery aid, not protected data: it
  // reveals the same information a directory listing of the owner's folder already would.
  async listDatabases(ownerId) {
    try { return JSON.parse(await fsp.readFile(this._catalogPath(ownerId), 'utf8')); }
    catch (_) { return []; }
  }

  // ---- create / open ----------------------------------------------------------------------

  async createDatabase({ ownerId, name, keyProvider = null }) {
    let clientSecretOut = null;
    if (!keyProvider) {
      const secret = randomClientSecret();
      clientSecretOut = secret.toString('base64'); // returned exactly once, never persisted
      keyProvider = new ClientSecretKeyProvider(secret);
    }

    const dbId = this.snowflake.nextIdString();
    const dbIdBuf = Buffer.from(dbId);
    const kek = await keyProvider.deriveKek(dbIdBuf);
    const ddk = randomKey(32);
    const wrappedDDK = wrapKey(kek, ddk);
    const acl = new AccessControlList(ownerId);

    const manifest = {
      dbId, name, ownerId,
      wrappedDDK: wrappedDDK.toString('base64'),
      acl: acl.toJSON(),
      collections: {},
      createdAt: Date.now(),
    };

    const dir = this._dbDir(ownerId, dbId);
    await fsp.mkdir(path.join(dir, 'collections'), { recursive: true });
    const manifestKey = deriveManifestKeyFromKek(kek, dbIdBuf);
    await this._writeManifest(dir, manifestKey, manifest);
    await this._appendCatalog(ownerId, { dbId, name, createdAt: manifest.createdAt });

    this._cacheSession(dbId, ddk);
    const persistManifest = (m) => this._writeManifest(dir, manifestKey, m);
    const db = new Database({ dbId, name, dir, ddk, acl, manifest, idGenerator: this._idGen(), persistManifest, logger: this.log });
    this.openDatabases.set(dbId, db);
    this.log.info({ dbId, name, ownerId, dir, msg: 'database created' });
    return { db, dbId, clientSecret: clientSecretOut };
  }

  async openDatabase({ ownerId, dbId, requesterId, keyProvider, requiredPermission = DB_PERMISSIONS.READ }) {
    const open = this.openDatabases.get(dbId);
    if (open) return this._attachToOpen(open, { dbId, requesterId, keyProvider, requiredPermission });

    // A second caller arriving mid-open waits for the first one's handle rather than building
    // a rival one, then goes through exactly the same key and ACL checks against it.
    const inFlight = this._opening.get(dbId);
    if (inFlight) {
      const db = await inFlight;
      return this._attachToOpen(db, { dbId, requesterId, keyProvider, requiredPermission });
    }

    const attempt = this._openUnshared({ ownerId, dbId, requesterId, keyProvider, requiredPermission });
    // Registered before the first await so a caller that arrives on the very next tick sees it.
    this._opening.set(dbId, attempt);
    try {
      return await attempt;
    } finally {
      // A failed open must not leave a rejected promise behind for the next caller to await.
      if (this._opening.get(dbId) === attempt) this._opening.delete(dbId);
    }
  }

  async _openUnshared({ ownerId, dbId, requesterId, keyProvider, requiredPermission }) {
    const dir = this._dbDir(ownerId, dbId);
    const dbIdBuf = Buffer.from(dbId);
    const kek = await keyProvider.deriveKek(dbIdBuf);
    const manifestKey = deriveManifestKeyFromKek(kek, dbIdBuf);
    const manifest = await this._readManifest(dir, manifestKey); // wrong keyProvider -> throws here

    const acl = AccessControlList.fromJSON(manifest.acl);
    if (!acl.can(requesterId, requiredPermission)) throw new Error('fitdb: access denied');

    const ddk = unwrapKey(kek, Buffer.from(manifest.wrappedDDK, 'base64'));
    this._cacheSession(dbId, ddk);

    const persistManifest = (m) => this._writeManifest(dir, manifestKey, m);
    const db = new Database({ dbId, name: manifest.name, dir, ddk, acl, manifest, idGenerator: this._idGen(), persistManifest, logger: this.log });
    const done = this.log.timer('open database', { warnAboveMs: 5000 });
    try {
      await db._openExistingCollections();
      done({ dbId, name: manifest.name, collections: db.collections.size });
    } catch (err) {
      // Whatever did open before the failure still holds descriptors; this handle is being
      // thrown away, so they have to go back now rather than at the next garbage collection.
      this.log.error({ dbId, error: err.message, msg: 'database failed to open' });
      await db.close().catch(() => {});
      throw err;
    }
    this.openDatabases.set(dbId, db);
    return db;
  }

  /**
   * Admits a caller to an already-open database.
   *
   * The key material is re-checked even though the handle exists. Skipping it -- which is what
   * this used to do -- meant that once ANY session had a database open, any other principal on
   * its ACL could attach to it with a `clientSecret` of the right length and no other
   * relationship to the real one, because nothing after the initial open ever consulted the
   * secret again. The check is one HKDF plus one 32-byte AES-GCM open, so it costs nothing
   * worth trading a credential check for.
   */
  async _attachToOpen(db, { dbId, requesterId, keyProvider, requiredPermission }) {
    const kek = await keyProvider.deriveKek(Buffer.from(dbId));
    let unwrapped;
    try { unwrapped = unwrapKey(kek, Buffer.from(db.manifest.wrappedDDK, 'base64')); }
    catch (_) { unwrapped = null; }
    // Same failure surface as a wrong secret on a cold open: the manifest cannot be
    // authenticated. server.js maps that onto UNAUTHENTICATED.
    if (!unwrapped || unwrapped.length !== db.ddk.length || !crypto.timingSafeEqual(unwrapped, db.ddk)) {
      throw new Error('fitdb: unsupported state or unable to authenticate data');
    }
    if (!db.acl.can(requesterId, requiredPermission)) throw new Error('fitdb: access denied');
    this._cacheSession(dbId, db.ddk);
    return db;
  }

  // Fast path for a request that arrives on an already-warm session (typical of the direct-
  // access flow: the edge server opened the database once via openDatabase(); subsequent
  // capability-token-authenticated requests hit the storage node directly and only need the
  // already-open Database handle, no key material re-supplied per request).
  getOpenDatabase(dbId) {
    return this.openDatabases.get(dbId) || null;
  }

  async closeDatabase(dbId) {
    // An open that is still in flight would otherwise register its handle just after this
    // method finished, leaving a database that is closed as far as callers are concerned but
    // still holding every descriptor it opened.
    const inFlight = this._opening.get(dbId);
    if (inFlight) await inFlight.catch(() => {});

    const db = this.openDatabases.get(dbId);
    if (!db) return false;
    await db.close();
    this.openDatabases.delete(dbId);
    const s = this.sessions.get(dbId);
    if (s?.timer) clearTimeout(s.timer);
    this.sessions.delete(dbId);
    return true;
  }

  // The O(1) key-rotation step the MLS design doc describes: on a membership change (or any
  // KEK rotation), the DDK itself never changes -- only the thing wrapping it does. This
  // unwraps with the OLD key material, re-wraps with the NEW key material, and rewrites
  // only the small `wrappedDDK` field in the manifest. No segment file, no index, no record
  // is touched, regardless of database size. Requires ADMIN on the current ACL.
  async rewrapDatabaseKey({ ownerId, dbId, oldKeyProvider, newKeyProvider, requesterId }) {
    const dir = this._dbDir(ownerId, dbId);
    const dbIdBuf = Buffer.from(dbId);

    const oldKek = await oldKeyProvider.deriveKek(dbIdBuf);
    const oldManifestKey = deriveManifestKeyFromKek(oldKek, dbIdBuf);
    const manifest = await this._readManifest(dir, oldManifestKey);

    const acl = AccessControlList.fromJSON(manifest.acl);
    if (requesterId && !acl.can(requesterId, DB_PERMISSIONS.ADMIN)) {
      throw new Error('fitdb: rewrapping a database key requires ADMIN permission');
    }

    const ddk = unwrapKey(oldKek, Buffer.from(manifest.wrappedDDK, 'base64'));

    const newKek = await newKeyProvider.deriveKek(dbIdBuf);
    manifest.wrappedDDK = wrapKey(newKek, ddk).toString('base64');
    const newManifestKey = deriveManifestKeyFromKek(newKek, dbIdBuf);
    await this._writeManifest(dir, newManifestKey, manifest);

    // If this database is live in this process, its in-memory DDK is still valid (it never
    // changed) -- only re-point the cached session so future manifest reads use the new key.
    if (this.openDatabases.has(dbId)) this._cacheSession(dbId, ddk);
    return true;
  }
}

module.exports = { DatabaseManager };
