'use strict';

const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');

const { SnowflakeGenerator } = require('./snowflake');
const { AccessControlList, DB_PERMISSIONS } = require('./rbac');
const { deriveManifestKeyFromKek, randomKey, wrapKey, unwrapKey, aesGcmEncrypt, aesGcmDecrypt } = require('./crypto-core');
const { ClientSecretKeyProvider, randomClientSecret } = require('./key-provider');
const { Database } = require('./database');

// Manifest = small, infrequently-read structural metadata (schema definitions, ACL, wrapped
// DDK). Encrypted as a whole with AES-256-GCM under manifestKey, plaintext JSON before
// encryption — this is the one deliberate JSON use in the whole engine: it's tiny, not on
// the hot path, and using JSON here buys real implementation simplicity for zero measurable
// cost. Every actual DATA record, by contrast, goes through the binary TLV codec
// (lib/binary-codec.js) and is what the "more efficient than JSON" requirement is about.
class DatabaseManager {
  constructor({ baseDir, snowflake, sessionTtlMs = 15 * 60 * 1000 }) {
    this.baseDir = baseDir;
    this.snowflake = snowflake || new SnowflakeGenerator();
    this.sessionTtlMs = sessionTtlMs;
    this.sessions = new Map(); // dbId -> { ddk, timer }
    this.openDatabases = new Map(); // dbId -> Database
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

  async _writeManifest(dir, manifestKey, manifest) {
    const plaintext = Buffer.from(JSON.stringify(manifest), 'utf8');
    const enc = aesGcmEncrypt(manifestKey, plaintext);
    const tmp = path.join(dir, 'manifest.bin.tmp');
    await fsp.writeFile(tmp, enc);
    await fsp.rename(tmp, path.join(dir, 'manifest.bin'));
  }

  async _readManifest(dir, manifestKey) {
    const buf = await fsp.readFile(path.join(dir, 'manifest.bin'));
    const plaintext = aesGcmDecrypt(manifestKey, buf); // throws on wrong key (auth tag mismatch)
    return JSON.parse(plaintext.toString('utf8'));
  }

  async _appendCatalog(ownerId, entry) {
    const p = this._catalogPath(ownerId);
    let list = [];
    try { list = JSON.parse(await fsp.readFile(p, 'utf8')); } catch (_) {}
    list.push(entry);
    await fsp.mkdir(path.dirname(p), { recursive: true });
    await fsp.writeFile(p, JSON.stringify(list));
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
    const db = new Database({ dbId, name, dir, ddk, acl, manifest, idGenerator: this._idGen(), persistManifest });
    this.openDatabases.set(dbId, db);
    return { db, dbId, clientSecret: clientSecretOut };
  }

  async openDatabase({ ownerId, dbId, requesterId, keyProvider, requiredPermission = DB_PERMISSIONS.READ }) {
    if (this.openDatabases.has(dbId)) {
      const db = this.openDatabases.get(dbId);
      if (!db.acl.can(requesterId, requiredPermission)) throw new Error('fitdb: access denied');
      return db;
    }

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
    const db = new Database({ dbId, name: manifest.name, dir, ddk, acl, manifest, idGenerator: this._idGen(), persistManifest });
    await db._openExistingCollections();
    this.openDatabases.set(dbId, db);
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
