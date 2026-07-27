'use strict';

const path = require('node:path');
const { CollectionStorage } = require('./storage-engine');
const { hkdf } = require('./crypto-core');
const { ChangeHub, CHANGE_OPS } = require('./change-stream');

const STORAGE_OP_PUT = 1; // mirrors OP_PUT/OP_DELETE in storage-engine.js


const RESERVED_FIELD_NO = 1;
const RESERVED_FIELD_NAME = '_id';
const ALLOWED_TYPES = new Set(['bool', 'int32', 'int64', 'uint32', 'uint64', 'float', 'double', 'string', 'bytes']);

// Every collection's records are encrypted with a subkey derived from the database's DDK,
// not the raw DDK itself: collectionKey = HKDF-SHA256(DDK, salt=collectionName, info=...).
// This answers "should every collection have its own DDK?" from the design doc with a
// cheaper "yes, effectively" — compromising one collection's derived key reveals nothing
// about another collection's key, exactly like independent per-collection DDKs would, but
// without needing a separate wrapped-key entry (and separate rotation bookkeeping) per
// collection in the manifest. The only thing a *fully* independent random DDK-per-collection
// buys beyond this is rotating one collection's key without touching the database's root
// DDK at all — not needed unless collections get individually shared to different parties,
// at which point (per the MLS discussion) that collection likely deserves its own
// KeyProvider-backed database rather than living inside a shared one anyway.
function deriveCollectionKey(ddk, collectionName) {
  return hkdf(ddk, Buffer.alloc(0), Buffer.from(`fitdb-collection-v1:${collectionName}`), 32);
}

function normalizeSchema(fields) {
  const NUMERIC_TYPES = new Set(['int32', 'int64', 'uint32', 'uint64', 'float', 'double']);
  for (const f of fields) {
    if (f.no === RESERVED_FIELD_NO || f.name === RESERVED_FIELD_NAME) {
      throw new Error(`fitdb: field number ${RESERVED_FIELD_NO} and name '_id' are reserved for the auto-managed primary key`);
    }
    if (!ALLOWED_TYPES.has(f.type)) throw new Error(`fitdb: unsupported field type '${f.type}' on '${f.name}'`);
    if ((f.index || f.blindIndex) && f.type === 'bytes') {
      throw new Error(`fitdb: field '${f.name}' cannot be indexed (type 'bytes' has no meaningful equality index)`);
    }
    if (f.rangeBucket) {
      if (!NUMERIC_TYPES.has(f.type)) throw new Error(`fitdb: rangeBucket requires a numeric field type on '${f.name}'`);
      if (!(f.rangeBucket.width > 0)) throw new Error(`fitdb: rangeBucket.width must be a positive number on '${f.name}'`);
    }
    if (f.diskBacked && !(f.index || f.blindIndex || f.rangeBucket)) {
      throw new Error(`fitdb: diskBacked only applies to a field that also has index, blindIndex, or rangeBucket set ('${f.name}')`);
    }
  }
  const seenNo = new Set(), seenName = new Set();
  for (const f of fields) {
    if (seenNo.has(f.no)) throw new Error(`fitdb: duplicate field number ${f.no}`);
    if (seenName.has(f.name)) throw new Error(`fitdb: duplicate field name '${f.name}'`);
    seenNo.add(f.no); seenName.add(f.name);
  }
  return [{ no: RESERVED_FIELD_NO, name: RESERVED_FIELD_NAME, type: 'uint64' }, ...fields];
}

class Collection {
  constructor(name, schema, storage, { idGenerator, title = null, description = null } = {}) {
    this.name = name;
    this.schema = schema;
    this.storage = storage;
    this._idGenerator = idGenerator;
    this.title = title;
    this.description = description;
  }

  _validate(obj) {
    for (const f of this.schema) {
      if (f.required && (obj[f.name] === undefined || obj[f.name] === null)) {
        throw new Error(`fitdb: field '${f.name}' is required on collection '${this.name}'`);
      }
    }
  }

  async insert(obj) {
    this._validate(obj);
    const rec = { ...obj };
    if (rec._id === undefined || rec._id === null) {
      if (!this._idGenerator) throw new Error('fitdb: no id generator wired and no _id supplied');
      rec._id = this._idGenerator();
    }
    await this.storage.put(rec);
    return String(rec._id);
  }

  // Generates an id from the same shared Snowflake sequence insert() would use, without
  // inserting anything yet -- for callers (like FitObjectStore) that need to know the id
  // BEFORE writing a record, e.g. to derive a per-object key or a blob file path first.
  generateId() {
    if (!this._idGenerator) throw new Error('fitdb: no id generator wired on this collection');
    return String(this._idGenerator());
  }

  async get(id) { return this.storage.get(id); }
  async getWithVersion(id) { return this.storage.getWithVersion(id); }
  async update(id, patch) { return this.storage.update(id, patch); }
  async delete(id) { return this.storage.delete(id); }

  async findOne(field, value) {
    const ids = await this.storage.lookupIds(field, value);
    if (!ids || ids.size === 0) return null;
    return this.get(ids.values().next().value);
  }

  async find(field, value) {
    const ids = await this.storage.lookupIds(field, value);
    const out = [];
    if (ids) for (const id of ids) { const r = await this.get(id); if (r) out.push(r); }
    return out;
  }

  // Range query over a `rangeBucket`-configured field. This is bucketed/coarsened blind
  // indexing, NOT order-preserving encryption: candidates come from decrypting every id in
  // the (small number of) overlapping buckets, then an exact [min,max] filter is applied
  // client-side-equivalent (here: server-side but post-decrypt, same trust tier as any
  // other direct-server operation). The server learns which bucket a record falls into
  // (e.g. "which day", for a day-width bucket on a timestamp), not its exact value -- the
  // bucket width is the dial between query utility and leakage, chosen per field.
  async findRange(field, min, max) {
    const candidateIds = await this.storage.lookupRangeCandidates(field, min, max);
    const out = [];
    for (const id of candidateIds) {
      const r = await this.get(id);
      if (r && r[field] >= min && r[field] <= max) out.push(r);
    }
    return out;
  }

  // Native ordered range query for a plain (non-blind) diskBacked:true indexed numeric
  // field -- see CollectionStorage.lookupPlainRange for the confidentiality trade-off this
  // implies (the server learns real value order for this field, unlike rangeBucket).
  async findRangePlain(field, min, max) {
    const candidateIds = await this.storage.lookupPlainRange(field, min, max);
    const out = [];
    for (const id of candidateIds) { const r = await this.get(id); if (r) out.push(r); }
    return out;
  }

  count() { return this.storage.liveCount(); }
  scan() { return this.storage.scan(); }
  compact() { return this.storage.compact(); }

  async scanPage(afterId, limit = 100) {
    const { ids, nextCursor } = this.storage.scanPage(afterId, limit);
    const records = [];
    for (const id of ids) { const r = await this.get(id); if (r) records.push(r); }
    return { records, nextCursor };
  }
}

class Database {
  constructor({ dbId, name, dir, ddk, acl, manifest, idGenerator, persistManifest, changeBacklogSize = 1024 }) {
    this.dbId = dbId;
    this.name = name;
    this.dir = dir;
    this.ddk = ddk;
    this.acl = acl;
    this.manifest = manifest; // { collections: { [name]: { fields, options } }, ... }
    this._idGenerator = idGenerator;
    // One hub per database, not per collection: a watcher that cares about several
    // collections (or all of them) needs a single ordered sequence across them, otherwise
    // "resume from seq N" is ambiguous about which stream N belongs to.
    this.changes = new ChangeHub({ backlogSize: changeBacklogSize });
    // Called with the current manifest whenever collection/ACL metadata changes, so a
    // schema defined after createDatabase() is not silently lost to the next reopen (the
    // manifest on disk is otherwise a point-in-time snapshot from creation time only).
    this._persistManifest = persistManifest || (async () => {});
    this.collections = new Map();
  }

  // Adapts the storage engine's numeric op code into the hub's stable string vocabulary, so
  // a subscriber never has to know the on-disk frame format to read a change event.
  _changeSink(collectionName) {
    return ({ op, id, version, record }) => this.changes.publish({
      collection: collectionName,
      op: op === STORAGE_OP_PUT ? CHANGE_OPS.PUT : CHANGE_OPS.DELETE,
      id, version, record,
    });
  }

  async _openExistingCollections() {
    for (const [name, def] of Object.entries(this.manifest.collections || {})) {
      const storage = new CollectionStorage({
        dir: path.join(this.dir, 'collections', name),
        ddk: deriveCollectionKey(this.ddk, name),
        schema: normalizeSchema(def.fields),
        segmentMaxBytes: def.options?.segmentMaxBytes,
        compress: def.options?.compress,
        onChange: this._changeSink(name),
      });
      await storage.open();
      this.collections.set(name, new Collection(name, storage.schema, storage, { idGenerator: this._idGenerator, title: def.title, description: def.description }));
    }
  }

  // { name -> {title, description} } for every defined collection -- e.g. for a UI listing
  // available tables with friendly names instead of raw internal collection identifiers.
  listCollectionInfo() {
    return [...this.collections.values()].map((c) => ({ name: c.name, title: c.title, description: c.description }));
  }

  defineCollection(name, { fields, title = null, description = null, segmentMaxBytes = 16 * 1024 * 1024, compress = false } = {}) {
    if (this.collections.has(name)) return this.collections.get(name);
    const schema = normalizeSchema(fields);
    const storage = new CollectionStorage({
      dir: path.join(this.dir, 'collections', name),
      ddk: deriveCollectionKey(this.ddk, name),
      schema,
      segmentMaxBytes,
      compress,
      onChange: this._changeSink(name),
    });
    // open() is async but collection creation is synchronous in the public API for
    // ergonomics; callers that need the open (AND the manifest update below) to have fully
    // landed before their first op should await defineCollectionAsync instead.
    this.manifest.collections[name] = { fields, title, description, options: { segmentMaxBytes, compress } };
    const ready = storage.open().then(() => this._persistManifest(this.manifest));
    const collection = new Collection(name, schema, storage, { idGenerator: this._idGenerator, title, description });
    collection._readyPromise = ready;
    this.collections.set(name, collection);
    return collection;
  }

  async defineCollectionAsync(name, opts) {
    const collection = this.defineCollection(name, opts);
    await collection._readyPromise;
    return collection;
  }

  collection(name) {
    const c = this.collections.get(name);
    if (!c) throw new Error(`fitdb: collection '${name}' is not open on database '${this.name}'`);
    return c;
  }

  listCollections() { return [...this.collections.keys()]; }

  // Push-based alternative to polling. `collection` may be '*' to watch the whole database.
  // Returns an unsubscribe function; see change-stream.js for the resume/gap semantics that
  // make a subscriber's cached view safe to serve from.
  watch(collection, handler) { return this.changes.subscribe(collection, handler); }

  // A consistent starting point for a watcher: the full current contents of a collection
  // plus the sequence numbers those contents correspond to.
  //
  // The counters are read BEFORE the scan, not after, and that ordering is the whole
  // correctness argument. Reading after would let a write that landed mid-scan be both
  // missed by the scan (if it targeted an already-visited position) and covered by the
  // returned counter -- the watcher would then discard its event as "already applied" and
  // silently serve a view missing that record forever. Reading first can only cause the
  // opposite, harmless case: an event that re-applies something the snapshot already has.
  async snapshot(collectionName) {
    const collection = this.collection(collectionName);
    const lastSeq = this.changes.lastSeq;
    const lastCollSeq = this.changes.lastCollSeq(collectionName);
    const records = [];
    for await (const rec of collection.scan()) records.push(rec);
    return { records, lastSeq, lastCollSeq };
  }

  async close() {
    for (const c of this.collections.values()) await c.storage.close();
    this.changes.clear();
  }
}

module.exports = { Collection, Database, deriveCollectionKey, normalizeSchema };
