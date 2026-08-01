'use strict';

const path = require('node:path');
const { CollectionStorage } = require('./storage-engine');
const { hkdf } = require('./crypto-core');
const { ChangeHub, CHANGE_OPS } = require('./change-stream');
const { planMigration, describeBlockers, SchemaMigrationError } = require('./schema-migration');
const { adapt } = require('./logger');

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

function normalizeSchema(fields, { reserved = [] } = {}) {
  const NUMERIC_TYPES = new Set(['int32', 'int64', 'uint32', 'uint64', 'float', 'double']);
  const reservedSet = new Set(reserved);
  for (const f of fields) {
    if (f.no === RESERVED_FIELD_NO || f.name === RESERVED_FIELD_NAME) {
      throw new Error(`fitdb: field number ${RESERVED_FIELD_NO} and name '_id' are reserved for the auto-managed primary key`);
    }
    // A number retired by an earlier migration must never come back under a new meaning:
    // records written while it was live still carry bytes under that tag, and they would be
    // read as the new field. Same discipline as protobuf's `reserved`.
    if (reservedSet.has(f.no)) {
      throw new Error(
        `fitdb: field number ${f.no} is reserved on this collection (it was used by a field that has since been removed) `
        + `and cannot be reused for '${f.name}'`,
      );
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

  /**
   * insert() that refuses if a live record already holds the same value in any of `unique`.
   * The check and the write are one atomic step -- see CollectionStorage#putUnique for why
   * the read-then-insert spelling of this does not hold under concurrency.
   *
   * Named fields must be indexed (`index: true` or `blindIndex: true`); a blind index is
   * enough, since proving "no record has this exact value" is precisely the one question a
   * blind index can answer.
   *
   *   await certs.insertUnique({ skidHex, serialNumberHex, ... }, { unique: ['skidHex'] });
   *
   * Throws UniqueConstraintError, which carries `.field` and `.value`.
   */
  async insertUnique(obj, { unique } = {}) {
    if (!unique || (Array.isArray(unique) && unique.length === 0)) {
      throw new Error('fitdb: insertUnique needs at least one field in `unique`');
    }
    this._validate(obj);
    const rec = { ...obj };
    if (rec._id === undefined || rec._id === null) {
      if (!this._idGenerator) throw new Error('fitdb: no id generator wired and no _id supplied');
      rec._id = this._idGenerator();
    }
    await this.storage.putUnique(rec, unique);
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
  //
  // `limit` stops the decrypt loop as soon as enough matches are in hand. That matters most
  // on exactly the queries the sweep strategy serves: "everything due by now" hands back
  // every id the field has indexed as a candidate, and without a limit the caller pays a
  // decrypt for all of them on every poll even though it only ever consumes a batch.
  async findRange(field, min, max, { limit = 0 } = {}) {
    const candidateIds = await this.storage.lookupRangeCandidates(field, min, max);
    const out = [];
    for (const id of candidateIds) {
      const r = await this.get(id);
      if (r && r[field] >= min && r[field] <= max) out.push(r);
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  // Native ordered range query for a plain (non-blind) diskBacked:true indexed numeric
  // field -- see CollectionStorage.lookupPlainRange for the confidentiality trade-off this
  // implies (the server learns real value order for this field, unlike rangeBucket).
  async findRangePlain(field, min, max, { limit = 0 } = {}) {
    const candidateIds = await this.storage.lookupPlainRange(field, min, max);
    const out = [];
    for (const id of candidateIds) {
      const r = await this.get(id);
      if (r) out.push(r);
      if (limit && out.length >= limit) break;
    }
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
  constructor({ dbId, name, dir, ddk, acl, manifest, idGenerator, persistManifest, changeBacklogSize = 1024, logger = null }) {
    this.dbId = dbId;
    this.name = name;
    // One logger per database, with each collection taking a child of it, so a line always
    // says which database AND which collection it came from. A host application can replace
    // the whole tree at once with logger.setSink().
    this.log = adapt(logger, logger ? String(name) : `fitdb:${name}`);
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
    // collectionName -> tail of the in-flight define/migrate chain. Two clients defining or
    // evolving the same collection at once would otherwise overlap a schema application with
    // an index rebuild over the same files.
    this._defining = new Map();
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
        // Passing `reserved` here is an integrity check rather than a normal path: a manifest
        // whose field list uses a retired number would be one written by something that
        // bypassed the migration rules, and catching it at open beats decoding old records
        // under a new field's type.
        schema: normalizeSchema(def.fields, { reserved: def.reserved || [] }),
        segmentMaxBytes: def.options?.segmentMaxBytes,
        compress: def.options?.compress,
        onChange: this._changeSink(name),
        logger: this.log,
        name,
      });
      try {
        await storage.open();
      } catch (err) {
        // open() may have taken file handles before it failed, and this storage is about to
        // become unreachable -- nothing else holds a reference to it, so releasing them here
        // is the only chance before the garbage collector gets around to it.
        await storage.close().catch(() => {});
        throw err;
      }
      this.collections.set(name, new Collection(name, storage.schema, storage, { idGenerator: this._idGenerator, title: def.title, description: def.description }));
    }
  }

  // { name -> {title, description} } for every defined collection -- e.g. for a UI listing
  // available tables with friendly names instead of raw internal collection identifiers.
  listCollectionInfo() {
    return [...this.collections.values()].map((c) => ({ name: c.name, title: c.title, description: c.description }));
  }

  /**
   * Defines a collection, or evolves the one that already exists.
   *
   * Calling this again with an extra field used to return the existing collection untouched,
   * which meant the new field had no tag in the encoder and every value written to it was
   * silently discarded -- no error, no warning, just missing data. Redefining is now a
   * migration: additive changes are applied, index changes trigger a rebuild from the stored
   * records, and anything that would misread data already on disk is refused with an
   * explanation of what to do instead.
   *
   * @param {object}   [opts.dropFields]  field names the caller accepts losing; their numbers
   *   are then reserved forever, because records written while they were live still carry
   *   bytes under those tags.
   * @param {boolean}  [opts.migrate=true] false restores the old return-as-is behaviour.
   */
  defineCollection(name, { fields, title = null, description = null, segmentMaxBytes = 16 * 1024 * 1024, compress = false, dropFields = [], allowRetype = false, migrate = true } = {}) {
    const existingDefinition = this.manifest.collections?.[name];

    if (this.collections.has(name) || existingDefinition) {
      if (!migrate) {
        const existing = this.collections.get(name);
        if (existing) return existing;
      } else {
        const collection = this._migrateCollection(name, {
          fields, title, description, dropFields, allowRetype,
        });
        if (collection) return collection;
      }
    }

    const schema = normalizeSchema(fields);
    const storage = new CollectionStorage({
      dir: path.join(this.dir, 'collections', name),
      ddk: deriveCollectionKey(this.ddk, name),
      schema,
      segmentMaxBytes,
      compress,
      onChange: this._changeSink(name),
      logger: this.log,
      name,
    });
    // open() is async but collection creation is synchronous in the public API for
    // ergonomics; callers that need the open (AND the manifest update below) to have fully
    // landed before their first op should await defineCollectionAsync instead.
    this.manifest.collections[name] = {
      fields, title, description, reserved: [], schemaVersion: 1,
      options: { segmentMaxBytes, compress },
    };
    const ready = storage.open().then(() => this._persistManifest(this.manifest));
    // defineCollection() is synchronous, so nothing is obliged to await `ready`. An open that
    // failed then became an unhandled rejection, which on Node >= 15 terminates the process --
    // a failure to open ONE collection taking down the entire database server. Attaching a
    // handler here makes the rejection observed; `_readyPromise` still rejects for
    // defineCollectionAsync/applyCollectionSchema callers, who do want to see it.
    ready.catch((err) => this.log.error({
      collection: name, error: err.message,
      msg: 'collection failed to open; it will not be usable until the cause is fixed',
    }));
    const collection = new Collection(name, schema, storage, { idGenerator: this._idGenerator, title, description });
    collection._readyPromise = ready;
    // `created` distinguishes this from "the collection already existed and needed no change",
    // which is otherwise the identical result. A caller that computes it by checking the
    // manifest before the call gets it wrong under concurrency: with two clients defining the
    // same collection at once, both look before either has written, and both claim to have
    // created it.
    collection.migration = { changed: false, changes: [], rebuilt: false, created: true };
    this.collections.set(name, collection);
    return collection;
  }

  /**
   * Applies a schema change to an already-defined collection. Returns null if the collection
   * is not open yet (the caller then falls through to a normal open), otherwise the collection
   * with `migration` describing what happened.
   */
  _migrateCollection(name, { fields, title, description, dropFields, allowRetype }) {
    const definition = this.manifest.collections[name];
    const collection = this.collections.get(name);
    if (!definition || !collection) return null;

    const reserved = definition.reserved || [];
    const plan = planMigration(definition.fields || [], fields, { reserved, dropFields, allowRetype });

    if (!plan.applicable) throw new SchemaMigrationError(describeBlockers(name, plan), plan.blocked);

    if (!plan.changed) {
      collection.migration = { changed: false, changes: [], rebuilt: false, created: false };
      return collection;
    }

    const schema = normalizeSchema(fields, { reserved: plan.newReserved });

    definition.fields = fields;
    definition.reserved = plan.newReserved;
    definition.schemaVersion = (definition.schemaVersion || 1) + 1;
    if (title !== null) definition.title = title;
    if (description !== null) definition.description = description;

    collection.schema = schema;
    if (title !== null) collection.title = title;
    if (description !== null) collection.description = description;

    // The manifest is persisted only after the storage layer has accepted the new schema and
    // rebuilt its indexes, so a crash mid-migration leaves the old, consistent definition on
    // disk rather than a manifest that promises a schema the indexes do not reflect.
    collection._readyPromise = collection.storage
      .applySchema(schema, { rebuildIndexes: plan.needsRebuild })
      .then(() => this._persistManifest(this.manifest));
    // Same reasoning as in defineCollection(): a migration nobody awaited must not be able to
    // kill the process through an unhandled rejection.
    collection._readyPromise.catch((err) => this.log.error({
      collection: name, error: err.message, msg: 'schema migration failed',
    }));

    this.log.info({
      collection: name,
      changes: plan.changes.length,
      rebuildIndexes: plan.needsRebuild,
      schemaVersion: definition.schemaVersion,
      msg: 'collection schema migrated',
    });

    collection.migration = {
      changed: true,
      changes: plan.changes,
      rebuilt: plan.needsRebuild,
      created: false,
      schemaVersion: definition.schemaVersion,
      reserved: plan.newReserved,
    };
    return collection;
  }

  /**
   * defineCollection() plus the wait for its storage to be open and its manifest persisted,
   * returning what this particular call did: `{ collection, migration }`.
   *
   * Two properties this has and reading `collection.migration` after the fact does not.
   *
   * It is serialized per collection name. defineCollection() itself is synchronous up to the
   * point it registers the collection, so two callers can never both create one -- but the
   * second lands in _migrateCollection(), which calls applySchema() on a storage whose open()
   * may still be replaying, and an index rebuild overlapping a replay over the same files is
   * not something either side is written to survive.
   *
   * And the migration result is captured inside that critical section. `collection` is a single
   * shared object per collection, so its `.migration` describes whichever definition ran most
   * recently -- with two clients applying the same migration at once, both could end up
   * reporting the same one as theirs. Each call assigns a fresh object rather than mutating the
   * old one, so a reference taken here stays true to the call that took it.
   */
  async applyCollectionSchema(name, opts) {
    const previous = this._defining.get(name) || Promise.resolve();
    const task = previous.then(async () => {
      const collection = this.defineCollection(name, opts);
      await collection._readyPromise;
      return { collection, migration: collection.migration || { changed: false, changes: [], rebuilt: false, created: false } };
    });
    // The chain must keep flowing even when one definition is rejected (a refused migration is
    // an ordinary outcome), so the tail settles regardless while the caller still sees the
    // real result of their own call.
    const tail = task.then(() => undefined, () => undefined);
    this._defining.set(name, tail);
    try {
      return await task;
    } finally {
      if (this._defining.get(name) === tail) this._defining.delete(name);
    }
  }

  async defineCollectionAsync(name, opts) {
    const { collection } = await this.applyCollectionSchema(name, opts);
    return collection;
  }

  /**
   * Reports what redefining a collection with `fields` would do, without doing it. Intended
   * for a deploy-time check: a migration that turns out to be refused is much better
   * discovered by a pipeline than by the first write after a rollout.
   */
  inspectMigration(name, fields, { dropFields = [], allowRetype = false } = {}) {
    const definition = this.manifest.collections?.[name];
    if (!definition) return { exists: false, changed: true, applicable: true, changes: [], blocked: [] };
    const plan = planMigration(definition.fields || [], fields, {
      reserved: definition.reserved || [], dropFields, allowRetype,
    });
    return { exists: true, ...plan };
  }

  /**
   * Defines or evolves every collection in a registry object -- the shape a project's
   * `schemas.js` already has:
   *
   *   { users: { fields: [...] }, sessions: { fields: [...] } }
   *
   * Runs the whole set through inspectMigration first and refuses before touching anything if
   * any collection is blocked. A partial migration across a related set of collections is much
   * worse than none: the application comes up against a schema that is half old and half new.
   */
  async applySchemaRegistry(registry, { dropFields = {}, allowRetype = false, dryRun = false } = {}) {
    const blocked = [];
    for (const [name, definition] of Object.entries(registry)) {
      const plan = this.inspectMigration(name, definition.fields, {
        dropFields: dropFields[name] || [], allowRetype,
      });
      if (plan.exists && !plan.applicable) blocked.push({ name, plan });
    }
    if (blocked.length > 0) {
      const detail = blocked.map(({ name, plan }) => describeBlockers(name, plan)).join('\n');
      throw new SchemaMigrationError(`fitdb: schema registry cannot be applied:\n${detail}`, blocked);
    }

    const applied = {};
    for (const [name, definition] of Object.entries(registry)) {
      if (dryRun) { applied[name] = this.inspectMigration(name, definition.fields); continue; }
      const { migration } = await this.applyCollectionSchema(name, {
        ...definition,
        dropFields: dropFields[name] || [],
        allowRetype,
      });
      applied[name] = migration;
    }
    return applied;
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

  /**
   * Closes every collection, then drops subscribers.
   *
   * Each close is attempted independently. Letting one rejection escape the loop -- which is
   * what a bare `await` in a for-of does -- meant a single collection failing to write its
   * final snapshot left every collection after it in the iteration order open, holding its
   * append handle and its whole read-FD pool, with no remaining reference to close them by.
   */
  async close() {
    const failures = [];
    for (const c of this.collections.values()) {
      try { await c.storage.close(); }
      catch (err) { failures.push({ collection: c.name, error: err.message }); }
    }
    this.changes.clear();
    if (failures.length) {
      this.log.error({ failures, msg: 'some collections did not close cleanly' });
    }
    return { closed: this.collections.size - failures.length, failures };
  }
}

module.exports = { Collection, Database, deriveCollectionKey, normalizeSchema };
