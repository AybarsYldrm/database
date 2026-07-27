'use strict';

const { EventEmitter } = require('node:events');
const { GrpcClient, GRPC_STATUS } = require('@fitfak/grpc');

const { DATABASE_SCHEMAS, WATCH_EVENTS, DB_SERVICE_NAME } = require('./schemas');
const { ReplicatedView, CHANGE_OPS } = require('../change-stream');
const { toJson } = require('./record-codec');

// The client half of `@fitfak/database`: what you get from `npm install @fitfak/database` when
// the data lives somewhere else.
//
// The API deliberately mirrors the embedded one (`Collection#insert/get/find/...`), so code
// written against a local database moves to a remote one by changing how the handle is
// obtained and nothing else. Two things are remote-only because they have no meaning
// in-process: `watch()`, which keeps a decrypted materialized view current without polling,
// and the enrolment flow that gets this process a client certificate in the first place.

const DEFAULT_OPTIONS = {
  packageName: 'custom.network',
  serviceName: DB_SERVICE_NAME,
  reconnectWatchMs: 1000,
  maxReconnectWatchMs: 30000,
  logger: null,
};

class DatabaseClientError extends Error {
  constructor(message, code) { super(message); this.name = 'DatabaseClientError'; this.code = code; }
}

class RemoteCollection {
  constructor(database, name) {
    this.database = database;
    this.name = name;
    this._schema = null;
  }

  _call(method, request, options) {
    return this.database._call(method, { ...request, dbId: this.database.dbId, collection: this.name }, options);
  }

  /** Field definitions, cached. Needed before the binary payload form can be used. */
  async describe({ refresh = false } = {}) {
    if (this._schema && !refresh) return this._schema;
    const res = await this._call('DescribeCollection', {});
    this._schema = JSON.parse(res.payloadJson);
    return this._schema;
  }

  async insert(record) {
    const res = await this._call('InsertRecord', { payloadJson: toJson(record) });
    return res.recordId;
  }

  /**
   * insert() that the server refuses if a live record already holds the same value in any of
   * `unique`. Rejects with `code: 'ALREADY_EXISTS'`.
   *
   * The check happens inside the server's write queue, in the same step as the append. Doing
   * it here -- findOne, then insert -- would be two round trips with the whole network between
   * them, which is the widest possible window for a second caller to slip through.
   *
   *   await certs.insertUnique({ skidHex, ... }, { unique: ['skidHex'] });
   */
  async insertUnique(record, { unique } = {}) {
    const fields = Array.isArray(unique) ? unique : [unique].filter(Boolean);
    if (fields.length === 0) throw new Error('fitdb: insertUnique needs at least one field in `unique`');
    const res = await this._call('InsertRecord', { payloadJson: toJson(record), uniqueFields: fields });
    return res.recordId;
  }

  async get(recordId) {
    const res = await this._call('GetRecord', { recordId: String(recordId) });
    return res.found ? JSON.parse(res.payloadJson) : null;
  }

  /**
   * The record plus its AEAD-authenticated version counter. Pair it with a VersionWatermark to
   * detect a storage node serving an older-but-genuine record -- authentication proves a
   * record is real, not that it is the latest.
   */
  async getWithVersion(recordId) {
    const res = await this._call('GetRecord', { recordId: String(recordId) });
    return res.found ? { value: JSON.parse(res.payloadJson), version: res.version } : null;
  }

  /**
   * @param {object} [opts.expectedVersion] refuse the write if the record has moved since;
   *   without it, two concurrent read-modify-write callers silently lose one of the writes.
   */
  async update(recordId, patch, { expectedVersion = 0 } = {}) {
    const res = await this._call('UpdateRecord', {
      recordId: String(recordId), payloadJson: toJson(patch), expectedVersion,
    });
    return res.version;
  }

  async delete(recordId) {
    const res = await this._call('DeleteRecord', { recordId: String(recordId) });
    return res.deleted;
  }

  async find(field, value, { limit = 0 } = {}) {
    const res = await this._call('FindRecord', { field, value: String(value), limit });
    return JSON.parse(res.payloadJson);
  }

  async findOne(field, value) {
    const rows = await this.find(field, value, { limit: 1 });
    return rows[0] || null;
  }

  /** Bucketed range query over a `rangeBucket` field; the server never learns exact values. */
  async findRange(field, min, max) {
    const res = await this._call('FindRange', { field, min: String(min), max: String(max), plain: false });
    return JSON.parse(res.payloadJson);
  }

  /** Ordered scan over a plain `diskBacked` index. The server does learn value order here. */
  async findRangePlain(field, min, max) {
    const res = await this._call('FindRange', { field, min: String(min), max: String(max), plain: true });
    return JSON.parse(res.payloadJson);
  }

  async scanPage(afterId = null, limit = 100) {
    const res = await this._call('ScanRecords', { afterId: afterId ? String(afterId) : '', limit });
    return { records: JSON.parse(res.payloadJson), nextCursor: res.nextCursor || null };
  }

  /** Pages transparently, so a caller can `for await` a whole collection without pagination code. */
  async* scan({ pageSize = 200 } = {}) {
    let cursor = null;
    for (;;) {
      const { records, nextCursor } = await this.scanPage(cursor, pageSize);
      for (const record of records) yield record;
      if (!nextCursor) return;
      cursor = nextCursor;
    }
  }

  async count() {
    const res = await this._call('CountRecords', {});
    return Number(res.count);
  }

  async compact() {
    const res = await this._call('Compact', {});
    return { liveRecords: Number(res.liveRecords), segmentsReclaimed: res.segmentsReclaimed };
  }

  /**
   * A live, decrypted, in-memory copy of this collection, kept current by the server's change
   * stream. This is the answer to "I need to serve DNS answers / certificates out of an
   * encrypted store without a round trip per query": one snapshot, then deltas.
   */
  watch(options = {}) {
    return new WatchedCollection(this, options).start();
  }
}

/**
 * The materialized view and the stream that feeds it.
 *
 * Correctness rests on two things the server provides: a per-collection sequence number so a
 * gap is detectable, and an explicit RESET when the server can no longer prove continuity.
 * Without both, a cache silently drifts from the database and there is no way to notice.
 */
class WatchedCollection extends EventEmitter {
  constructor(collection, { includeSnapshot = true, autoReconnect = true, keyField = '_id' } = {}) {
    super();
    this.collection = collection;
    this.includeSnapshot = includeSnapshot;
    this.autoReconnect = autoReconnect;
    this.view = new ReplicatedView({ keyField, seqField: 'collSeq' });
    this.lastSeq = 0;           // global seq, the server-side resume token
    this.running = false;
    this._cancel = null;
    this._backoff = collection.database.options.reconnectWatchMs;
    this._ready = null;
  }

  /** True once a snapshot has landed and no gap has been detected since. */
  get fresh() { return !this.view.stale; }
  get size() { return this.view.size; }
  get(id) { return this.view.get(id); }
  all() { return this.view.all(); }

  start() {
    if (this.running) return this;
    this.running = true;
    this._ready = new Promise((resolve) => this.once('ready', resolve));
    this._connect();
    return this;
  }

  /** Resolves when the first snapshot has been applied. */
  ready() { return this._ready; }

  stop() {
    this.running = false;
    if (this._cancel) this._cancel();
    return this;
  }

  _connect() {
    if (!this.running) return;
    const { database, name } = { database: this.collection.database, name: this.collection.name };

    const call = database.client.serverStream(
      database._path('WatchCollection'), DATABASE_SCHEMAS,
      `${database.options.serviceName}_WatchCollectionReq`,
      `${database.options.serviceName}_WatchCollectionRes`,
      {
        dbId: database.dbId,
        collection: name,
        includeSnapshot: this.includeSnapshot,
        // Resuming from where the last stream stopped avoids re-sending a whole snapshot
        // across a brief disconnect. The server refuses (with RESET) if it cannot prove the
        // resumed stream is contiguous.
        resumeSeq: BigInt(this.lastSeq),
      },
      (message) => this._onMessage(message),
      { deadlineMs: 0 }, // a watch is open-ended; a deadline would cut it off
    );

    this._cancel = call.cancel;
    call.done.then(
      () => this._onClosed(null),
      (err) => this._onClosed(err),
    );
  }

  _onMessage(message) {
    let payload;
    try { payload = JSON.parse(message.payloadJson); }
    catch (err) { return this.emit('error', err); }

    switch (payload.type) {
      case WATCH_EVENTS.SNAPSHOT:
        this.view.loadSnapshot(payload.records, payload.lastCollSeq);
        this.lastSeq = payload.lastSeq;
        this._backoff = this.collection.database.options.reconnectWatchMs;
        this.emit('snapshot', { size: this.view.size });
        this.emit('ready', this);
        break;

      case WATCH_EVENTS.CHANGE: {
        this.lastSeq = payload.seq;
        const applied = this.view.applyEvent(payload);
        if (!applied && this.view.stale) {
          // A gap. The view can no longer claim to be a faithful copy, so it says so and
          // re-snapshots rather than serving a half-updated set.
          this.emit('stale', { at: payload.collSeq });
          this._resnapshot();
          return;
        }
        if (applied) {
          this.emit('change', payload);
          this.emit(payload.op === CHANGE_OPS.DELETE ? 'delete' : 'put', payload);
        }
        break;
      }

      case WATCH_EVENTS.RESET:
        this.emit('stale', { reason: payload.reason });
        this.view.stale = true;
        break;

      case WATCH_EVENTS.PING:
        this.emit('ping', payload.at);
        break;

      default:
        break;
    }
  }

  _resnapshot() {
    this.lastSeq = 0;
    this.includeSnapshot = true;
    if (this._cancel) this._cancel();
  }

  _onClosed(err) {
    this._cancel = null;

    // A watch that was deliberately stopped, or one being cancelled in order to re-snapshot,
    // closes with CANCELLED. That is the expected path, not a fault.
    const deliberate = !this.running || err?.code === GRPC_STATUS.CANCELLED;
    if (err && !deliberate) {
      // An EventEmitter that emits 'error' with nobody listening takes the process down. A
      // watcher whose whole job is to survive disconnects must not do that to its host, so
      // the failure is reported only if someone asked to hear about it -- reconnection
      // happens either way.
      if (this.listenerCount('error') > 0) this.emit('error', err);
      else this.emit('warning', err);
    }

    if (!this.running) return this.emit('closed');
    if (!this.autoReconnect) { this.running = false; return this.emit('closed'); }

    // Full jitter: a fixed retry interval turns a server restart into a synchronised
    // stampede from every watcher at once, which is how a recovering server goes back down.
    const ceiling = Math.min(this.collection.database.options.maxReconnectWatchMs, this._backoff * 2);
    this._backoff = ceiling;
    const delay = Math.random() * ceiling;
    this.emit('reconnecting', { delay });
    const timer = setTimeout(() => this._connect(), delay);
    timer.unref?.();
  }
}

class RemoteDatabase {
  constructor(client, dbId, options) {
    this.client = client;
    this.dbId = dbId;
    this.options = options;
    this._collections = new Map();
  }

  _path(method) { return `/${this.options.packageName}.${this.options.serviceName}/${method}`; }

  async _call(method, request, options = {}) {
    try {
      return await this.client.unary(
        this._path(method), DATABASE_SCHEMAS,
        `${this.options.serviceName}_${method}Req`,
        `${this.options.serviceName}_${method}Res`,
        request, options,
      );
    } catch (err) {
      throw new DatabaseClientError(err.message, err.code);
    }
  }

  collection(name) {
    if (!this._collections.has(name)) this._collections.set(name, new RemoteCollection(this, name));
    return this._collections.get(name);
  }

  /**
   * Defines a collection, or migrates the existing one to `fields`.
   *
   * Redefining with an extra field is the ordinary way a schema grows, and it applies: the
   * field starts being encoded, and if it is indexed the index is built from the records
   * already stored. Removing a field must be named in `dropFields`, because its bytes remain
   * in every record already written and its number is reserved from then on. Anything that
   * would misread stored data -- changing a field's type, reusing a retired number -- is
   * refused with an explanation rather than applied.
   */
  async defineCollection(name, { fields, title = null, description = null, compress = false, segmentMaxBytes = 0, dropFields = [], allowRetype = false, dryRun = false } = {}) {
    const res = await this._call('DefineCollection', {
      dbId: this.dbId, collection: name, fieldsJson: JSON.stringify(fields),
      title: title || '', description: description || '', compress,
      dropFields, allowRetype, dryRun,
      ...(segmentMaxBytes ? { segmentMaxBytes: BigInt(segmentMaxBytes) } : {}),
    });
    const collection = this.collection(name);
    // Any migration may have changed the field list, so a cached description is stale.
    collection._schema = null;
    return {
      ...res,
      changes: res.changesJson ? JSON.parse(res.changesJson) : [],
      collection,
    };
  }

  /**
   * Applies a whole schema registry -- the shape a project's `schemas.js` already has:
   *
   *   { users: { fields: [...] }, sessions: { fields: [...] } }
   *
   * Every collection is checked with `dryRun` first and nothing is applied if any one of them
   * would be refused. A partial migration across a related set of collections is worse than
   * none: the application comes up against a schema that is half old and half new.
   */
  async applySchemaRegistry(registry, { dropFields = {}, allowRetype = false, dryRun = false } = {}) {
    const planned = {};
    for (const [name, definition] of Object.entries(registry)) {
      planned[name] = await this.defineCollection(name, {
        ...definition, dropFields: dropFields[name] || [], allowRetype, dryRun: true,
      });
    }

    const refused = Object.entries(planned).filter(([, plan]) => /refused/.test(plan.message));
    if (refused.length > 0) {
      const detail = refused.map(([name, plan]) => `${name}: ${plan.changes.filter((c) => c.safety === 'breaking').map((c) => c.reason).join('; ')}`).join('\n');
      throw new DatabaseClientError(`fitdb: schema registry cannot be applied:\n${detail}`, GRPC_STATUS.FAILED_PRECONDITION);
    }
    if (dryRun) return planned;

    const applied = {};
    for (const [name, definition] of Object.entries(registry)) {
      applied[name] = await this.defineCollection(name, {
        ...definition, dropFields: dropFields[name] || [], allowRetype,
      });
    }
    return applied;
  }

  async listCollections() {
    const res = await this._call('ListCollections', { dbId: this.dbId });
    return JSON.parse(res.payloadJson);
  }

  /** Mints a narrow, short-lived token for the capability-token direct-access path. */
  async issueCapability({ collection = '*', scope, ttlMs = 30000, singleUse = true, rowFilter = null, subject = '' }) {
    const res = await this._call('IssueCapability', {
      dbId: this.dbId, collection, scope, ttlMs, singleUse,
      rowFilterJson: rowFilter ? JSON.stringify(rowFilter) : '',
      subject,
    });
    return { token: res.token, expiresAt: Number(res.expiresAt) };
  }

  async grantAccess(principal, mask) {
    const res = await this._call('GrantAccess', { dbId: this.dbId, principal, mask });
    return res.mask;
  }

  async revokeAccess(principal, mask) {
    const res = await this._call('RevokeAccess', { dbId: this.dbId, principal, mask });
    return res.mask;
  }

  async close() {
    await this._call('CloseDatabase', { dbId: this.dbId });
  }
}

/**
 * Connects, optionally enrolling first, and opens a database.
 *
 * Three ways to authenticate, in descending order of how much setup they need:
 *
 *   credentials  - this process already has a client certificate.
 *   enroll       - it does not, and should bootstrap one (see provisioning/enrollment-client.js).
 *   identity     - a ManagedIdentity from a previous enrolment, reused.
 *
 * @returns {Promise<{ db, client, identity, close }>}
 */
async function connectDatabase({
  target,
  credentials = null,
  enroll: enrolOptions = null,
  identity = null,
  dbId = null,
  clientSecret = null,
  ownerId = null,
  clientOptions = {},
  logger = null,
  ...rest
}) {
  const options = { ...DEFAULT_OPTIONS, ...rest, logger };

  let client;
  let managedIdentity = identity || null;

  if (managedIdentity) {
    client = managedIdentity.client;
  } else if (enrolOptions) {
    const { enroll } = require('../provisioning/enrollment-client');
    managedIdentity = await enroll({ target, logger, ...enrolOptions });
    client = managedIdentity.client;
  } else {
    if (!credentials?.cert || !credentials?.key) {
      throw new Error(
        'fitdb: connecting needs a client certificate. Pass `credentials: { key, cert, ca }`, '
        + 'or `enroll: { ... }` to bootstrap one over the enrolment channel.',
      );
    }
    client = new GrpcClient(target, { ...clientOptions, credentials });
    await client.connect();
  }

  const info = client.channelInfo();
  if (!info.mutual) {
    // Reaching the data plane without a client certificate is impossible server-side, so
    // failing here produces a comprehensible error instead of a PERMISSION_DENIED per call.
    throw new Error('fitdb: the channel is not mutually authenticated; the database will reject every call');
  }
  logger?.info?.(`[db] connected to ${target} (${info.protocol}, ${info.cipher})`);

  const api = {
    client,
    identity: managedIdentity,
    channel: info,

    async whoAmI() {
      const res = await client.unary(`/${options.packageName}.${options.serviceName}/WhoAmI`,
        DATABASE_SCHEMAS, `${options.serviceName}_WhoAmIReq`, `${options.serviceName}_WhoAmIRes`, {});
      return res;
    },

    async createDatabase(name, { ownerId: owner = '' } = {}) {
      const res = await client.unary(`/${options.packageName}.${options.serviceName}/CreateDatabase`,
        DATABASE_SCHEMAS, `${options.serviceName}_CreateDatabaseReq`, `${options.serviceName}_CreateDatabaseRes`,
        { name, ownerId: owner });
      // The secret is returned exactly once and never persisted server-side; a caller that
      // loses it has lost the data.
      return { dbId: res.dbId, clientSecret: res.clientSecret, ownerId: res.ownerId };
    },

    async openDatabase({ dbId: id, clientSecret: secret, ownerId: owner = '' }) {
      const res = await client.unary(`/${options.packageName}.${options.serviceName}/OpenDatabase`,
        DATABASE_SCHEMAS, `${options.serviceName}_OpenDatabaseReq`, `${options.serviceName}_OpenDatabaseRes`,
        { dbId: id, clientSecret: secret, ownerId: owner });
      const db = new RemoteDatabase(client, id, options);
      db.collectionNames = res.collections;
      return db;
    },

    async listDatabases(owner = '') {
      const res = await client.unary(`/${options.packageName}.${options.serviceName}/ListDatabases`,
        DATABASE_SCHEMAS, `${options.serviceName}_ListDatabasesReq`, `${options.serviceName}_ListDatabasesRes`,
        { ownerId: owner });
      return JSON.parse(res.payloadJson);
    },

    close() {
      if (managedIdentity) managedIdentity.close();
      else client.close();
    },
  };

  if (dbId && clientSecret) {
    api.db = await api.openDatabase({ dbId, clientSecret, ownerId: ownerId || '' });
  }
  return api;
}

module.exports = {
  connectDatabase,
  RemoteDatabase,
  RemoteCollection,
  WatchedCollection,
  DatabaseClientError,
  DATABASE_SCHEMAS,
  WATCH_EVENTS,
};
