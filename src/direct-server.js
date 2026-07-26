'use strict';

const net = require('node:net');
const tls = require('node:tls');
const { DB_PERMISSIONS } = require('./rbac');
const { buildResponseFrame, parseRequestFrame, createFrameReader } = require('./direct-protocol');

const OPS = { GET: 1, PUT: 2, DELETE: 3, FIND_ONE: 4, SCAN: 5, OBJECT_DOWNLOAD: 6 };

const REQUIRED_OP_FOR = {
  [OPS.GET]: DB_PERMISSIONS.READ,
  [OPS.FIND_ONE]: DB_PERMISSIONS.READ,
  [OPS.SCAN]: DB_PERMISSIONS.READ,
  [OPS.PUT]: DB_PERMISSIONS.WRITE,
  [OPS.DELETE]: DB_PERMISSIONS.DELETE,
  [OPS.OBJECT_DOWNLOAD]: DB_PERMISSIONS.READ,
};

const DEFAULT_IDLE_TIMEOUT_MS = 30000;

function rowFilterMatches(rowFilter, record) {
  if (!rowFilter || !record) return true;
  return record[rowFilter.field] === rowFilter.value || String(record[rowFilter.field]) === String(rowFilter.value);
}

// This realizes "the database server is, in effect, also an edge server": given a valid
// scoped capability token (see capability-token.js), a client talks to this listener
// directly. A connection now stays open across many requests (v2 protocol,
// requestId-correlated) rather than one-shot per v1 -- avoiding a fresh TLS handshake per
// operation, which matters a lot for bulk/scanning workloads. The capability token is the
// ONLY thing authenticating each individual request; there is no session or cookie beyond
// it, so its checks (signature/scope/expiry/single-use/row-filter, all enforced here) are
// the entire trust boundary. This process must already hold the target database open
// (DatabaseManager.openDatabase was called for it by whoever has RBAC authority) so the DDK
// is live in memory; a capability token grants scoped operation rights, it carries no key
// material to open a database cold.
class DirectAccessServer {
  constructor({ databaseManager, capabilityTokens, idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS }) {
    this.databaseManager = databaseManager;
    this.capabilityTokens = capabilityTokens;
    this.idleTimeoutMs = idleTimeoutMs;
    this.objectStores = new Map(); // dbId -> FitObjectStore, for OBJECT_DOWNLOAD
    this.server = null;
  }

  registerObjectStore(dbId, objectStore) { this.objectStores.set(String(dbId), objectStore); }

  listen(port, { host = '0.0.0.0', tlsOptions = null } = {}) {
    const onConnection = (socket) => this._handleConnection(socket);
    if (tlsOptions) {
      this.server = tls.createServer({ ...tlsOptions, allowHalfOpen: false }, onConnection);
    } else {
      console.warn('[fitdb direct-server] listening WITHOUT TLS - local/dev use only, pass tlsOptions in production');
      this.server = net.createServer(onConnection);
    }
    this.server.on('error', (e) => console.error('[fitdb direct-server] server error:', e.message));
    this.server.listen(port, host);
    return this.server;
  }

  _handleConnection(socket) {
    socket.on('error', () => {}); // client resets shouldn't surface as unhandled errors
    socket.setTimeout(this.idleTimeoutMs, () => socket.end());
    socket.on('data', createFrameReader((frame) => {
      // Deliberately not awaited here: multiple requests on the same connection are meant
      // to run concurrently (that is the point of multiplexing), each writing its response
      // whenever it finishes, matched back to its request by requestId regardless of order.
      this._handleFrame(socket, frame);
    }));
  }

  async _handleFrame(socket, frame) {
    let requestId = 0;
    try {
      const req = parseRequestFrame(frame);
      requestId = req.requestId;
      const requiredOp = REQUIRED_OP_FOR[req.opCode];
      if (!requiredOp) throw new Error(`unknown opCode ${req.opCode}`);

      const claims = this.capabilityTokens.verify(req.token, {
        dbId: req.dbId, collection: req.collection, requiredOp,
      });

      const db = this.databaseManager.getOpenDatabase(req.dbId);
      if (!db) throw new Error('database is not open on this node (no live session)');
      const rowFilter = claims.rowFilter || null;

      // Streaming case: many response frames share this one requestId, terminated by a
      // {done:true} frame, instead of the single-response shape every other op uses.
      if (req.opCode === OPS.OBJECT_DOWNLOAD) {
        const objectStore = this.objectStores.get(String(req.dbId));
        if (!objectStore) throw new Error('no object store registered for this database on this node');
        const meta = await objectStore.getMeta(req.args.objectId);
        if (rowFilter && !rowFilterMatches(rowFilter, meta)) throw new Error('object not found'); // hide existence, consistent with GET/FIND_ONE
        let index = 0;
        const isAdmin = (claims.scope & DB_PERMISSIONS.ADMIN) === DB_PERMISSIONS.ADMIN;
        for await (const chunk of objectStore.readPrivateObject(req.args.objectId, claims.sub, { isAdmin })) {
          if (socket.destroyed) return;
          socket.write(buildResponseFrame(requestId, { ok: true, streaming: true, index, data: chunk.toString('base64') }));
          index += 1;
        }
        if (!socket.destroyed) socket.write(buildResponseFrame(requestId, { ok: true, streaming: true, done: true, chunkCount: index }));
        return;
      }

      const collection = db.collection(req.collection);
      let result;
      switch (req.opCode) {
        case OPS.GET: {
          const r = await collection.getWithVersion(req.args.id);
          if (r && !rowFilterMatches(rowFilter, r.value)) result = { ok: true, value: null };
          else result = r ? { ok: true, value: r.value, version: r.version } : { ok: true, value: null };
          break;
        }
        case OPS.PUT: {
          const record = req.args.record;
          if (record?._id === undefined) throw new Error('direct PUT requires an explicit _id (mint one via the edge-mediated insert path first)');
          if (rowFilter && !rowFilterMatches(rowFilter, record)) {
            throw new Error(`record does not satisfy this token's row scope (${rowFilter.field} must equal the granted value)`);
          }
          await collection.storage.put(record);
          result = { ok: true, id: String(record._id) };
          break;
        }
        case OPS.DELETE: {
          if (rowFilter) {
            const existing = await collection.get(req.args.id);
            if (!rowFilterMatches(rowFilter, existing)) { result = { ok: true, deleted: false }; break; }
          }
          const deleted = await collection.delete(req.args.id);
          result = { ok: true, deleted };
          break;
        }
        case OPS.FIND_ONE: {
          const value = await collection.findOne(req.args.field, req.args.value);
          result = { ok: true, value: rowFilterMatches(rowFilter, value) ? value : null };
          break;
        }
        case OPS.SCAN: {
          const { records, nextCursor } = await collection.scanPage(req.args.afterId ?? null, req.args.limit || 100);
          const filtered = rowFilter ? records.filter((r) => rowFilterMatches(rowFilter, r)) : records;
          result = { ok: true, records: filtered, nextCursor };
          break;
        }
        default:
          throw new Error(`unhandled opCode ${req.opCode}`);
      }
      if (!socket.destroyed) socket.write(buildResponseFrame(requestId, result));
    } catch (e) {
      if (!socket.destroyed) {
        try { socket.write(buildResponseFrame(requestId, { ok: false, error: e.message })); } catch (_) {}
      }
    }
  }

  close() {
    return new Promise((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }
}

module.exports = { DirectAccessServer, OPS };
