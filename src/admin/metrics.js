'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { EventEmitter } = require('node:events');

// What each service is actually costing this database, and who is connected right now.
//
// Two numbers get conflated in most dashboards and they answer different questions:
//
//   TRANSPORT bytes  what a service moved over the wire. Answers "who is generating load".
//                    Read from the TLS socket's own counters, so it includes TLS record
//                    overhead and HTTP/2 framing -- it is what the network actually carried,
//                    not what the application thinks it sent.
//
//   STORED bytes     what a service's data occupies on disk. Answers "who is using the space".
//                    Read by walking the database directory, so it includes segment files,
//                    index snapshots and whatever else the engine wrote.
//
// A service can be huge on one and nothing on the other. A DNS resolver reads constantly and
// stores almost nothing; an archival job is the reverse. Showing one number labelled "usage"
// would be wrong half the time.
//
//
// HOW ATTRIBUTION WORKS, AND WHERE IT IS APPROXIMATE
//
// Transport bytes are attributed by reading the client certificate off the socket when the
// HTTP/2 session opens. That is the same certificate the data plane authenticates with, so the
// attribution is as trustworthy as the connection itself.
//
// It is approximate in one direction, and the approximation is worth stating: bytes spent on
// the TLS handshake, and on any connection that never presents a certificate (a probe, a health
// check, a peer that gets refused), cannot be attributed to a principal. Those land under
// `unattributed` rather than being silently dropped or misfiled -- an unattributed number that
// suddenly grows is itself a signal.
//
// Counters are held in memory. A restart resets them, and that is the honest behaviour for a
// process-local counter; anything else would need a metrics backend, which is a different piece
// of software.

const BYTES_IN_MB = 1024 * 1024;

class ServiceMetrics extends EventEmitter {
  /**
   * @param {object}  opts
   * @param {string} [opts.baseDir]        the database data directory, for stored-byte sizing
   * @param {number} [opts.sampleIntervalMs] how often live sockets are re-read
   */
  constructor({ baseDir = null, sampleIntervalMs = 5000 } = {}) {
    super();
    this.baseDir = baseDir;
    this.startedAt = Date.now();
    this.resetAt = Date.now();
    this.sampleIntervalMs = sampleIntervalMs;

    // principal -> counters. Survives disconnects, which is the point: "how much has
    // smtp-service moved today" should not go back to zero because it reconnected.
    this._principals = new Map();
    // A monotonically increasing id per connection, so the panel can tell two connections from
    // the same principal apart.
    this._nextConnectionId = 1;
    this._connections = new Map(); // id -> record
    this._unattributed = { bytesIn: 0, bytesOut: 0, connections: 0 };

    this._sampler = null;
  }

  // ---- registration -------------------------------------------------------------------------

  /**
   * Attaches to a running HTTP/2 server. Every session that opens is tracked from that moment
   * until it closes.
   *
   * Deliberately takes the raw server rather than the GrpcApplication: byte counters live on
   * the socket, and reaching for them through three wrappers would break the first time one of
   * those wrappers changed shape.
   */
  attach(http2Server) {
    if (!http2Server || typeof http2Server.on !== 'function') {
      throw new Error('fitdb metrics: attach() needs the HTTP/2 server (server.app.server.server)');
    }
    http2Server.on('session', (session) => this._trackSession(session));
    this._startSampling();
    return this;
  }

  _trackSession(session) {
    const socket = session.socket;
    if (!socket) return;

    const id = this._nextConnectionId++;
    const record = {
      id,
      principal: null,
      spiffeId: null,
      openedAt: Date.now(),
      remoteAddress: socket.remoteAddress || null,
      // Sampled from the socket rather than accumulated per message: the socket already counts
      // this correctly, including everything the framing layer added.
      bytesIn: 0,
      bytesOut: 0,
      requests: 0,
      lastSeenAt: Date.now(),
      socket,
    };

    // The certificate is available as soon as the TLS handshake completes, which for an HTTP/2
    // session is before 'session' fires. `getPeerCertificate` returns {} for a peer that
    // presented none -- which is legitimate here, because the bootstrap and enrolment endpoints
    // are reachable without one.
    if (typeof socket.getPeerCertificate === 'function') {
      const cert = socket.getPeerCertificate();
      if (cert && cert.subject) {
        record.principal = cert.subject.CN || null;
        record.spiffeId = extractSpiffeId(cert);
      }
    }

    this._connections.set(id, record);
    if (record.principal) this._ensure(record.principal).connectionsOpened += 1;
    else this._unattributed.connections += 1;

    const close = () => {
      this._sampleConnection(record);
      this._connections.delete(id);
      if (record.principal) {
        const entry = this._ensure(record.principal);
        entry.connectionsClosed += 1;
        entry.lastSeenAt = Date.now();
      }
      this.emit('disconnected', { id, principal: record.principal });
    };
    session.once('close', close);
    session.once('error', close);

    // Requests are counted here rather than in a handler, so a request refused by the transport
    // (wrong security level, sealed database) still shows up. A panel that only counts requests
    // that reached a handler cannot show you a service being turned away.
    session.on('stream', () => {
      record.requests += 1;
      record.lastSeenAt = Date.now();
      if (record.principal) this._ensure(record.principal).requests += 1;
    });

    this.emit('connected', { id, principal: record.principal, spiffeId: record.spiffeId });
  }

  _ensure(principal) {
    let entry = this._principals.get(principal);
    if (!entry) {
      entry = {
        principal,
        spiffeId: null,
        bytesIn: 0,
        bytesOut: 0,
        requests: 0,
        connectionsOpened: 0,
        connectionsClosed: 0,
        firstSeenAt: Date.now(),
        lastSeenAt: Date.now(),
      };
      this._principals.set(principal, entry);
    }
    return entry;
  }

  // ---- sampling -----------------------------------------------------------------------------

  _startSampling() {
    if (this._sampler) return;
    this._sampler = setInterval(() => this.sample(), this.sampleIntervalMs);
    // A metrics timer must never be the reason a process stays alive.
    if (typeof this._sampler.unref === 'function') this._sampler.unref();
  }

  /**
   * Reads the live sockets and folds the delta into the per-principal totals.
   *
   * Deltas rather than absolutes because `socket.bytesRead` is per-socket and resets with the
   * socket; adding the absolute value each time would multiply a long-lived connection's
   * traffic by the number of samples taken.
   */
  sample() {
    for (const record of this._connections.values()) this._sampleConnection(record);
    return this;
  }

  _sampleConnection(record) {
    const socket = record.socket;
    if (!socket) return;
    const readNow = socket.bytesRead || 0;
    const writtenNow = socket.bytesWritten || 0;
    const deltaIn = Math.max(0, readNow - record.bytesIn);
    const deltaOut = Math.max(0, writtenNow - record.bytesOut);
    record.bytesIn = readNow;
    record.bytesOut = writtenNow;

    if (record.principal) {
      const entry = this._ensure(record.principal);
      entry.bytesIn += deltaIn;
      entry.bytesOut += deltaOut;
      if (record.spiffeId) entry.spiffeId = record.spiffeId;
      entry.lastSeenAt = Date.now();
    } else {
      this._unattributed.bytesIn += deltaIn;
      this._unattributed.bytesOut += deltaOut;
    }
  }

  // ---- reading ------------------------------------------------------------------------------

  /** Per-principal totals, newest activity first. */
  services() {
    this.sample();
    return [...this._principals.values()]
      .map((entry) => ({
        ...entry,
        totalBytes: entry.bytesIn + entry.bytesOut,
        megabytes: round2((entry.bytesIn + entry.bytesOut) / BYTES_IN_MB),
        connectionsLive: entry.connectionsOpened - entry.connectionsClosed,
      }))
      .sort((a, b) => b.lastSeenAt - a.lastSeenAt);
  }

  /** Connections open right now. */
  connections() {
    this.sample();
    return [...this._connections.values()].map((record) => ({
      id: record.id,
      principal: record.principal,
      spiffeId: record.spiffeId,
      // A connection with no principal is not an error: the control plane and the enrolment
      // endpoints are reachable without a certificate, by design.
      authenticated: !!record.principal,
      remoteAddress: record.remoteAddress,
      openedAt: record.openedAt,
      lastSeenAt: record.lastSeenAt,
      requests: record.requests,
      megabytes: round2((record.bytesIn + record.bytesOut) / BYTES_IN_MB),
    })).sort((a, b) => a.openedAt - b.openedAt);
  }

  unattributed() {
    this.sample();
    return {
      ...this._unattributed,
      megabytes: round2((this._unattributed.bytesIn + this._unattributed.bytesOut) / BYTES_IN_MB),
    };
  }

  /**
   * Disk occupied by each database, by walking its directory.
   *
   * Walked rather than tracked incrementally because the engine compacts, snapshots and rewrites
   * segments on its own schedule; a counter maintained here would drift away from the truth and
   * there would be no way to notice.
   */
  async storage() {
    if (!this.baseDir || !fs.existsSync(this.baseDir)) return [];
    const entries = await fsp.readdir(this.baseDir, { withFileTypes: true });
    const out = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const dir = path.join(this.baseDir, entry.name);
      const bytes = await directorySize(dir);
      out.push({
        dbId: entry.name,
        bytes,
        megabytes: round2(bytes / BYTES_IN_MB),
      });
    }
    return out.sort((a, b) => b.bytes - a.bytes);
  }

  summary() {
    const services = this.services();
    const totalBytes = services.reduce((sum, s) => sum + s.totalBytes, 0);
    return {
      startedAt: this.startedAt,
      resetAt: this.resetAt,
      uptimeMs: Date.now() - this.startedAt,
      sinceResetMs: Date.now() - this.resetAt,
      principals: services.length,
      liveConnections: this._connections.size,
      totalMegabytes: round2(totalBytes / BYTES_IN_MB),
      unattributed: this.unattributed(),
      process: {
        // rss is what the operator sees in `top`; heapUsed is what a leak shows up in first.
        rssMegabytes: round2(process.memoryUsage().rss / BYTES_IN_MB),
        heapUsedMegabytes: round2(process.memoryUsage().heapUsed / BYTES_IN_MB),
        uptimeSeconds: Math.floor(process.uptime()),
      },
    };
  }

  // ---- resetting ----------------------------------------------------------------------------

  /**
   * Zeroes the counters. Live connections keep their sockets, so the next sample counts only
   * what happens from here -- resetting must not make an active connection's whole history
   * reappear as one enormous delta.
   *
   * @param {string} [principal] reset one service; omit to reset everything
   */
  reset(principal = null) {
    this.sample();

    if (principal) {
      const entry = this._principals.get(principal);
      if (!entry) return { reset: false, reason: 'unknown principal' };
      Object.assign(entry, {
        bytesIn: 0, bytesOut: 0, requests: 0,
        // Connection counts are NOT zeroed to zero-minus-live: subtracting the closed count
        // from the opened one is how `connectionsLive` is derived, so resetting both to 0 while
        // connections are still open would show a negative live count as they close.
        connectionsOpened: entry.connectionsOpened - entry.connectionsClosed,
        connectionsClosed: 0,
      });
      this.emit('reset', { principal });
      return { reset: true, principal };
    }

    for (const entry of this._principals.values()) {
      Object.assign(entry, {
        bytesIn: 0, bytesOut: 0, requests: 0,
        connectionsOpened: entry.connectionsOpened - entry.connectionsClosed,
        connectionsClosed: 0,
      });
    }
    this._unattributed = { bytesIn: 0, bytesOut: 0, connections: 0 };
    this.resetAt = Date.now();
    this.emit('reset', { principal: null });
    return { reset: true, principal: null };
  }

  /** Forgets a service entirely -- for one that has been decommissioned. */
  forget(principal) {
    const existed = this._principals.delete(principal);
    return { forgotten: existed };
  }

  close() {
    if (this._sampler) { clearInterval(this._sampler); this._sampler = null; }
  }
}

async function directorySize(dir) {
  let total = 0;
  let entries;
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch (_) {
    // A directory that vanished between the listing and the walk is a compaction, not an error.
    return 0;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    try {
      if (entry.isDirectory()) total += await directorySize(full);
      else if (entry.isFile()) total += (await fsp.stat(full)).size;
    } catch (_) { /* same */ }
  }
  return total;
}

/**
 * Pulls a SPIFFE ID out of Node's peer-certificate shape.
 *
 * `getPeerCertificate()` returns `subjectaltname` as a comma-joined string ("DNS:a, URI:b"),
 * which is a different shape from what the transport hands the principal resolver -- hence a
 * second reader here rather than reusing that one.
 */
function extractSpiffeId(cert) {
  const raw = cert.subjectaltname || '';
  for (const part of String(raw).split(',')) {
    const value = part.trim();
    if (/^URI:spiffe:\/\//i.test(value)) return value.slice(4);
  }
  return null;
}

function round2(n) { return Math.round(n * 100) / 100; }

function createServiceMetrics(options) { return new ServiceMetrics(options); }

module.exports = { ServiceMetrics, createServiceMetrics, BYTES_IN_MB };
