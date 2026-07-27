'use strict';

// Why a change stream exists at all, in a database whose whole point is encryption at rest:
// the alternative for any caller that needs to stay current is polling, and polling an
// encrypted store is unusually expensive -- every poll re-decrypts records that did not
// change, on both ends, forever. The concrete case this was built for is a DNS zone served
// out of fitdb (see dns-store.js): a resolver answering queries cannot afford a decrypt +
// round trip per query, so it holds a decrypted view in memory and this hub tells it when
// that view goes stale. Same shape works for certificate/key material (secret-store.js),
// where the cost of a stale cache is worse than the cost of a stale DNS answer.
//
// Deliberately in-process and best-effort: a ChangeHub is not a durable log and is not a
// replication protocol. Every event carries a monotonically increasing `seq`, and the hub
// keeps a bounded backlog so a subscriber that briefly disconnects can resume from where it
// left off; a subscriber that falls further behind than the backlog is told so explicitly
// (`resumeLost`) rather than being handed a silently incomplete stream, and is expected to
// re-snapshot. That distinction -- "you are behind, and I know it" vs. "here is a gap you
// cannot see" -- is the only thing that makes a cached view safe to trust.

const CHANGE_OPS = Object.freeze({ PUT: 'put', DELETE: 'delete' });

const ALL_COLLECTIONS = '*';

class ChangeHub {
  constructor({ backlogSize = 1024 } = {}) {
    this.backlogSize = backlogSize;
    this._seq = 0;
    this._collSeq = new Map();     // collectionName -> per-collection counter
    this._subscribers = new Map(); // collectionName ('*' for all) -> Set(handler)
    this._backlog = [];            // bounded, ordered by seq ascending
  }

  get lastSeq() { return this._seq; }

  // Every event carries two counters, and the difference matters. `seq` is database-global
  // and orders the backlog; `collSeq` counts only within one collection. A watcher following
  // a single collection must check contiguity on `collSeq`, because writes to OTHER
  // collections consume global `seq` numbers and would look like gaps in its stream -- a
  // "gap" that is not a lost event, and must not be reported as one.
  lastCollSeq(collection) { return this._collSeq.get(collection) || 0; }

  // Returns an unsubscribe function. `collection` may be a specific name or '*'.
  subscribe(collection, handler) {
    const key = collection || ALL_COLLECTIONS;
    if (!this._subscribers.has(key)) this._subscribers.set(key, new Set());
    this._subscribers.get(key).add(handler);
    return () => {
      const set = this._subscribers.get(key);
      if (!set) return;
      set.delete(handler);
      if (set.size === 0) this._subscribers.delete(key);
    };
  }

  subscriberCount(collection) {
    const exact = this._subscribers.get(collection)?.size || 0;
    const wildcard = this._subscribers.get(ALL_COLLECTIONS)?.size || 0;
    return exact + wildcard;
  }

  publish({ collection, op, id, version = 0, record = null }) {
    const collSeq = (this._collSeq.get(collection) || 0) + 1;
    this._collSeq.set(collection, collSeq);
    const event = {
      seq: ++this._seq,
      collSeq,
      collection,
      op,
      id: String(id),
      version,
      record,
      at: Date.now(),
    };

    this._backlog.push(event);
    if (this._backlog.length > this.backlogSize) this._backlog.splice(0, this._backlog.length - this.backlogSize);

    // A throwing subscriber must not break the write that produced the event, nor starve the
    // subscribers after it in iteration order -- publish() is called from inside the storage
    // engine's write path, where an exception would surface as a failed insert.
    for (const key of [collection, ALL_COLLECTIONS]) {
      const set = this._subscribers.get(key);
      if (!set) continue;
      for (const handler of [...set]) {
        try { handler(event); } catch (_) { /* a broken subscriber is its own problem */ }
      }
    }
    return event;
  }

  // Events strictly after `afterSeq`, for a subscriber reconnecting with a resume token.
  // `resumeLost: true` means the requested position has already been evicted from the
  // backlog, so the caller MUST re-snapshot instead of treating `events` as a continuation.
  replay(afterSeq, collection = ALL_COLLECTIONS) {
    const from = Number(afterSeq) || 0;
    if (from === 0) return { events: [], resumeLost: false, lastSeq: this._seq };
    const oldestRetained = this._backlog.length ? this._backlog[0].seq : this._seq + 1;
    if (from + 1 < oldestRetained) return { events: [], resumeLost: true, lastSeq: this._seq };
    const events = this._backlog.filter(
      (e) => e.seq > from && (collection === ALL_COLLECTIONS || e.collection === collection),
    );
    return { events, resumeLost: false, lastSeq: this._seq };
  }

  clear() {
    this._backlog.length = 0;
    this._subscribers.clear();
  }
}

// Client-side counterpart: a decrypted, in-memory materialized view kept current by change
// events instead of by re-reading. `applyEvent` is deliberately strict about ordering --
// applying a put whose seq is older than one already applied would silently resurrect stale
// data, which is exactly the failure mode a cache is supposed to make impossible.
class ReplicatedView {
  // `seqField` selects which counter this view checks contiguity on: 'collSeq' when following
  // exactly one collection (the common case), 'seq' when following '*'. Getting this wrong
  // does not corrupt data -- it makes the view declare itself stale on every unrelated write.
  constructor({ keyField = '_id', seqField = 'collSeq' } = {}) {
    this.keyField = keyField;
    this.seqField = seqField;
    this.records = new Map(); // idStr -> record
    this.lastSeq = 0;
    this.stale = true; // until a snapshot lands, nothing here is trustworthy
  }

  loadSnapshot(records, lastSeq) {
    this.records.clear();
    for (const r of records) this.records.set(String(r[this.keyField]), r);
    this.lastSeq = Number(lastSeq) || 0;
    this.stale = false;
    return this;
  }

  applyEvent(event) {
    if (this.stale) return false;
    const seq = event[this.seqField];
    if (seq <= this.lastSeq) return false; // already applied (duplicate delivery)
    if (seq !== this.lastSeq + 1) {
      // A gap means at least one change was never delivered; the view can no longer claim to
      // be a faithful copy, so it says so rather than quietly serving a half-updated set.
      this.stale = true;
      return false;
    }
    if (event.op === CHANGE_OPS.DELETE) this.records.delete(String(event.id));
    else if (event.record) this.records.set(String(event.id), event.record);
    this.lastSeq = seq;
    return true;
  }

  get(id) { return this.records.get(String(id)) || null; }
  all() { return [...this.records.values()]; }
  get size() { return this.records.size; }
}

module.exports = { ChangeHub, ReplicatedView, CHANGE_OPS, ALL_COLLECTIONS };
