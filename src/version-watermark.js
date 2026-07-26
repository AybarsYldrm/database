'use strict';

// AEAD authentication (see storage-engine.js) proves a frame is genuine and untampered, but
// by itself it does NOT prove a frame is the *latest* one — a storage node that is untrusted
// (e.g. reached over the direct-access capability-token path, see direct-server.js) could
// still serve an older, perfectly authentic frame instead of the newest write for a given id.
// This is the classic "rollback/snapshot replay" gap: AEAD gives integrity of a message, not
// freshness across messages.
//
// The fix has to live on the side that does NOT trust the storage node, i.e. the client. A
// client keeps a small watermark of the highest version it has ever observed per id; if a
// later read comes back with a lower version, that is direct evidence of a rollback and
// should be treated as an integrity failure, not silently accepted.
//
// This only defends within a given client's observed history (it cannot detect a rollback to
// a version older than anything that client has ever seen) — for durability across restarts,
// persist the watermark map alongside other client-held state.
class VersionWatermark {
  constructor() { this.seen = new Map(); } // idStr -> highest version observed

  // Throws if `version` is a regression versus what this client has already observed for
  // `id`; otherwise records the new high-water mark and returns true.
  check(id, version) {
    const idStr = String(id);
    const prev = this.seen.get(idStr);
    if (prev !== undefined && version < prev) {
      throw new Error(`fitdb: rollback detected for id ${idStr} (saw version ${prev} previously, got ${version})`);
    }
    this.seen.set(idStr, prev === undefined ? version : Math.max(prev, version));
    return true;
  }

  toJSON() { return Object.fromEntries(this.seen); }
  static fromJSON(obj) {
    const w = new VersionWatermark();
    for (const [k, v] of Object.entries(obj || {})) w.seen.set(k, Number(v));
    return w;
  }
}

module.exports = { VersionWatermark };
