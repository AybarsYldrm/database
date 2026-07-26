'use strict';

// Segmented LRU (a la MySQL InnoDB's buffer-pool midpoint insertion / ARC-style two-list
// scheme): new entries land in a small "probationary" segment; a second touch promotes them
// into a larger "protected" segment. This means a single scan through cold records (a full
// table scan, a one-off export) can't flush out the genuinely hot working set the way a
// plain single-list LRU would. Both segments are backed by a Map, whose insertion-order
// iteration gives O(1) amortized "oldest first" eviction without any extra bookkeeping.
class SegmentedLRUCache {
  constructor({ maxEntries = 10000, protectedRatio = 0.8, ttlMs = 0 } = {}) {
    this.maxEntries = maxEntries;
    this.maxProtected = Math.max(1, Math.floor(maxEntries * protectedRatio));
    this.ttlMs = ttlMs;
    this.probationary = new Map();
    this.protectedSeg = new Map();
  }

  _expired(entry) { return this.ttlMs > 0 && entry.expiresAt < Date.now(); }
  _wrap(value) { return { value, expiresAt: this.ttlMs > 0 ? Date.now() + this.ttlMs : Infinity }; }

  get(key) {
    if (this.protectedSeg.has(key)) {
      const entry = this.protectedSeg.get(key);
      if (this._expired(entry)) { this.protectedSeg.delete(key); return undefined; }
      this.protectedSeg.delete(key); this.protectedSeg.set(key, entry); // refresh recency
      return entry.value;
    }
    if (this.probationary.has(key)) {
      const entry = this.probationary.get(key);
      if (this._expired(entry)) { this.probationary.delete(key); return undefined; }
      this.probationary.delete(key);
      this._insertProtected(key, entry); // second touch -> promote
      return entry.value;
    }
    return undefined;
  }

  set(key, value) {
    const entry = this._wrap(value);
    if (this.protectedSeg.has(key)) { this.protectedSeg.delete(key); this._insertProtected(key, entry); return; }
    this.probationary.delete(key);
    this.probationary.set(key, entry);
    this._evictIfNeeded();
  }

  _insertProtected(key, entry) {
    this.protectedSeg.set(key, entry);
    while (this.protectedSeg.size > this.maxProtected) {
      const oldestKey = this.protectedSeg.keys().next().value;
      const oldestEntry = this.protectedSeg.get(oldestKey);
      this.protectedSeg.delete(oldestKey);
      this.probationary.set(oldestKey, oldestEntry); // demote, don't just drop
    }
    this._evictIfNeeded();
  }

  _evictIfNeeded() {
    while (this.probationary.size + this.protectedSeg.size > this.maxEntries) {
      if (this.probationary.size > 0) this.probationary.delete(this.probationary.keys().next().value);
      else this.protectedSeg.delete(this.protectedSeg.keys().next().value);
    }
  }

  delete(key) { this.probationary.delete(key); this.protectedSeg.delete(key); }
  has(key) { return this.probationary.has(key) || this.protectedSeg.has(key); }
  get size() { return this.probationary.size + this.protectedSeg.size; }
  clear() { this.probationary.clear(); this.protectedSeg.clear(); }
}

module.exports = { SegmentedLRUCache };
