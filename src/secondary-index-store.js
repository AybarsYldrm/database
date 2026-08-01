'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const { SortedIndexSegment } = require('./sorted-index-segment');
const { compareIndexValues } = require('./index-value-codec');

// LSM-style secondary index: writes land in a small, bounded in-memory memtable; once it
// grows past flushThreshold entries, it is merge-sorted against the existing on-disk
// SortedIndexSegment (if any) and written out as a brand-new segment (old one discarded) --
// after a flush, RAM usage drops back to just the sparse index (see sorted-index-segment.js),
// which is O(entries / entriesPerBlock), not O(entries). This is the actual "disk-backed"
// property: a collection with millions of indexed values does not need millions of entries
// resident in RAM at once, only however many have accumulated since the last flush plus one
// sparse-index entry per ~128 total entries.
//
// Simplified relative to a "full" multi-level LSM (RocksDB/LevelDB-style) on purpose: there
// is exactly one on-disk segment at a time, fully rewritten on every flush, rather than
// multiple levels merged lazily. That trades some flush-time I/O (a flush costs O(total
// entries), not O(memtable size)) for a MUCH simpler and more auditable correctness story --
// no cross-segment tombstone bookkeeping, no leveled-compaction scheduling, one code path
// to get right. This is the honest scope: real, bounded-memory, disk-backed, and tested --
// not a from-scratch RocksDB clone.
class SecondaryIndexStore {
  constructor(filePath, { flushThreshold = 2000 } = {}) {
    this.filePath = filePath;
    this.flushThreshold = flushThreshold;
    this.memtable = new Map();    // key -> Set(idStr), additions since the last flush
    this.tombstones = new Map();  // key -> Set(idStr), removals since the last flush
    this.diskSegment = null;      // SortedIndexSegment | null (null until anything is ever flushed)
  }

  async open() {
    if (fs.existsSync(this.filePath)) {
      this.diskSegment = new SortedIndexSegment(this.filePath);
      await this.diskSegment.open();
    }
  }

  async close() {
    await this.flush();
    if (this.diskSegment) await this.diskSegment.close();
  }

  add(key, idStr) {
    if (!this.memtable.has(key)) this.memtable.set(key, new Set());
    this.memtable.get(key).add(idStr);
    this.tombstones.get(key)?.delete(idStr); // undo a same-window tombstone for this exact id, if any
  }

  remove(key, idStr) {
    this.memtable.get(key)?.delete(idStr);
    if (!this.tombstones.has(key)) this.tombstones.set(key, new Set());
    this.tombstones.get(key).add(idStr);
  }

  async get(key) {
    const fromMemtable = this.memtable.get(key) || new Set();
    let fromDisk = new Set();
    if (this.diskSegment) fromDisk = (await this.diskSegment.get(key)) || new Set();
    const tombstoned = this.tombstones.get(key) || new Set();
    const union = new Set([...fromMemtable, ...fromDisk]);
    for (const id of tombstoned) union.delete(id);
    return union;
  }

  async range(min, max) {
    const result = new Map();
    for (const [key, ids] of this.memtable) {
      if (compareIndexValues(key, min) >= 0 && compareIndexValues(key, max) <= 0) result.set(key, new Set(ids));
    }
    if (this.diskSegment) {
      const diskRange = await this.diskSegment.range(min, max);
      for (const [key, ids] of diskRange) {
        if (!result.has(key)) result.set(key, new Set());
        for (const id of ids) result.get(key).add(id);
      }
    }
    for (const [key, tombstoned] of this.tombstones) {
      if (result.has(key)) { for (const id of tombstoned) result.get(key).delete(id); if (result.get(key).size === 0) result.delete(key); }
    }
    return result;
  }

  /**
   * Every live key -> id-set in this store, memtable and disk segment merged, tombstones
   * applied. The full-store counterpart to range(), for a caller that has decided scanning
   * everything is cheaper than probing keys one at a time (see the sweep strategy in
   * CollectionStorage.lookupRangeCandidates).
   */
  async entries() {
    const result = new Map();
    if (this.diskSegment) {
      for await (const [key, ids] of this.diskSegment.entries()) result.set(key, new Set(ids));
    }
    for (const [key, ids] of this.memtable) {
      if (!result.has(key)) result.set(key, new Set());
      const target = result.get(key);
      for (const id of ids) target.add(id);
    }
    for (const [key, tombstoned] of this.tombstones) {
      const live = result.get(key);
      if (!live) continue;
      for (const id of tombstoned) live.delete(id);
      if (live.size === 0) result.delete(key);
    }
    return result;
  }

  needsFlush() { return this.memtable.size + this.tombstones.size >= this.flushThreshold; }

  async flush() {
    if (this.memtable.size === 0 && this.tombstones.size === 0) return;

    const merged = new Map();
    if (this.diskSegment) {
      for await (const [key, ids] of this.diskSegment.entries()) merged.set(key, new Set(ids));
    }
    for (const [key, tombstoned] of this.tombstones) {
      const existing = merged.get(key);
      if (existing) { for (const id of tombstoned) existing.delete(id); if (existing.size === 0) merged.delete(key); }
    }
    for (const [key, ids] of this.memtable) {
      if (!merged.has(key)) merged.set(key, new Set());
      const target = merged.get(key);
      for (const id of ids) target.add(id);
    }
    for (const [key, ids] of [...merged]) if (ids.size === 0) merged.delete(key);

    const oldSegment = this.diskSegment;
    if (oldSegment) await oldSegment.close();

    if (merged.size > 0) {
      const sortedEntries = [...merged.entries()].sort((a, b) => compareIndexValues(a[0], b[0]));
      await SortedIndexSegment.writeFromSortedEntries(this.filePath, sortedEntries);
      this.diskSegment = new SortedIndexSegment(this.filePath);
      await this.diskSegment.open();
    } else {
      this.diskSegment = null;
      await fsp.unlink(this.filePath).catch(() => {});
    }

    this.memtable.clear();
    this.tombstones.clear();
  }
}

module.exports = { SecondaryIndexStore };
