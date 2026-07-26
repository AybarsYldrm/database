'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const { encodeIndexValue, decodeIndexValue, compareIndexValues } = require('./index-value-codec');
const { idToBuf, bufToId } = require('./id-codec');

// A single immutable, sorted-by-key on-disk file, in the spirit of an LSM "SSTable"
// (LevelDB/RocksDB/Cassandra all use this pattern). This is the actual "disk-backed" part
// of the disk-backed index: opening a segment only loads its SPARSE index into RAM (one
// entry per block, not one per key), so RAM use is O(entries / entriesPerBlock), not
// O(entries). A lookup binary-searches the sparse index (RAM, fast), then reads and scans
// exactly one block from disk (bounded I/O, not the whole file).
//
// File layout:
//   [magic:4 'SIDX'][version:1][blockCount:4 BE]
//   Data blocks (sequential, globally sorted by key):
//     [entryCount:4 BE] { [keyEncoded][idCount:4 BE][id:8]*idCount }*entryCount
//   Sparse index (one entry per block, at the END of the file):
//     { [firstKeyEncoded][blockOffset:4 BE][blockLength:4 BE] }*blockCount
//   Footer: [sparseIndexOffset:4 BE][sparseIndexLength:4 BE][magic:4 'SIDX']
//
// Segments are immutable once written: there is no in-place update. New/changed data lives
// in a bounded in-memory memtable (see secondary-index-store.js) until flushed, at which
// point the memtable is merge-sorted against this file's entries to produce a brand-new
// segment (old one deleted after the new one lands) -- the same "never mutate in place,
// always write a new immutable file and swap" discipline already used for the main
// storage segments and index.snapshot elsewhere in fitdb.

const MAGIC = Buffer.from('SIDX');
const VERSION = 1;
const DEFAULT_ENTRIES_PER_BLOCK = 128;

function encodeEntry(key, idSet) {
  const keyBuf = encodeIndexValue(key);
  const idCountBuf = Buffer.alloc(4); idCountBuf.writeUInt32BE(idSet.size, 0);
  const idsBuf = Buffer.concat([...idSet].map(idToBuf));
  return Buffer.concat([keyBuf, idCountBuf, idsBuf]);
}

function decodeEntry(buf, offset) {
  const { value: key, next: afterKey } = decodeIndexValue(buf, offset);
  let o = afterKey;
  const idCount = buf.readUInt32BE(o); o += 4;
  const ids = new Set();
  for (let i = 0; i < idCount; i++) { ids.add(bufToId(buf.subarray(o, o + 8))); o += 8; }
  return { key, ids, next: o };
}

class SortedIndexSegment {
  constructor(filePath) {
    this.filePath = filePath;
    this.sparseIndex = []; // [{ firstKey, blockOffset, blockLength }], sorted by firstKey
    this.blockCount = 0;
    this._readFd = null;
  }

  static async writeFromSortedEntries(filePath, sortedEntries, { entriesPerBlock = DEFAULT_ENTRIES_PER_BLOCK } = {}) {
    const blocks = [];
    for (let i = 0; i < sortedEntries.length; i += entriesPerBlock) {
      blocks.push(sortedEntries.slice(i, i + entriesPerBlock));
    }

    const dataParts = [];
    const sparseParts = [];
    let runningOffset = 4 + 1 + 4; // after magic+version+blockCount header

    for (const block of blocks) {
      const entryBufs = block.map(([key, idSet]) => encodeEntry(key, idSet));
      const countBuf = Buffer.alloc(4); countBuf.writeUInt32BE(block.length, 0);
      const blockBuf = Buffer.concat([countBuf, ...entryBufs]);
      dataParts.push(blockBuf);

      const firstKeyBuf = encodeIndexValue(block[0][0]);
      const offsetBuf = Buffer.alloc(4); offsetBuf.writeUInt32BE(runningOffset, 0);
      const lengthBuf = Buffer.alloc(4); lengthBuf.writeUInt32BE(blockBuf.length, 0);
      sparseParts.push(Buffer.concat([firstKeyBuf, offsetBuf, lengthBuf]));

      runningOffset += blockBuf.length;
    }

    const header = Buffer.alloc(4 + 1 + 4);
    MAGIC.copy(header, 0);
    header.writeUInt8(VERSION, 4);
    header.writeUInt32BE(blocks.length, 5);

    const sparseIndexBuf = Buffer.concat(sparseParts);
    const sparseIndexOffset = runningOffset;
    const footer = Buffer.alloc(4 + 4 + 4);
    footer.writeUInt32BE(sparseIndexOffset, 0);
    footer.writeUInt32BE(sparseIndexBuf.length, 4);
    MAGIC.copy(footer, 8);

    const tmpPath = filePath + '.tmp';
    await fsp.writeFile(tmpPath, Buffer.concat([header, ...dataParts, sparseIndexBuf, footer]));
    await fsp.rename(tmpPath, filePath); // atomic swap, same discipline as index.snapshot
  }

  async open() {
    const stat = await fsp.stat(this.filePath);
    this._readFd = await fsp.open(this.filePath, 'r');

    const footerBuf = Buffer.alloc(12);
    await this._readFd.read(footerBuf, 0, 12, stat.size - 12);
    if (!footerBuf.subarray(8, 12).equals(MAGIC)) throw new Error('fitdb: corrupt sorted index segment (bad footer magic)');
    const sparseIndexOffset = footerBuf.readUInt32BE(0);
    const sparseIndexLength = footerBuf.readUInt32BE(4);

    const headerBuf = Buffer.alloc(9);
    await this._readFd.read(headerBuf, 0, 9, 0);
    if (!headerBuf.subarray(0, 4).equals(MAGIC)) throw new Error('fitdb: corrupt sorted index segment (bad header magic)');
    if (headerBuf.readUInt8(4) !== VERSION) throw new Error('fitdb: unsupported sorted index segment version');
    this.blockCount = headerBuf.readUInt32BE(5);

    const sparseBuf = Buffer.alloc(sparseIndexLength);
    await this._readFd.read(sparseBuf, 0, sparseIndexLength, sparseIndexOffset);
    this.sparseIndex = [];
    let off = 0;
    for (let i = 0; i < this.blockCount; i++) {
      const { value: firstKey, next } = decodeIndexValue(sparseBuf, off);
      const blockOffset = sparseBuf.readUInt32BE(next);
      const blockLength = sparseBuf.readUInt32BE(next + 4);
      this.sparseIndex.push({ firstKey, blockOffset, blockLength });
      off = next + 8;
    }
    return this;
  }

  async close() {
    if (this._readFd) { await this._readFd.close(); this._readFd = null; }
  }

  // Binary-search the (small, RAM-resident) sparse index for the LAST block whose firstKey
  // is <= target -- that's the only block that could contain target, since blocks are
  // globally sorted and non-overlapping.
  _findBlockFor(key) {
    let lo = 0, hi = this.sparseIndex.length - 1, result = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (compareIndexValues(this.sparseIndex[mid].firstKey, key) <= 0) { result = mid; lo = mid + 1; }
      else hi = mid - 1;
    }
    return result === -1 ? null : this.sparseIndex[result];
  }

  async _readBlock(blockMeta) {
    const buf = Buffer.alloc(blockMeta.blockLength);
    await this._readFd.read(buf, 0, blockMeta.blockLength, blockMeta.blockOffset);
    const entryCount = buf.readUInt32BE(0);
    let off = 4;
    const entries = [];
    for (let i = 0; i < entryCount; i++) {
      const { key, ids, next } = decodeEntry(buf, off);
      entries.push([key, ids]);
      off = next;
    }
    return entries;
  }

  // Point lookup: one sparse-index binary search (RAM) + one bounded block read (disk).
  async get(key) {
    const blockMeta = this._findBlockFor(key);
    if (!blockMeta) return null;
    const entries = await this._readBlock(blockMeta);
    for (const [k, ids] of entries) if (compareIndexValues(k, key) === 0) return ids;
    return null;
  }

  // Range scan: walk every block whose key range could overlap [min,max]. Still bounded --
  // only touches blocks that might contain a match, not the whole file.
  async range(min, max) {
    const out = new Map();
    for (let i = 0; i < this.sparseIndex.length; i++) {
      const blockMeta = this.sparseIndex[i];
      const nextFirstKey = i + 1 < this.sparseIndex.length ? this.sparseIndex[i + 1].firstKey : null;
      // skip blocks that end before `min` starts (next block's firstKey <= min means this
      // whole block is before the range)
      if (nextFirstKey !== null && compareIndexValues(nextFirstKey, min) <= 0) continue;
      if (compareIndexValues(blockMeta.firstKey, max) > 0) break; // sorted -> nothing further matches
      const entries = await this._readBlock(blockMeta);
      for (const [k, ids] of entries) {
        if (compareIndexValues(k, min) >= 0 && compareIndexValues(k, max) <= 0) out.set(k, ids);
      }
    }
    return out;
  }

  // Full iteration in sorted order, used by the merge step when flushing a memtable.
  async *entries() {
    for (const blockMeta of this.sparseIndex) {
      const entries = await this._readBlock(blockMeta);
      for (const e of entries) yield e;
    }
  }
}

module.exports = { SortedIndexSegment, encodeEntry, decodeEntry };
