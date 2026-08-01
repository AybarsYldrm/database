'use strict';

const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const zlib = require('node:zlib');

const { encodeRecord, decodeRecord } = require('./binary-codec');
const { aesGcmEncrypt, aesGcmDecrypt, deriveBlindIndexKey, blindIndexValue } = require('./crypto-core');
const { AsyncQueue } = require('./async-queue');
const { encodeIndexValue, decodeIndexValue } = require('./index-value-codec');
const { idToBuf, bufToId } = require('./id-codec');
const { SecondaryIndexStore } = require('./secondary-index-store');
const { adapt } = require('./logger');

// On-disk frame format, one per record mutation, appended sequentially to a segment file:
//   [op:1][flags:1][id:8 BE][version:4 BE][payloadLen:4 BE][payload: iv(12)+tag(16)+ciphertext]
//
// `payload` is the AES-256-GCM output of encrypting the (optionally compressed) encoded
// record; AAD = id ++ op ++ flags ++ version, so a frame can never be silently relabeled
// under a different id/op/flags, AND a storage node cannot replay an older-but-genuinely-
// authentic frame for the same id without the mismatch being detectable by anyone tracking
// per-id version watermarks (see lib/version-watermark.js) — this specifically matters at
// the direct-access trust boundary (lib/direct-server.js), where the storage process is not
// the same trust domain as the connecting client.
const HEADER_SIZE = 1 + 1 + 8 + 4 + 4; // op, flags, id, version, payloadLen
const OP_PUT = 1;
const OP_DELETE = 2;
const FLAG_COMPRESSED = 0x01;

const SNAPSHOT_MAGIC = Buffer.from('FDBX');
const SNAPSHOT_VERSION = 4; // bumped: snapshot now also persists rangeBucket index tables

// The most discrete rangeBucket keys a single range query will ever probe.
//
// This constant exists because its absence took the whole process down. `lookupRangeCandidates`
// walks one bucket at a time from min to max, hashing each bucket number into its blind key, so
// its cost is set by the WIDTH OF THE RANGE, not by how much data is stored. A caller asking the
// natural question "everything due by now" -- findRange(field, 0, Date.now()) -- on a field
// bucketed by the minute asks for floor(Date.now() / 60000) buckets: just under thirty million
// HMACs, none of which await anything on the in-memory path, so the event loop is held for over
// two minutes per call with a single row in the collection.
//
// What that looked like from the outside is worth recording, because it is nothing like "a slow
// query": every other client of the database stopped being served, the queue's next poll piled
// up behind the one still running, and a restart changed nothing -- the first poll after boot
// hit the same call. Only an EMPTY collection was fast, because the field's bucket map does not
// exist until the first row is written and the lookup returned early. Deleting the database
// therefore "fixed" it, right up until the next message was enqueued.
//
// Past this many buckets, probing is abandoned for a scan of the field's populated buckets
// (see the fallback in lookupRangeCandidates), which is bounded by how much data actually
// exists rather than by how wide the caller's range happens to be.
const MAX_PROBED_BUCKETS = 4096;

// How many buckets to probe between yields to the event loop. Even a within-budget probe
// should not be an uninterruptible unit of work: a database that answers nothing at all while
// one query runs is the failure this whole area is about.
const PROBE_YIELD_INTERVAL = 512;

function segFileName(segId) { return `seg-${String(segId).padStart(6, '0')}.log`; }

function buildAad(idBuf, op, flags, version) {
  const vb = Buffer.alloc(4);
  vb.writeUInt32BE(version, 0);
  return Buffer.concat([idBuf, Buffer.from([op, flags]), vb]);
}




/**
 * Raised when putUnique() finds a live record already holding the value. Carries the field and
 * value so a caller can map it onto its own vocabulary -- the gRPC layer turns it into
 * ALREADY_EXISTS, the IdP turns it into "this key has already been certified".
 */
class UniqueConstraintError extends Error {
  constructor(field, value, message) {
    super(message || `fitdb: duplicate value for unique field '${field}'`);
    this.name = 'UniqueConstraintError';
    this.code = 'UNIQUE_CONSTRAINT';
    this.field = field;
    this.value = value;
  }
}

class CollectionStorage {
  constructor({ dir, ddk, schema, segmentMaxBytes = 16 * 1024 * 1024, compress = false, cache, maxOpenReadFds = 64, cryptoOffload = null, diskFlushThreshold = 2000, onChange = null, logger = null, name = null }) {
    this.name = name || path.basename(dir || '');
    // adapt(), not the logger as given: a host logger with only info/warn/error would
    // otherwise reach `this.log.timer(...)` in open() and throw, leaving the collection
    // permanently unopened because someone supplied a simple logger.
    this.log = adapt(logger, logger ? this.name : `fitdb:storage:${this.name}`);
    this.dir = dir;
    this.ddk = ddk;
    this.schema = schema; // array of {no,name,type,index?,blindIndex?,required?,diskBacked?}
    this.segmentMaxBytes = segmentMaxBytes;
    this.compress = compress;
    this.cache = cache;
    this.maxOpenReadFds = maxOpenReadFds;
    this.diskFlushThreshold = diskFlushThreshold; // memtable entries before a disk-backed field flushes
    // Fired after a mutation is durable AND indexed, never before -- a subscriber must never
    // be able to observe a change that a concurrent reader cannot yet see. Notification order
    // matches write order because every mutation runs through the same AsyncQueue.
    this.onChange = onChange;
    // Optional { pool: CryptoWorkerPool, thresholdBytes } -- see crypto-worker-pool.js for
    // why this is gated by size and off by default: worker-thread dispatch measurably LOSES
    // to inline main-thread AES-GCM for small records (fitdb's realistic case), and only
    // wins for large payloads. Below thresholdBytes, behavior is identical to no pool at all.
    this.cryptoOffload = cryptoOffload;

    this.index = new Map();      // idStr -> {segmentId, offset(payload start), length, version, flags, deleted}
    this.secondary = new Map();  // fieldName -> Map(value -> Set(idStr))
    this.blind = new Map();      // fieldName -> Map(blindHex -> Set(idStr))
    this.rangeBuckets = new Map(); // fieldName -> Map(bucketHashHex -> Set(idStr)) -- see rangeBucket schema option
    this.diskStores = new Map(); // fieldName -> SecondaryIndexStore, for fields with diskBacked:true (real bounded-memory index)
    this._blindKeys = new Map(); // fieldName -> derived blind key (cached)
    this._rangeKeys = new Map(); // fieldName -> derived range-bucket blind key (cached, distinct from _blindKeys)

    // segmentId -> { fd, segId, inUse, retired }; bounded and LRU-evicted, but never evicting
    // a handle a concurrent read is still positioned on -- see _acquireReadFd.
    this.readFds = new Map();
    this._readFdOpens = new Map(); // segmentId -> Promise<entry> for an open in flight
    this.activeSegmentId = 0;
    this.activeSegmentOffset = 0;
    this.activeWriteFd = null;

    this._writeQueue = new AsyncQueue();
    this._opened = false;
  }

  // ---- lifecycle -----------------------------------------------------------------------

  async open() {
    // Opening twice would silently orphan the first activeWriteFd and every read handle taken
    // during replay, and leave two in-memory indexes disagreeing about the same file. Callers
    // that legitimately race (two requests for the same collection) share the first open.
    if (this._opened) return this;
    if (this._openPromise) return this._openPromise;
    this._openPromise = this._openOnce().finally(() => { this._openPromise = null; });
    return this._openPromise;
  }

  async _openOnce() {
    const done = this.log.timer('open', { warnAboveMs: 2000 });
    await fsp.mkdir(this.dir, { recursive: true });

    // Disk-backed fields (diskBacked:true) get their own independent, persistent
    // SortedIndexSegment-backed store, opened up front -- their persistence is entirely
    // separate from index.snapshot (which only ever holds non-disk-backed fields' entries,
    // since _indexInsertOnly/_indexRemove route disk-backed fields here instead).
    for (const f of this.schema) {
      if (f.diskBacked) {
        const store = new SecondaryIndexStore(path.join(this.dir, `secidx-${f.name}.sidx`), { flushThreshold: this.diskFlushThreshold });
        await store.open();
        this.diskStores.set(f.name, store);
      }
    }

    const files = (await fsp.readdir(this.dir).catch(() => []))
      .filter((f) => /^seg-\d+\.log$/.test(f));
    let segNumbers = files.map((f) => parseInt(f.match(/\d+/)[0], 10)).sort((a, b) => a - b);

    const snapshotPath = path.join(this.dir, 'index.snapshot');
    let resumeSegmentId = 0;
    let resumeOffset = 0;
    let haveSnapshot = false;

    if (fs.existsSync(snapshotPath)) {
      try {
        const buf = await fsp.readFile(snapshotPath);
        const parsed = this._parseSnapshot(buf);
        this.index = parsed.index;
        this.secondary = parsed.secondary;
        this.blind = parsed.blind;
        this.rangeBuckets = parsed.rangeBuckets;
        resumeSegmentId = parsed.lastSegmentId;
        resumeOffset = parsed.lastOffset;
        haveSnapshot = true;
      } catch (e) {
        // A discarded snapshot is not a harmless detail: it turns a fast open into a full
        // replay of every segment, and if it happens on EVERY open something is durably wrong
        // (a half-written snapshot, a version the binary no longer understands). Silence here
        // is what made "why does startup take minutes now" unanswerable.
        this.log.warn({
          error: e.message,
          msg: 'index snapshot unusable, falling back to a full segment replay',
        });
        this.index = new Map(); // corrupt/incompatible snapshot -> fall back to a full replay
      }
    }

    if (segNumbers.length === 0) segNumbers = [0]; // brand-new collection

    // If a snapshot loaded, secondary/blind are already populated -- only the (typically
    // small or empty) tail since the last clean snapshot needs its records decrypted to
    // patch those tables incrementally. Without a snapshot, secondary/blind stay empty here
    // and get the full O(live records) rebuild below (unavoidable cold-start cost).
    if (!haveSnapshot) {
      for (const segId of segNumbers) await this._replaySegment(segId, 0, { updateSecondary: false });
    } else {
      if (segNumbers.includes(resumeSegmentId)) await this._replaySegment(resumeSegmentId, resumeOffset, { updateSecondary: true });
      for (const segId of segNumbers) if (segId > resumeSegmentId) await this._replaySegment(segId, 0, { updateSecondary: true });
    }

    this.activeSegmentId = Math.max(...segNumbers, 0);
    const activePath = path.join(this.dir, segFileName(this.activeSegmentId));
    const stat = fs.existsSync(activePath) ? await fsp.stat(activePath) : { size: 0 };
    this.activeSegmentOffset = stat.size;
    this.activeWriteFd = await fsp.open(activePath, 'a');

    if (!haveSnapshot) await this._rebuildSecondaryIndexes();
    this._opened = true;
    done({
      records: this.liveCount(),
      segments: segNumbers.length,
      resumedFromSnapshot: haveSnapshot,
      diskBackedFields: this.diskStores.size,
      msg: 'collection open',
    });
    return this;
  }

  /**
   * Releases every descriptor this storage holds, whether or not open() ran to completion.
   *
   * The `if (!this._opened) return` this used to start with meant a storage whose open()
   * failed part way -- disk-backed index stores created, segment handles taken, then a throw --
   * could not be cleaned up at all: its close() was a no-op and its file handles survived
   * until garbage collection. Snapshotting is the part that needs a complete open; freeing
   * handles is not, and must happen either way.
   */
  async close() {
    const wasOpen = this._opened;
    this._opened = false;
    if (wasOpen) await this._writeSnapshot();
    for (const store of this.diskStores.values()) await store.close().catch(() => {}); // flushes pending memtable/tombstones
    if (this.activeWriteFd) {
      const fd = this.activeWriteFd;
      this.activeWriteFd = null;
      await fd.close().catch(() => {});
    }
    for (const entry of [...this.readFds.values()]) this._retireReadFd(entry);
    this.readFds.clear();
    this._readFdOpens.clear();
  }

  // ---- crypto/compress helpers -----------------------------------------------------------

  _blindKeyFor(fieldName) {
    if (!this._blindKeys.has(fieldName)) this._blindKeys.set(fieldName, deriveBlindIndexKey(this.ddk, fieldName));
    return this._blindKeys.get(fieldName);
  }

  // Distinct derived key from the equality blind index (different HKDF info string) so a
  // range-bucket field and an equality-blind-indexed field never share a namespace even if
  // it were ever the same field name used both ways.
  _rangeKeyFor(fieldName) {
    if (!this._rangeKeys.has(fieldName)) this._rangeKeys.set(fieldName, deriveBlindIndexKey(this.ddk, `range:${fieldName}`));
    return this._rangeKeys.get(fieldName);
  }

  _bucketOf(field, value) {
    // Number() on a BigInt (int64/uint64 fields) loses precision far beyond bucket-relevant
    // magnitudes -- acceptable here because buckets are deliberately coarse (width chosen by
    // the schema author), not because precision doesn't matter in general.
    return Math.floor(Number(value) / field.rangeBucket.width);
  }

  _maybeCompress(plainBuf) {
    if (!this.compress) return { payload: plainBuf, flags: 0 };
    const compressed = zlib.deflateRawSync(plainBuf);
    if (compressed.length < plainBuf.length) return { payload: compressed, flags: FLAG_COMPRESSED };
    return { payload: plainBuf, flags: 0 };
  }
  _maybeDecompress(buf, flags) {
    return (flags & FLAG_COMPRESSED) ? zlib.inflateRawSync(buf) : buf;
  }

  // Routes to the worker pool only when configured AND the payload crosses the measured
  // size threshold; otherwise identical to calling aesGcmEncrypt/aesGcmDecrypt directly.
  async _encrypt(payload, aad) {
    if (this.cryptoOffload && payload.length > this.cryptoOffload.thresholdBytes) {
      return this.cryptoOffload.pool.encrypt(this.ddk, payload, aad);
    }
    return aesGcmEncrypt(this.ddk, payload, aad);
  }
  async _decrypt(framed, aad) {
    if (this.cryptoOffload && framed.length > this.cryptoOffload.thresholdBytes) {
      return this.cryptoOffload.pool.decrypt(this.ddk, framed, aad);
    }
    return aesGcmDecrypt(this.ddk, framed, aad);
  }

  // ---- segment file plumbing (bounded read-FD pool, LRU-evicted) -------------------------

  /**
   * Borrows a read handle for a segment. Every caller must pair this with _release().
   *
   * Two things here exist only because reads run concurrently -- several requests reading the
   * same collection at once is the normal case for a server, not an edge case.
   *
   * The in-flight map: `readFds.has(segId)` followed by `await fsp.open(...)` is a
   * check-then-act, so two readers that both miss on the same segment both open it and the
   * second `set` drops the first handle on the floor, unclosed, for as long as it takes the
   * garbage collector to notice. Sharing the pending open makes the miss happen once.
   *
   * The use count: eviction (and compaction) used to close whichever handle was least
   * recently used, including one another reader was in the middle of a positional read on,
   * which surfaces as a spurious EBADF. A handle that is still in use is unlinked from the
   * pool and closed by whoever releases it last instead.
   */
  async _acquireReadFd(segId) {
    for (;;) {
      const existing = this.readFds.get(segId);
      if (existing) {
        this.readFds.delete(segId); this.readFds.set(segId, existing); // refresh recency
        existing.inUse++; // synchronous with the lookup, so eviction cannot slip in between
        return existing;
      }

      const pending = this._readFdOpens.get(segId);
      if (pending) {
        const entry = await pending;
        entry.inUse++;
        // Retired between this open finishing and this caller counting itself in. The handle
        // may already be closed, so take a fresh one rather than read through it.
        if (entry.retired) { this._release(entry); continue; }
        return entry;
      }

      const opening = (async () => {
        const fd = await fsp.open(path.join(this.dir, segFileName(segId)), 'r');
        // Starts at 1, held by the caller that initiated this open. An entry sitting at 0
        // between being published and being counted could be evicted -- and closed -- by
        // another segment's first read before its own opener ever touched it.
        const entry = { fd, segId, inUse: 1, retired: false };
        this._evictReadFds();
        this.readFds.set(segId, entry);
        return entry;
      })();

      this._readFdOpens.set(segId, opening);
      try {
        return await opening; // the reservation above belongs to this caller
      } finally {
        if (this._readFdOpens.get(segId) === opening) this._readFdOpens.delete(segId);
      }
    }
  }

  _release(entry) {
    if (!entry) return;
    entry.inUse--;
    // Retired while this reader held it: the pool has already forgotten it, so the last
    // release is the only remaining chance to give the descriptor back.
    if (entry.retired && entry.inUse <= 0) entry.fd.close().catch(() => {});
  }

  _retireReadFd(entry) {
    if (!entry || entry.retired) return;
    entry.retired = true;
    this.readFds.delete(entry.segId);
    if (entry.inUse <= 0) entry.fd.close().catch(() => {});
  }

  _evictReadFds() {
    while (this.readFds.size >= this.maxOpenReadFds) {
      const oldest = this.readFds.values().next().value;
      if (!oldest) return;
      this._retireReadFd(oldest);
    }
  }

  async _closeAndDeleteSegment(segId) {
    this._retireReadFd(this.readFds.get(segId));
    await fsp.unlink(path.join(this.dir, segFileName(segId))).catch(() => {});
  }

  async _appendFrame(op, flags, idBuf, version, encPayload) {
    if (this.activeSegmentOffset + HEADER_SIZE + encPayload.length > this.segmentMaxBytes && this.activeSegmentOffset > 0) {
      await this.activeWriteFd.close();
      this.activeSegmentId += 1;
      this.activeSegmentOffset = 0;
      this.activeWriteFd = await fsp.open(path.join(this.dir, segFileName(this.activeSegmentId)), 'a');
    }
    const header = Buffer.alloc(HEADER_SIZE);
    header.writeUInt8(op, 0);
    header.writeUInt8(flags, 1);
    idBuf.copy(header, 2);
    header.writeUInt32BE(version, 10);
    header.writeUInt32BE(encPayload.length, 14);
    const frame = Buffer.concat([header, encPayload]);
    await this.activeWriteFd.write(frame);
    const payloadOffset = this.activeSegmentOffset + HEADER_SIZE;
    this.activeSegmentOffset += frame.length;
    return { segmentId: this.activeSegmentId, offset: payloadOffset, length: encPayload.length, version, flags };
  }

  async _readRawAt(loc) {
    const entry = await this._acquireReadFd(loc.segmentId);
    try {
      const buf = Buffer.alloc(loc.length);
      await entry.fd.read(buf, 0, loc.length, loc.offset);
      return buf;
    } finally {
      this._release(entry);
    }
  }

  async _readAt(idStr, loc) {
    const encPayload = await this._readRawAt(loc);
    const idBuf = idToBuf(idStr);
    const aad = buildAad(idBuf, OP_PUT, loc.flags, loc.version);
    const plain = await this._decrypt(encPayload, aad);
    const decompressed = this._maybeDecompress(plain, loc.flags);
    return decodeRecord(this.schema, decompressed);
  }

  // ---- replay / recovery ------------------------------------------------------------------

  async _replaySegment(segId, fromOffset, { updateSecondary = false } = {}) {
    const filePath = path.join(this.dir, segFileName(segId));
    if (!fs.existsSync(filePath)) return;
    const fd = await fsp.open(filePath, 'r');
    try {
      const stat = await fd.stat();
      let pos = fromOffset;
      const headerBuf = Buffer.alloc(HEADER_SIZE);
      for (;;) {
        if (pos + HEADER_SIZE > stat.size) break; // no more complete frames (possibly a torn write at EOF)
        const { bytesRead } = await fd.read(headerBuf, 0, HEADER_SIZE, pos);
        if (bytesRead < HEADER_SIZE) break;
        const op = headerBuf.readUInt8(0);
        const flags = headerBuf.readUInt8(1);
        const idStr = bufToId(headerBuf.subarray(2, 10));
        const version = headerBuf.readUInt32BE(10);
        const payloadLen = headerBuf.readUInt32BE(14);
        if (pos + HEADER_SIZE + payloadLen > stat.size) break; // torn trailing frame, stop here
        const payloadOffset = pos + HEADER_SIZE;

        // Only relevant for the small tail past a snapshot: decrypt to know what to remove
        // from secondary/blind BEFORE overwriting `this.index`'s entry for this id, using
        // whatever location this.index currently holds (from the snapshot, or an earlier
        // frame in this very replay) as the "before" state.
        let priorObj = null;
        if (updateSecondary) {
          const priorLoc = this.index.get(idStr);
          if (priorLoc && !priorLoc.deleted) priorObj = await this._readAt(idStr, priorLoc);
        }

        if (op === OP_PUT) {
          this.index.set(idStr, { segmentId: segId, offset: payloadOffset, length: payloadLen, version, flags, deleted: false });
          if (updateSecondary) {
            const newObj = await this._readAt(idStr, this.index.get(idStr));
            await this._reconcileIndexes(idStr, priorObj, newObj);
          }
        } else if (op === OP_DELETE) {
          this.index.set(idStr, { segmentId: segId, offset: payloadOffset, length: payloadLen, version, flags, deleted: true });
          if (updateSecondary) await this._reconcileIndexes(idStr, priorObj, {});
        }
        pos = payloadOffset + payloadLen;
      }
    } finally {
      await fd.close();
    }
  }

  async _rebuildSecondaryIndexes() {
    // One decrypt per live record. Timed because on a large collection this is the single
    // slowest thing an open can do, and it is worth being able to attribute a slow start to
    // it rather than guessing.
    const done = this.log.timer('rebuild secondary indexes', { warnAboveMs: 2000 });
    this.secondary.clear();
    this.blind.clear();
    this.rangeBuckets.clear();
    let rebuilt = 0;
    for (const [idStr, loc] of this.index) {
      if (loc.deleted) continue;
      const obj = await this._readAt(idStr, loc);
      await this._indexInsertOnly(idStr, obj);
      rebuilt++;
    }
    done({ records: rebuilt });
  }

  /**
   * Adopts a new schema for this collection and rebuilds whatever the change invalidated.
   *
   * Records on disk are never rewritten: the TLV encoding is tag-based, so a record written
   * under the old schema still decodes correctly under the new one as long as no field number
   * changed meaning. That check belongs to schema-migration.js and has already happened by the
   * time this runs -- this method assumes the change is applicable and only does the work.
   *
   * Index state is a different matter. Index tables are keyed by field NAME and their entries
   * were derived from the old schema's flags, so any change to indexing (a new indexed field,
   * a rename, a different rangeBucket width, a field gaining or losing diskBacked) leaves
   * entries that no longer correspond to the schema. Those get discarded and rebuilt from the
   * live records, which costs one decrypt pass over the collection and is always correct.
   */
  async applySchema(newSchema, { rebuildIndexes = true } = {}) {
    const previousByName = new Map(this.schema.map((f) => [f.name, f]));
    this.schema = newSchema;

    // Derived keys are cached per field name; a rename or a re-typed index must not keep
    // using a key derived for the old configuration.
    this._blindKeys.clear();
    this._rangeKeys.clear();

    const wanted = new Set(newSchema.filter((f) => f.diskBacked).map((f) => f.name));

    // Fields that stopped being disk-backed (or vanished) leave a segment file behind that no
    // longer matches any schema field. Closing and deleting it is what keeps a reopen from
    // loading a stale index for a field that no longer exists.
    for (const [name, store] of [...this.diskStores]) {
      if (wanted.has(name)) continue;
      await store.close().catch(() => {});
      this.diskStores.delete(name);
      await fsp.unlink(path.join(this.dir, `secidx-${name}.sidx`)).catch(() => {});
    }

    for (const name of wanted) {
      if (this.diskStores.has(name)) continue;
      const store = new SecondaryIndexStore(path.join(this.dir, `secidx-${name}.sidx`), { flushThreshold: this.diskFlushThreshold });
      await store.open();
      this.diskStores.set(name, store);
    }

    if (!rebuildIndexes) return { rebuilt: false, records: 0 };

    // Every disk-backed store is emptied before the rebuild, not merged into: leaving old
    // entries in place would keep serving lookups for values that are no longer indexed the
    // same way, which is the subtlest possible form of a stale index.
    for (const [name, store] of this.diskStores) {
      await store.close().catch(() => {});
      await fsp.unlink(path.join(this.dir, `secidx-${name}.sidx`)).catch(() => {});
      const fresh = new SecondaryIndexStore(path.join(this.dir, `secidx-${name}.sidx`), { flushThreshold: this.diskFlushThreshold });
      await fresh.open();
      this.diskStores.set(name, fresh);
    }

    await this._rebuildSecondaryIndexes();
    for (const store of this.diskStores.values()) await store.flush();
    await this._writeSnapshot();

    return { rebuilt: true, records: this.liveCount(), previousFields: previousByName.size };
  }

  // ---- index snapshot persistence (primary index + secondary/blind index tables) --------

  _parseSnapshot(buf) {
    if (buf.length < 4 || !buf.subarray(0, 4).equals(SNAPSHOT_MAGIC)) throw new Error('bad snapshot magic');
    let off = 4;
    const version = buf.readUInt8(off); off += 1;
    if (version !== SNAPSHOT_VERSION) throw new Error('unsupported snapshot version');
    const lastSegmentId = buf.readUInt32BE(off); off += 4;
    const lastOffset = buf.readUInt32BE(off); off += 4;
    const entryCount = buf.readUInt32BE(off); off += 4;
    const index = new Map();
    for (let i = 0; i < entryCount; i++) {
      const idStr = bufToId(buf.subarray(off, off + 8)); off += 8;
      const segmentId = buf.readUInt32BE(off); off += 4;
      const offset = buf.readUInt32BE(off); off += 4;
      const length = buf.readUInt32BE(off); off += 4;
      const recVersion = buf.readUInt32BE(off); off += 4;
      const flags = buf.readUInt8(off); off += 1;
      const deleted = buf.readUInt8(off) === 1; off += 1;
      index.set(idStr, { segmentId, offset, length, version: recVersion, flags, deleted });
    }

    const secondary = new Map();
    const secondaryFieldCount = buf.readUInt16BE(off); off += 2;
    for (let f = 0; f < secondaryFieldCount; f++) {
      const nameLen = buf.readUInt8(off); off += 1;
      const fieldName = buf.subarray(off, off + nameLen).toString('utf8'); off += nameLen;
      const valueCount = buf.readUInt32BE(off); off += 4;
      const m = new Map();
      for (let v = 0; v < valueCount; v++) {
        const decoded = decodeIndexValue(buf, off); off = decoded.next;
        const idCount = buf.readUInt32BE(off); off += 4;
        const ids = new Set();
        for (let k = 0; k < idCount; k++) { ids.add(bufToId(buf.subarray(off, off + 8))); off += 8; }
        m.set(decoded.value, ids);
      }
      secondary.set(fieldName, m);
    }

    const blind = new Map();
    const blindFieldCount = buf.readUInt16BE(off); off += 2;
    for (let f = 0; f < blindFieldCount; f++) {
      const nameLen = buf.readUInt8(off); off += 1;
      const fieldName = buf.subarray(off, off + nameLen).toString('utf8'); off += nameLen;
      const entryCount2 = buf.readUInt32BE(off); off += 4;
      const m = new Map();
      for (let e = 0; e < entryCount2; e++) {
        const hashLen = buf.readUInt8(off); off += 1;
        const hashHex = buf.subarray(off, off + hashLen).toString('hex'); off += hashLen;
        const idCount = buf.readUInt32BE(off); off += 4;
        const ids = new Set();
        for (let k = 0; k < idCount; k++) { ids.add(bufToId(buf.subarray(off, off + 8))); off += 8; }
        m.set(hashHex, ids);
      }
      blind.set(fieldName, m);
    }

    const rangeBuckets = new Map();
    const rangeFieldCount = buf.readUInt16BE(off); off += 2;
    for (let f = 0; f < rangeFieldCount; f++) {
      const nameLen = buf.readUInt8(off); off += 1;
      const fieldName = buf.subarray(off, off + nameLen).toString('utf8'); off += nameLen;
      const entryCount3 = buf.readUInt32BE(off); off += 4;
      const m = new Map();
      for (let e = 0; e < entryCount3; e++) {
        const hashLen = buf.readUInt8(off); off += 1;
        const hashHex = buf.subarray(off, off + hashLen).toString('hex'); off += hashLen;
        const idCount = buf.readUInt32BE(off); off += 4;
        const ids = new Set();
        for (let k = 0; k < idCount; k++) { ids.add(bufToId(buf.subarray(off, off + 8))); off += 8; }
        m.set(hashHex, ids);
      }
      rangeBuckets.set(fieldName, m);
    }

    return { lastSegmentId, lastOffset, index, secondary, blind, rangeBuckets };
  }

  async _writeSnapshot() {
    const entries = [...this.index.entries()];
    const header = Buffer.alloc(4 + 1 + 4 + 4 + 4);
    let off = 0;
    SNAPSHOT_MAGIC.copy(header, off); off += 4;
    header.writeUInt8(SNAPSHOT_VERSION, off); off += 1;
    header.writeUInt32BE(this.activeSegmentId, off); off += 4;
    header.writeUInt32BE(this.activeSegmentOffset, off); off += 4;
    header.writeUInt32BE(entries.length, off); off += 4;

    const body = Buffer.alloc(entries.length * (8 + 4 + 4 + 4 + 4 + 1 + 1));
    let bo = 0;
    for (const [idStr, loc] of entries) {
      idToBuf(idStr).copy(body, bo); bo += 8;
      body.writeUInt32BE(loc.segmentId, bo); bo += 4;
      body.writeUInt32BE(loc.offset, bo); bo += 4;
      body.writeUInt32BE(loc.length, bo); bo += 4;
      body.writeUInt32BE(loc.version, bo); bo += 4;
      body.writeUInt8(loc.flags, bo); bo += 1;
      body.writeUInt8(loc.deleted ? 1 : 0, bo); bo += 1;
    }

    const secondaryParts = [];
    const secCountBuf = Buffer.alloc(2); secCountBuf.writeUInt16BE(this.secondary.size, 0);
    secondaryParts.push(secCountBuf);
    for (const [fieldName, valueMap] of this.secondary) {
      const nameBuf = Buffer.from(fieldName, 'utf8');
      const valCountBuf = Buffer.alloc(4); valCountBuf.writeUInt32BE(valueMap.size, 0);
      secondaryParts.push(Buffer.from([nameBuf.length]), nameBuf, valCountBuf);
      for (const [value, idSet] of valueMap) {
        const idCountBuf = Buffer.alloc(4); idCountBuf.writeUInt32BE(idSet.size, 0);
        const idsBuf = Buffer.concat([...idSet].map(idToBuf));
        secondaryParts.push(encodeIndexValue(value), idCountBuf, idsBuf);
      }
    }

    const blindParts = [];
    const blindCountBuf = Buffer.alloc(2); blindCountBuf.writeUInt16BE(this.blind.size, 0);
    blindParts.push(blindCountBuf);
    for (const [fieldName, hashMap] of this.blind) {
      const nameBuf = Buffer.from(fieldName, 'utf8');
      const entryCountBuf = Buffer.alloc(4); entryCountBuf.writeUInt32BE(hashMap.size, 0);
      blindParts.push(Buffer.from([nameBuf.length]), nameBuf, entryCountBuf);
      for (const [hashHex, idSet] of hashMap) {
        const hashBuf = Buffer.from(hashHex, 'hex');
        const idCountBuf = Buffer.alloc(4); idCountBuf.writeUInt32BE(idSet.size, 0);
        const idsBuf = Buffer.concat([...idSet].map(idToBuf));
        blindParts.push(Buffer.from([hashBuf.length]), hashBuf, idCountBuf, idsBuf);
      }
    }

    const rangeParts = [];
    const rangeCountBuf = Buffer.alloc(2); rangeCountBuf.writeUInt16BE(this.rangeBuckets.size, 0);
    rangeParts.push(rangeCountBuf);
    for (const [fieldName, hashMap] of this.rangeBuckets) {
      const nameBuf = Buffer.from(fieldName, 'utf8');
      const entryCountBuf = Buffer.alloc(4); entryCountBuf.writeUInt32BE(hashMap.size, 0);
      rangeParts.push(Buffer.from([nameBuf.length]), nameBuf, entryCountBuf);
      for (const [hashHex, idSet] of hashMap) {
        const hashBuf = Buffer.from(hashHex, 'hex');
        const idCountBuf = Buffer.alloc(4); idCountBuf.writeUInt32BE(idSet.size, 0);
        const idsBuf = Buffer.concat([...idSet].map(idToBuf));
        rangeParts.push(Buffer.from([hashBuf.length]), hashBuf, idCountBuf, idsBuf);
      }
    }

    const tmpPath = path.join(this.dir, 'index.snapshot.tmp');
    await fsp.writeFile(tmpPath, Buffer.concat([header, body, ...secondaryParts, ...blindParts, ...rangeParts]));
    await fsp.rename(tmpPath, path.join(this.dir, 'index.snapshot')); // atomic on same filesystem
  }

  // ---- secondary/blind index bookkeeping ---------------------------------------------------

  async _indexInsertOnly(idStr, obj) {
    for (const f of this.schema) {
      if (f.blindIndex) {
        const val = obj[f.name];
        if (val === undefined) continue;
        const hex = blindIndexValue(this._blindKeyFor(f.name), val).toString('hex');
        await this._diskOrMapAdd(f, this.blind, hex, idStr);
      } else if (f.index) {
        const val = obj[f.name];
        if (val === undefined) continue;
        await this._diskOrMapAdd(f, this.secondary, val, idStr);
      }
      if (f.rangeBucket) {
        const val = obj[f.name];
        if (val === undefined) continue;
        const bucket = this._bucketOf(f, val);
        const hex = blindIndexValue(this._rangeKeyFor(f.name), String(bucket)).toString('hex');
        await this._diskOrMapAdd(f, this.rangeBuckets, hex, idStr);
      }
    }
  }

  // Dispatches to the field's SecondaryIndexStore (real disk-backed, bounded memory) if
  // diskBacked:true, otherwise to the plain in-RAM Map (persisted via index.snapshot
  // instead) -- key computation is identical either way, only the backing store differs.
  async _diskOrMapAdd(field, mapFallback, key, idStr) {
    if (field.diskBacked) {
      const store = this.diskStores.get(field.name);
      store.add(key, idStr);
      if (store.needsFlush()) await store.flush();
      return;
    }
    if (!mapFallback.has(field.name)) mapFallback.set(field.name, new Map());
    const m = mapFallback.get(field.name);
    if (!m.has(key)) m.set(key, new Set());
    m.get(key).add(idStr);
  }

  async _diskOrMapRemove(field, mapFallback, key, idStr) {
    if (field.diskBacked) {
      const store = this.diskStores.get(field.name);
      store.remove(key, idStr);
      if (store.needsFlush()) await store.flush();
      return;
    }
    const m = mapFallback.get(field.name);
    if (m && m.has(key)) { m.get(key).delete(idStr); if (m.get(key).size === 0) m.delete(key); }
  }

  async _indexRemove(idStr, obj) {
    if (!obj) return;
    for (const f of this.schema) {
      if (f.blindIndex) {
        const val = obj[f.name];
        if (val === undefined) continue;
        const hex = blindIndexValue(this._blindKeyFor(f.name), val).toString('hex');
        await this._diskOrMapRemove(f, this.blind, hex, idStr);
      } else if (f.index) {
        const val = obj[f.name];
        if (val === undefined) continue;
        await this._diskOrMapRemove(f, this.secondary, val, idStr);
      }
      if (f.rangeBucket) {
        const val = obj[f.name];
        if (val === undefined) continue;
        const bucket = this._bucketOf(f, val);
        const hex = blindIndexValue(this._rangeKeyFor(f.name), String(bucket)).toString('hex');
        await this._diskOrMapRemove(f, this.rangeBuckets, hex, idStr);
      }
    }
  }

  async _reconcileIndexes(idStr, oldObj, newObj) {
    await this._indexRemove(idStr, oldObj);
    await this._indexInsertOnly(idStr, newObj);
  }

  // ---- public CRUD ---------------------------------------------------------------------

  async put(obj) {
    return this._writeQueue.run(() => this._putUnqueued(obj));
  }

  // The body of put(), with no queueing of its own, so a caller that has already entered the
  // write queue (putUnique) can reuse it without deadlocking on the tail it is holding.
  async _putUnqueued(obj) {
    const idStr = String(obj._id);
    let oldDecoded = null;
    const existing = this.index.get(idStr);
    if (existing && !existing.deleted) oldDecoded = await this._readAt(idStr, existing);
    const newVersion = (existing ? existing.version : 0) + 1;

    const idBuf = idToBuf(idStr);
    const plainBuf = encodeRecord(this.schema, obj);
    const { payload, flags } = this._maybeCompress(plainBuf);
    const aad = buildAad(idBuf, OP_PUT, flags, newVersion);
    const enc = await this._encrypt(payload, aad);
    const location = await this._appendFrame(OP_PUT, flags, idBuf, newVersion, enc);

    this.index.set(idStr, { ...location, deleted: false });
    await this._reconcileIndexes(idStr, oldDecoded, obj);
    if (this.cache) this.cache.set(idStr, obj);
    if (this.onChange) this.onChange({ op: OP_PUT, id: idStr, version: newVersion, record: obj });
    return obj;
  }

  /**
   * put() that first proves no live record already holds `obj[field]` for each named field,
   * with the check and the append inside ONE queued task.
   *
   * The check-then-act version of this -- `if (await c.findOne(f, v)) throw; await c.insert(x)`
   * -- is what callers write naturally, and it does not hold: the two awaits are separate
   * queue entries, so two concurrent callers both observe "absent" and both insert. For a
   * uniqueness rule that exists to stop the SAME key being certified twice, losing that race
   * is the entire failure mode, and it is easiest to lose exactly when someone is trying.
   *
   * Every other mutation path also runs through `_writeQueue`, so nothing can land between
   * the lookup and the append.
   */
  async putUnique(obj, uniqueFields) {
    const fields = Array.isArray(uniqueFields) ? uniqueFields : [uniqueFields];
    return this._writeQueue.run(async () => {
      for (const fieldName of fields) {
        const value = obj[fieldName];
        if (value === undefined || value === null || value === '') {
          throw new UniqueConstraintError(fieldName, value,
            `fitdb: unique field '${fieldName}' must have a value`);
        }
        const ids = await this.lookupIds(fieldName, value);
        // A tombstoned id stays in the index, so "already used" has to mean "used by a record
        // that is still live" -- otherwise deleting a certificate record would permanently
        // burn its key with no way to observe why.
        for (const id of ids || []) {
          const loc = this.index.get(String(id));
          if (loc && !loc.deleted) {
            throw new UniqueConstraintError(fieldName, value,
              `fitdb: a record with ${fieldName}='${value}' already exists`);
          }
        }
      }
      return this._putUnqueued(obj);
    });
  }

  async get(id) {
    const idStr = String(id);
    if (this.cache && this.cache.has(idStr)) return this.cache.get(idStr);
    const loc = this.index.get(idStr);
    if (!loc || loc.deleted) return null;
    const obj = await this._readAt(idStr, loc);
    if (this.cache) this.cache.set(idStr, obj);
    return obj;
  }

  // Bypasses the cache and returns the authenticated version counter alongside the value.
  // Intended for rollback-sensitive callers (see lib/version-watermark.js and the direct-
  // access path), where "was this genuinely the newest frame the storage node has?" matters.
  async getWithVersion(id) {
    const idStr = String(id);
    const loc = this.index.get(idStr);
    if (!loc || loc.deleted) return null;
    const obj = await this._readAt(idStr, loc);
    return { value: obj, version: loc.version };
  }

  async update(id, patch) {
    const idStr = String(id);
    const current = await this.get(idStr);
    if (!current) throw new Error(`fitdb: record '${idStr}' not found`);
    const merged = { ...current, ...patch, _id: current._id };
    return this.put(merged);
  }

  async delete(id) {
    const idStr = String(id);
    return this._writeQueue.run(async () => {
      const existing = this.index.get(idStr);
      if (!existing || existing.deleted) return false;
      const oldDecoded = await this._readAt(idStr, existing);
      const newVersion = existing.version + 1;
      const idBuf = idToBuf(idStr);
      const aad = buildAad(idBuf, OP_DELETE, 0, newVersion);
      const enc = await this._encrypt(Buffer.alloc(0), aad);
      const location = await this._appendFrame(OP_DELETE, 0, idBuf, newVersion, enc);
      this.index.set(idStr, { ...location, deleted: true });
      await this._reconcileIndexes(idStr, oldDecoded, {});
      if (this.cache) this.cache.delete(idStr);
      if (this.onChange) this.onChange({ op: OP_DELETE, id: idStr, version: newVersion, record: null });
      return true;
    });
  }

  async lookupIds(fieldName, value) {
    const field = this.schema.find((f) => f.name === fieldName);
    if (!field) throw new Error(`fitdb: no such field '${fieldName}'`);
    if (field.blindIndex) {
      const hex = blindIndexValue(this._blindKeyFor(fieldName), value).toString('hex');
      if (field.diskBacked) return this.diskStores.get(fieldName).get(hex);
      return this.blind.get(fieldName)?.get(hex) || new Set();
    }
    if (field.index) {
      if (field.diskBacked) return this.diskStores.get(fieldName).get(value);
      return this.secondary.get(fieldName)?.get(value) || new Set();
    }
    throw new Error(`fitdb: field '${fieldName}' is not indexed (set index:true or blindIndex:true)`);
  }

  // Native ordered range query for a PLAIN (non-blind) indexed numeric field that is also
  // diskBacked:true -- unlike rangeBucket (which deliberately hides order via blind
  // hashing), a plain index preserves real value order in the sorted segment, so this can
  // binary-search+range-scan directly instead of iterating discrete buckets. Only meaningful
  // when confidentiality of the field's order is not a concern (the server DOES learn the
  // relative order of every indexed value here, by design).
  async lookupPlainRange(fieldName, min, max) {
    const field = this.schema.find((f) => f.name === fieldName);
    if (!field) throw new Error(`fitdb: no such field '${fieldName}'`);
    if (!field.index || field.blindIndex) throw new Error(`fitdb: lookupPlainRange requires a plain (non-blind) index:true field`);
    if (!field.diskBacked) throw new Error(`fitdb: lookupPlainRange requires diskBacked:true on '${fieldName}'`);
    const rangeMap = await this.diskStores.get(fieldName).range(min, max);
    const out = new Set();
    for (const ids of rangeMap.values()) for (const id of ids) out.add(id);
    return out;
  }

  /**
   * Gathers candidate ids for values in [min,max] on a `rangeBucket` field.
   *
   * Membership is NECESSARY BUT NOT SUFFICIENT and always has been: a bucket is coarser than
   * the range, so ids near either edge can fall outside it. Every caller is therefore already
   * required to apply an exact filter after decrypting (Collection.findRange does). That
   * contract is what makes the second strategy below legitimate -- returning a superset is a
   * performance decision, never a correctness one.
   *
   * TWO STRATEGIES, CHOSEN BY WHICH IS ACTUALLY CHEAPER:
   *
   *   probe  -- hash each bucket number in the range and look it up. Cost is proportional to
   *             the WIDTH OF THE RANGE and independent of how much data exists. Right for an
   *             ordinary bounded query ("certificates expiring in the next 30 days").
   *
   *   sweep  -- hand back every id the field has indexed, in any bucket, and let the caller's
   *             exact filter do the rest. Cost is proportional to HOW MUCH DATA EXISTS and
   *             independent of the range width. Right for the open-ended query that the probe
   *             strategy cannot survive: "everything due by now", where min is 0 and the range
   *             spans every bucket since the epoch.
   *
   * The old code only had `probe`, with no ceiling, which is the defect described at
   * MAX_PROBED_BUCKETS: findRange(field, 0, Date.now()) on a minute-width field meant ~30
   * million synchronous HMACs and a two-minute event-loop stall per call.
   */
  async lookupRangeCandidates(fieldName, min, max) {
    const field = this.schema.find((f) => f.name === fieldName);
    if (!field) throw new Error(`fitdb: no such field '${fieldName}'`);
    if (!field.rangeBucket) throw new Error(`fitdb: field '${fieldName}' has no rangeBucket configured`);

    const width = field.rangeBucket.width;
    const minBucket = Math.floor(Number(min) / width);
    const maxBucket = Math.floor(Number(max) / width);
    const out = new Set();
    // A NaN bound (undefined, null, a non-numeric string) used to produce NaN buckets, and
    // `for (let b = NaN; b <= NaN; b++)` silently yields nothing -- an empty result for what is
    // really a caller bug. An inverted range is likewise empty, but legitimately so.
    if (!Number.isFinite(minBucket) || !Number.isFinite(maxBucket)) {
      throw new Error(`fitdb: findRange on '${fieldName}' needs numeric bounds (got ${min} .. ${max})`);
    }
    if (maxBucket < minBucket) return out;

    const diskStore = field.diskBacked ? this.diskStores.get(fieldName) : null;
    const fieldMap = diskStore ? null : this.rangeBuckets.get(fieldName);
    if (!diskStore && !fieldMap) return out;

    const spanBuckets = maxBucket - minBucket + 1;

    if (spanBuckets > MAX_PROBED_BUCKETS) {
      // The range is wide enough that probing it costs more than looking at everything stored.
      // Reported at DEBUG rather than swallowed: a caller who did NOT mean "scan the field"
      // (say, a bucket width accidentally set to milliseconds) should be able to see that this
      // is what their query turned into.
      const done = this.log.timer('range sweep', { warnAboveMs: 250 });
      const all = diskStore ? await diskStore.entries() : fieldMap;
      for (const ids of all.values()) for (const id of ids) out.add(id);
      done({
        field: fieldName,
        spanBuckets,
        strategy: 'sweep',
        buckets: all.size,
        candidates: out.size,
        msg: 'range wider than the probe budget; swept the field\'s populated buckets instead',
      });
      return out;
    }

    const rangeKey = this._rangeKeyFor(fieldName);
    let probed = 0;
    for (let b = minBucket; b <= maxBucket; b++) {
      const hex = blindIndexValue(rangeKey, String(b)).toString('hex');
      const ids = diskStore ? await diskStore.get(hex) : fieldMap.get(hex);
      if (ids) for (const id of ids) out.add(id);
      // Long probes stay interruptible so concurrent readers keep being served.
      if (++probed % PROBE_YIELD_INTERVAL === 0) await new Promise((resolve) => setImmediate(resolve));
    }
    return out;
  }

  liveCount() {
    let n = 0;
    for (const loc of this.index.values()) if (!loc.deleted) n++;
    return n;
  }

  async *scan() {
    for (const [idStr, loc] of this.index) {
      if (loc.deleted) continue;
      yield await this.get(idStr);
    }
  }

  // Cursor-based pagination ordered by numeric id ascending. Snowflake ids are roughly
  // time-ordered, so "id > cursor" gives well-defined, stable-enough pagination even if
  // records are inserted/deleted between pages (new inserts get larger ids and naturally
  // land on later pages; they don't reshuffle pages already handed out). This sorts the
  // full remaining candidate set on every call -- correct and simple, O(n log n) per call
  // rather than O(page size) -- fine at personal-database scale; a collection that outgrows
  // this needs a real persisted sorted structure (see the disk-backed-index discussion in
  // the README), not a bigger version of this method.
  scanPage(afterIdStr, limit) {
    const afterId = afterIdStr !== null && afterIdStr !== undefined ? BigInt(afterIdStr) : -1n;
    const liveIds = [];
    for (const [idStr, loc] of this.index) {
      if (loc.deleted) continue;
      const idBig = BigInt(idStr);
      if (idBig > afterId) liveIds.push(idBig);
    }
    liveIds.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const page = liveIds.slice(0, limit);
    const hasMore = liveIds.length > page.length;
    return { ids: page.map(String), nextCursor: hasMore ? page[page.length - 1].toString() : null };
  }

  // ---- compaction -----------------------------------------------------------------------
  // Live frames are copied byte-for-byte (no decrypt/re-encrypt needed: AAD only binds
  // id+op+flags+version, all unchanged by relocation) into a single fresh segment; every
  // old segment file is then deleted. Snapshot is rewritten immediately afterwards.

  async compact() {
    return this._writeQueue.run(async () => {
      const liveEntries = [...this.index.entries()].filter(([, v]) => !v.deleted);
      const oldSegIds = new Set([...this.index.values()].map((v) => v.segmentId));

      if (this.activeWriteFd) { await this.activeWriteFd.close(); this.activeWriteFd = null; }

      const newSegId = this.activeSegmentId + 1;
      const newPath = path.join(this.dir, segFileName(newSegId));
      const newFd = await fsp.open(newPath, 'w');
      let writeOffset = 0;
      const newIndex = new Map();

      for (const [idStr, loc] of liveEntries) {
        const frameStart = loc.offset - HEADER_SIZE;
        const frameLen = HEADER_SIZE + loc.length;
        const src = await this._acquireReadFd(loc.segmentId);
        const frameBuf = Buffer.alloc(frameLen);
        try { await src.fd.read(frameBuf, 0, frameLen, frameStart); }
        finally { this._release(src); }
        await newFd.write(frameBuf);
        newIndex.set(idStr, { segmentId: newSegId, offset: writeOffset + HEADER_SIZE, length: loc.length, version: loc.version, flags: loc.flags, deleted: false });
        writeOffset += frameLen;
      }
      await newFd.close();

      for (const segId of oldSegIds) await this._closeAndDeleteSegment(segId);

      this.index = newIndex;
      this.activeSegmentId = newSegId;
      this.activeSegmentOffset = writeOffset;
      this.activeWriteFd = await fsp.open(newPath, 'a');

      await this._writeSnapshot();
      this.log.info({
        liveRecords: newIndex.size,
        segmentsReclaimed: oldSegIds.size,
        bytes: writeOffset,
        msg: 'compaction complete',
      });
      return { liveRecords: newIndex.size, segmentsReclaimed: oldSegIds.size };
    });
  }
}

module.exports = {
  CollectionStorage, UniqueConstraintError,
  idToBuf, bufToId, HEADER_SIZE, OP_PUT, OP_DELETE,
};
