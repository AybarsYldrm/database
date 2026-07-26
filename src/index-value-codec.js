'use strict';

// Generic tagged encoding for index keys/values (string/number/bigint/bool/raw-bytes),
// shared between the in-memory snapshot format (storage-engine.js) and the on-disk sorted
// index segment format (sorted-index-segment.js) so both speak the same key encoding.
const VTAG_STRING = 0, VTAG_NUMBER = 1, VTAG_BIGINT = 2, VTAG_BOOL = 3, VTAG_BYTES = 4;

function encodeIndexValue(value) {
  if (typeof value === 'string') {
    const b = Buffer.from(value, 'utf8');
    const len = Buffer.alloc(2); len.writeUInt16BE(b.length, 0);
    return Buffer.concat([Buffer.from([VTAG_STRING]), len, b]);
  }
  if (typeof value === 'bigint') {
    const b = Buffer.from(value.toString(), 'ascii');
    const len = Buffer.alloc(2); len.writeUInt16BE(b.length, 0);
    return Buffer.concat([Buffer.from([VTAG_BIGINT]), len, b]);
  }
  if (typeof value === 'number') {
    const b = Buffer.alloc(8); b.writeDoubleLE(value, 0);
    return Buffer.concat([Buffer.from([VTAG_NUMBER]), b]);
  }
  if (typeof value === 'boolean') {
    return Buffer.from([VTAG_BOOL, value ? 1 : 0]);
  }
  if (Buffer.isBuffer(value)) {
    const len = Buffer.alloc(2); len.writeUInt16BE(value.length, 0);
    return Buffer.concat([Buffer.from([VTAG_BYTES]), len, value]);
  }
  throw new Error(`fitdb: cannot encode index value of type ${typeof value}`);
}

function decodeIndexValue(buf, offset) {
  const tag = buf.readUInt8(offset); offset += 1;
  if (tag === VTAG_STRING || tag === VTAG_BIGINT || tag === VTAG_BYTES) {
    const len = buf.readUInt16BE(offset); offset += 2;
    const slice = buf.subarray(offset, offset + len);
    offset += len;
    if (tag === VTAG_STRING) return { value: slice.toString('utf8'), next: offset };
    if (tag === VTAG_BIGINT) return { value: BigInt(slice.toString('ascii')), next: offset };
    return { value: Buffer.from(slice), next: offset };
  }
  if (tag === VTAG_NUMBER) {
    const v = buf.readDoubleLE(offset); offset += 8;
    return { value: v, next: offset };
  }
  if (tag === VTAG_BOOL) {
    const v = buf.readUInt8(offset) === 1; offset += 1;
    return { value: v, next: offset };
  }
  throw new Error(`fitdb: unknown index value tag ${tag} while decoding`);
}

// Total order over same-typed keys. Blind-hash "keys" are hex strings and get plain
// lexicographic ordering -- a valid total order for binary search, and deliberately
// uncorrelated with the original value's order (no order leakage from a blind index).
function compareIndexValues(a, b) {
  if (typeof a === 'string' && typeof b === 'string') return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === 'bigint' && typeof b === 'bigint') return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === 'number' && typeof b === 'number') return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === 'boolean' && typeof b === 'boolean') return a === b ? 0 : (a ? 1 : -1);
  if (Buffer.isBuffer(a) && Buffer.isBuffer(b)) return Buffer.compare(a, b);
  throw new Error('fitdb: cannot compare index values of mismatched or unsupported types');
}

module.exports = { encodeIndexValue, decodeIndexValue, compareIndexValues, VTAG_STRING, VTAG_NUMBER, VTAG_BIGINT, VTAG_BOOL, VTAG_BYTES };
