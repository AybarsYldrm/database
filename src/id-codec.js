'use strict';

// Snowflake ids fit comfortably in 63 bits; represented on disk as fixed 8-byte big-endian,
// and everywhere else as their decimal string form (the canonical in-memory id
// representation used throughout fitdb, to avoid BigInt/Number/String type-confusion bugs).
function idToBuf(idStr) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(idStr));
  return buf;
}
function bufToId(buf) { return buf.readBigUInt64BE(0).toString(); }

module.exports = { idToBuf, bufToId };
