'use strict';

// Compact protobuf-style TLV codec used to encode every record before encryption. Beats
// JSON on size (no field names/braces/quotes on the wire, varints for small integers) and
// on parse cost (no string tokenizing). Field numbers double as forward-compatibility:
// unknown field numbers are skipped by wire type rather than erroring, so schemas can gain
// fields later without invalidating already-stored records.
//
// Wire types: 0 = VARINT (bool/int32/int64/uint32/uint64), 1 = FIXED64 (double),
//             2 = LEN (string/bytes), 5 = FIXED32 (float).
//
// int64/uint64 decode to BigInt (JS numbers lose precision above 2^53, and Snowflake ids
// routinely exceed that); int32/uint32 decode to Number.

const WIRE_VARINT = 0;
const WIRE_FIXED64 = 1;
const WIRE_LEN = 2;
const WIRE_FIXED32 = 5;

function wireTypeFor(type) {
  switch (type) {
    case 'bool': case 'int32': case 'int64': case 'uint32': case 'uint64': return WIRE_VARINT;
    case 'double': return WIRE_FIXED64;
    case 'string': case 'bytes': return WIRE_LEN;
    case 'float': return WIRE_FIXED32;
    default: throw new Error(`fitdb codec: unknown field type '${type}'`);
  }
}

function zigzagEncode(n) { return n >= 0n ? (n << 1n) : ((-n << 1n) - 1n); }
function zigzagDecode(n) { return (n & 1n) === 0n ? (n >> 1n) : -((n + 1n) >> 1n); }

function writeVarint(value) {
  let n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n) throw new Error('fitdb codec: writeVarint requires a non-negative value (use zigzag for signed fields)');
  const bytes = [];
  do {
    let byte = Number(n & 0x7fn);
    n >>= 7n;
    if (n > 0n) byte |= 0x80;
    bytes.push(byte);
  } while (n > 0n);
  return Buffer.from(bytes);
}

function readVarint(buf, offset) {
  let result = 0n;
  let shift = 0n;
  let pos = offset;
  for (;;) {
    if (pos >= buf.length) throw new Error('fitdb codec: truncated varint');
    const byte = buf[pos++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return { value: result, next: pos };
}

function encodeField(field, val) {
  const wireType = wireTypeFor(field.type);
  const tag = writeVarint((field.no << 3) | wireType);
  switch (field.type) {
    case 'bool': return Buffer.concat([tag, writeVarint(val ? 1n : 0n)]);
    case 'int32': case 'int64': return Buffer.concat([tag, writeVarint(zigzagEncode(BigInt(val)))]);
    case 'uint32': case 'uint64': return Buffer.concat([tag, writeVarint(BigInt(val))]);
    case 'float': { const b = Buffer.alloc(4); b.writeFloatLE(val); return Buffer.concat([tag, b]); }
    case 'double': { const b = Buffer.alloc(8); b.writeDoubleLE(val); return Buffer.concat([tag, b]); }
    case 'string': { const sb = Buffer.from(String(val), 'utf8'); return Buffer.concat([tag, writeVarint(sb.length), sb]); }
    case 'bytes': { const bb = Buffer.isBuffer(val) ? val : Buffer.from(val); return Buffer.concat([tag, writeVarint(bb.length), bb]); }
    default: throw new Error(`fitdb codec: unknown field type '${field.type}'`);
  }
}

function encodeRecord(schema, obj) {
  const parts = [];
  for (const field of schema) {
    const val = obj[field.name];
    if (val === undefined || val === null) continue; // absent fields are simply omitted (protobuf-style optionality)
    parts.push(encodeField(field, val));
  }
  return Buffer.concat(parts);
}

function decodeVarintValue(field, value) {
  switch (field.type) {
    case 'bool': return value !== 0n;
    case 'int32': return Number(zigzagDecode(value));
    case 'int64': return zigzagDecode(value);
    case 'uint32': return Number(value);
    case 'uint64': return value;
    default: return value;
  }
}

function decodeRecord(schema, buf) {
  const byNo = new Map(schema.map((f) => [f.no, f]));
  const obj = {};
  let offset = 0;
  while (offset < buf.length) {
    const { value: tagVal, next: afterTag } = readVarint(buf, offset);
    offset = afterTag;
    const tag = Number(tagVal);
    const fieldNo = tag >>> 3;
    const wireType = tag & 0x7;
    const field = byNo.get(fieldNo);
    switch (wireType) {
      case WIRE_VARINT: {
        const { value, next } = readVarint(buf, offset);
        offset = next;
        if (field) obj[field.name] = decodeVarintValue(field, value);
        break;
      }
      case WIRE_FIXED64: {
        if (offset + 8 > buf.length) throw new Error('fitdb codec: truncated fixed64');
        const v = buf.readDoubleLE(offset);
        offset += 8;
        if (field) obj[field.name] = v;
        break;
      }
      case WIRE_FIXED32: {
        if (offset + 4 > buf.length) throw new Error('fitdb codec: truncated fixed32');
        const v = buf.readFloatLE(offset);
        offset += 4;
        if (field) obj[field.name] = v;
        break;
      }
      case WIRE_LEN: {
        const { value: lenBig, next } = readVarint(buf, offset);
        offset = next;
        const len = Number(lenBig);
        if (offset + len > buf.length) throw new Error('fitdb codec: truncated length-delimited field');
        const slice = buf.subarray(offset, offset + len);
        offset += len;
        if (field) obj[field.name] = field.type === 'bytes' ? Buffer.from(slice) : slice.toString('utf8');
        break;
      }
      default:
        throw new Error(`fitdb codec: unknown wire type ${wireType} while decoding`);
    }
  }
  return obj;
}

// Compatibility wrapper matching the existing `encodeMessage(schemas, typeName, obj)` /
// `decodeMessage(schemas, typeName, buf)` shape already used by ./protobuf in the gRPC
// layer (client.js / grpc-server.js / server.js), so this codec can be dropped in as a
// drop-in replacement for that module if desired, or used standalone for storage as below.
function encodeMessage(schemas, typeName, obj) { return encodeRecord(schemas[typeName], obj); }
function decodeMessage(schemas, typeName, buf) { return decodeRecord(schemas[typeName], buf); }

module.exports = {
  encodeRecord, decodeRecord, encodeMessage, decodeMessage,
  writeVarint, readVarint, zigzagEncode, zigzagDecode, wireTypeFor,
};
