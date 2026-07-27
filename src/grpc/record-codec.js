'use strict';

const { encodeRecord, decodeRecord } = require('../binary-codec');

// Records cross the gRPC boundary in one of two forms, and the choice is per call:
//
//   payloadJson - a JSON string. Schema-agnostic, readable in a log, and what the existing
//                 clients in this stack already speak.
//   payloadBin  - the collection's own TLV encoding (binary-codec.js). Roughly 2.5x smaller
//                 than the equivalent JSON, no number-precision games, and no re-encode step
//                 on the way to storage.
//
// JSON is the default because it works before a client knows the schema; binary is what a
// client that has called DescribeCollection should use for anything hot.
//
// The reason this file exists rather than a bare JSON.parse: JSON has no int64 and no bytes.
// A Snowflake id is a BigInt and every one of them is above 2^53, so `JSON.parse` silently
// rounds it -- inserting a record and reading it back would give a *different id*. Every
// value therefore gets coerced back to the type its schema field declares, rather than
// whatever JSON happened to produce.

const BIGINT_TYPES = new Set(['int64', 'uint64']);
const NUMBER_TYPES = new Set(['int32', 'uint32', 'float', 'double']);

/** JSON.stringify replacer: BigInt has no JSON representation and throws without this. */
function bigintReplacer(_key, value) {
  return typeof value === 'bigint' ? value.toString() : value;
}

function toJson(value) { return JSON.stringify(value, bigintReplacer); }

/**
 * Coerces a decoded JSON object into the types the collection's schema declares.
 *
 * Unknown fields are dropped rather than passed through: the TLV encoder has no field number
 * for them, so keeping them would mean silently discarding data at the next layer instead of
 * here, where the caller can be told.
 */
function coerceRecord(schema, input, { strict = false } = {}) {
  const out = {};
  const byName = new Map(schema.map((f) => [f.name, f]));

  for (const [key, value] of Object.entries(input || {})) {
    const field = byName.get(key);
    if (!field) {
      if (strict) throw new Error(`fitdb: '${key}' is not a field of this collection`);
      continue;
    }
    if (value === null || value === undefined) continue;
    out[key] = coerceValue(field, value, key);
  }
  return out;
}

function coerceValue(field, value, key) {
  if (BIGINT_TYPES.has(field.type)) {
    if (typeof value === 'bigint') return value;
    // A JSON number above 2^53 has already lost precision by the time it gets here, so this
    // rejects it rather than storing a corrupted id. Clients send large integers as strings.
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) {
        throw new Error(`fitdb: '${key}' is an ${field.type} but arrived as an unsafe JSON number (${value}); send it as a string`);
      }
      return BigInt(value);
    }
    try { return BigInt(String(value)); }
    catch (_) { throw new Error(`fitdb: '${key}' is an ${field.type} but '${value}' is not an integer`); }
  }

  if (NUMBER_TYPES.has(field.type)) {
    const n = Number(value);
    if (!Number.isFinite(n)) throw new Error(`fitdb: '${key}' is a ${field.type} but '${value}' is not a number`);
    return n;
  }

  if (field.type === 'bool') {
    if (typeof value === 'boolean') return value;
    return value === 'true' || value === 1 || value === '1';
  }

  if (field.type === 'bytes') {
    if (Buffer.isBuffer(value)) return value;
    // JSON cannot carry bytes; base64 is the convention, and Buffer.from tolerates both
    // standard and url-safe alphabets.
    if (typeof value === 'string') return Buffer.from(value, 'base64');
    if (value && value.type === 'Buffer' && Array.isArray(value.data)) return Buffer.from(value.data);
    throw new Error(`fitdb: '${key}' is bytes but arrived as ${typeof value}`);
  }

  return String(value);
}

/**
 * The inverse: a stored record shaped for JSON. `bytes` becomes base64 and BigInt becomes a
 * decimal string, so a client can round trip a record through coerceRecord() unchanged.
 */
function recordToJsonObject(schema, record) {
  if (!record) return null;
  const byName = new Map(schema.map((f) => [f.name, f]));
  const out = {};
  for (const [key, value] of Object.entries(record)) {
    const field = byName.get(key);
    if (field?.type === 'bytes' && Buffer.isBuffer(value)) out[key] = value.toString('base64');
    else if (typeof value === 'bigint') out[key] = value.toString();
    else out[key] = value;
  }
  return out;
}

function recordsToJson(schema, records) {
  return JSON.stringify(records.map((r) => recordToJsonObject(schema, r)));
}

/**
 * Reads whichever payload form the request carried. Having one place decide means a method
 * cannot accidentally support only one of them.
 */
function readPayload(schema, { payloadJson, payloadBin }, { strict = false } = {}) {
  if (payloadBin && payloadBin.length > 0) return decodeRecord(schema, payloadBin);
  if (payloadJson) {
    let parsed;
    try { parsed = JSON.parse(payloadJson); }
    catch (err) { throw new Error(`fitdb: payloadJson is not valid JSON (${err.message})`); }
    return coerceRecord(schema, parsed, { strict });
  }
  return {};
}

function writePayload(schema, record, { binary = false }) {
  if (!record) return { payloadJson: '', payloadBin: null, found: false };
  return binary
    ? { payloadBin: encodeRecord(schema, record), payloadJson: '', found: true }
    : { payloadJson: toJson(recordToJsonObject(schema, record)), payloadBin: null, found: true };
}

module.exports = {
  bigintReplacer, toJson, coerceRecord, coerceValue,
  recordToJsonObject, recordsToJson, readPayload, writePayload,
};
