'use strict';

const crypto = require('node:crypto');

// --- Key hierarchy -----------------------------------------------------------------------
//
// clientSecret (32 random bytes, generated once at CreateDatabase time, returned to the
//               caller exactly once, NEVER persisted server-side)
//   -> HKDF-SHA256(info="fitdb-manifest-v1") -> manifestKey  (encrypts the manifest: schema/ACL)
//   -> HKDF-SHA256(info="fitdb-kek-v1")      -> KEK          (unwraps the DDK)
//
// DDK (Database Data Key, 32 random bytes, generated once at CreateDatabase time)
//   -> wrapped with KEK (AES-256-GCM) and stored as `wrappedDDK` inside the manifest.
//   -> used directly (AES-256-GCM) to encrypt/decrypt every record payload.
//   -> HKDF-SHA256(info="fitdb-blind-v1:<field>") -> per-field blind-index key (HMAC only,
//      never used for encryption) so equality lookups are possible without ever exposing
//      plaintext as a lookup key.
//
// The server persists ONLY `wrappedDDK`. Without clientSecret nobody can derive KEK, and
// without KEK nobody can unwrap DDK, and without DDK nobody can decrypt a single record or
// even read the manifest (schema/ACL) — this holds true even for a process with full
// filesystem access to the data directory. See README for the honest caveat: once a
// legitimate session supplies clientSecret, DDK necessarily lives in RAM for that session's
// duration (bounded by a TTL) so the engine can do useful work (encode/decode, indexing).
// That is an unavoidable trade-off for a queryable store, not a gap in the at-rest design.

const KEK_INFO = Buffer.from('fitdb-kek-v1');
const MANIFEST_INFO = Buffer.from('fitdb-manifest-v1');
const BLIND_INFO_PREFIX = 'fitdb-blind-v1:';

function hkdf(ikm, salt, info, len = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));
}

// Kept for the simple, non-pluggable case. With a pluggable KeyProvider (see
// lib/key-provider.js) the manager derives the manifest key by chaining off the already-
// derived KEK instead (manifestKey = HKDF(kek, dbId, 'fitdb-manifest-v1')), since a
// KeyProvider (e.g. the MLS adapter) only promises to produce a KEK, not raw root secret
// material. Whoever can compute KEK can compute manifestKey either way; the set of people
// who can open the manifest is identical to the set who can unwrap the DDK.
function deriveKek(clientSecret, dbIdBuf) {
  return hkdf(clientSecret, dbIdBuf, KEK_INFO, 32);
}

function deriveManifestKeyFromKek(kek, dbIdBuf) {
  return hkdf(kek, dbIdBuf, MANIFEST_INFO, 32);
}

function deriveBlindIndexKey(ddk, fieldName) {
  return hkdf(ddk, Buffer.alloc(0), Buffer.from(BLIND_INFO_PREFIX + fieldName), 32);
}

function randomKey(len = 32) { return crypto.randomBytes(len); }

// AES-256-GCM, framed as [iv(12)][tag(16)][ciphertext]. `aad` (if given) is authenticated
// but not encrypted — used to bind ciphertext to context (record id + op + flags) so a
// swapped/relabeled frame fails authentication instead of silently decrypting as something
// else.
function aesGcmEncrypt(key, plaintext, aad = null) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

function aesGcmDecrypt(key, framed, aad = null) {
  const iv = framed.subarray(0, 12);
  const tag = framed.subarray(12, 28);
  const ct = framed.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function wrapKey(kek, rawKey) { return aesGcmEncrypt(kek, rawKey); }
function unwrapKey(kek, wrapped) { return aesGcmDecrypt(kek, wrapped); }

function blindIndexValue(blindKey, value) {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return crypto.createHmac('sha256', blindKey).update(buf).digest().subarray(0, 16);
}

module.exports = {
  hkdf, deriveKek, deriveManifestKeyFromKek, deriveBlindIndexKey, randomKey,
  aesGcmEncrypt, aesGcmDecrypt, wrapKey, unwrapKey, blindIndexValue,
};
