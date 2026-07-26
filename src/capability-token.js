'use strict';

const crypto = require('node:crypto');

// Same HMAC-JWT-lite shape already used for the main auth token in server.js
// (base64url(header).base64url(payload).base64url(sig)), extended with exactly the three
// things a *capability* needs that an *identity* token doesn't:
//   - kid   : which signing key was used, so keys can rotate without invalidating every
//             outstanding token (the verifier just needs to still recognize the kid).
//   - jti   : a Snowflake-generated unique token id, enabling single-use enforcement.
//   - scope : a DB_PERMISSIONS bitmask that must be a SUBSET of the issuing user's own ACL
//             mask for that database — a capability can only ever narrow authority, never
//             grant more than the issuer legitimately has.
// TTLs are expected to be short (seconds, not the ~1h of a normal session token) since the
// whole point is a narrow, disposable grant for one direct operation or a short burst.

function base64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function fromBase64url(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function hmacSign(secret, data) {
  return base64url(crypto.createHmac('sha256', secret).update(data).digest());
}
function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

class CapabilityKeyRing {
  constructor({ maxRetainedKeys = 3 } = {}) {
    this.keys = new Map(); // kid -> secret Buffer, insertion-ordered
    this.currentKid = null;
    this.maxRetainedKeys = maxRetainedKeys;
    this.rotate();
  }
  rotate() {
    const kid = crypto.randomBytes(8).toString('hex');
    this.keys.set(kid, crypto.randomBytes(32));
    this.currentKid = kid;
    while (this.keys.size > this.maxRetainedKeys) this.keys.delete(this.keys.keys().next().value);
    return kid;
  }
  currentSecret() { return { kid: this.currentKid, secret: this.keys.get(this.currentKid) }; }
  secretFor(kid) { return this.keys.get(kid) || null; }
}

class CapabilityTokenService {
  constructor(keyRing, snowflake) {
    this.keyRing = keyRing;
    this.snowflake = snowflake;
    this.usedJti = new Map(); // jti -> expiresAt (pruned lazily so it can't grow unbounded)
  }

  issue({ sub, dbId, collection = '*', scope, ttlMs = 60000, singleUse = true, rowFilter = null }) {
    if (!scope) throw new Error('fitdb: capability token requires a non-zero scope bitmask');
    if (rowFilter && collection === '*') throw new Error('fitdb: rowFilter requires a specific collection, not \'*\'');
    const { kid, secret } = this.keyRing.currentSecret();
    const jti = this.snowflake.nextIdString();
    const now = Date.now();
    // rowFilter narrows the token to "operations may only touch records where
    // record[rowFilter.field] === rowFilter.value" -- e.g. "User X may only read records
    // where owner == X". Enforced by whoever holds the decrypted record (direct-server.js),
    // i.e. this is an authorization check on already-decrypted plaintext, the same trust
    // tier as the rest of the direct-access path -- NOT a blind/searchable-encryption-level
    // guarantee. True row-level ACL enforced *without* the enforcing party seeing plaintext
    // is an attribute-based-encryption-class problem, well beyond a capability-token scope
    // field; this is deliberately the narrower, honestly-scoped version of that idea.
    const payload = { sub: String(sub), dbId: String(dbId), collection, scope, jti, singleUse, rowFilter, iat: now, exp: now + ttlMs };
    const header = base64url(JSON.stringify({ alg: 'HS256', kid }));
    const body = base64url(JSON.stringify(payload));
    const sig = hmacSign(secret, `${header}.${body}`);
    return `${header}.${body}.${sig}`;
  }

  verify(token, { dbId, collection, requiredOp }) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new Error('fitdb: malformed capability token');
    const [header, body, sig] = parts;

    let kid;
    try { ({ kid } = JSON.parse(fromBase64url(header).toString('utf8'))); }
    catch (_) { throw new Error('fitdb: malformed capability token header'); }

    const secret = this.keyRing.secretFor(kid);
    if (!secret) throw new Error('fitdb: unknown or revoked capability key id');

    const expectedSig = hmacSign(secret, `${header}.${body}`);
    if (!timingSafeEqualStr(sig, expectedSig)) throw new Error('fitdb: capability token signature invalid');

    const claims = JSON.parse(fromBase64url(body).toString('utf8'));
    const now = Date.now();
    if (claims.exp < now) throw new Error('fitdb: capability token expired');
    if (claims.dbId !== String(dbId)) throw new Error('fitdb: capability token is not scoped to this database');
    if (claims.collection !== '*' && claims.collection !== collection) throw new Error('fitdb: capability token is not scoped to this collection');
    if ((claims.scope & requiredOp) !== requiredOp) throw new Error('fitdb: capability token scope does not cover this operation');

    if (claims.singleUse) {
      this._pruneUsed(now);
      if (this.usedJti.has(claims.jti)) throw new Error('fitdb: capability token already used (replay)');
      this.usedJti.set(claims.jti, claims.exp);
    }
    return claims;
  }

  _pruneUsed(now) {
    for (const [jti, exp] of this.usedJti) if (exp < now) this.usedJti.delete(jti);
  }
}

module.exports = { CapabilityKeyRing, CapabilityTokenService };
