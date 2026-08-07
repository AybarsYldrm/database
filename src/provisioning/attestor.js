'use strict';

const crypto = require('node:crypto');
const spiffe = require('./spiffe');

// How a peer that has no certificate yet proves it deserves one.
//
// This is the hard part of any enrolment scheme and it is deliberately pluggable, because the
// right answer differs per service: an IdP being brought up for the first time is provisioned
// with an out-of-band enrolment secret, a workload in an orchestrator presents a platform
// token, a device presents a TPM attestation, and a service whose certificate is merely
// expiring presents the certificate it already has. Hard-coding any one of those would force
// every future service onto a mechanism that does not fit it.
//
// An attestor implements:
//
//   async attest({ request, peer, channelBinding }) -> grant
//
// where `grant` is what the peer is allowed to become:
//
//   { principal, spiffeId, subject: {CN,...}, altNames: [], roles: [],
//     validityDays | validitySeconds, singleUse }
//
// Throwing rejects the enrolment. Returning a grant does NOT issue anything -- the enrolment
// service still checks the CSR against the grant, so an attestor that is too generous cannot
// by itself hand out an identity the CSR did not ask for, and vice versa.
//
// `spiffeId` is the identity that actually matters. A grant that carries one is saying "this
// peer may hold this SPIFFE ID", and the enrolment service will refuse a CSR that asks for any
// other. The CN is kept alongside it as a display string and as the key into allow-lists that
// predate SPIFFE, not as an authorisation input -- see spiffe.js for why that split exists.
//
// `validitySeconds` is the short-lived path. A workload certificate measured in minutes is the
// BeyondCorp model: the credential expires faster than a revocation could propagate, so
// rotation replaces revocation for everything except a compromise that has to be stopped
// immediately. `validityDays` remains for the service identities where minutes would mean
// re-issuing thousands of times a day for no gain.

const ENROLMENT_CONTEXT = 'fitdb-enroll-v1';

class EnrolmentDenied extends Error {
  constructor(message) { super(message); this.name = 'EnrolmentDenied'; }
}

/**
 * The canonical bytes both sides sign over. Every field here exists to close a specific hole:
 *
 * - `serviceName` + `nonce`: identifies the request and makes it single-use.
 * - `channelBinding` (RFC 9266 tls-exporter): ties the proof to THIS TLS session. Without it,
 *   anyone who can see the bootstrap exchange -- including a proxy that terminates TLS -- can
 *   replay the proof on their own connection.
 * - `csrFingerprint`: ties the proof to THIS public key. Without it, an interceptor can keep
 *   a valid proof and substitute a CSR over a key they control, and the CA will happily
 *   certify the attacker's key under the victim's name.
 * - `timestamp`: bounds how long a captured proof stays useful even if the nonce cache is lost.
 */
function enrolmentTranscript({ serviceName, nonce, timestamp, channelBinding, csrPem }) {
  const csrFingerprint = crypto.createHash('sha256').update(String(csrPem || '')).digest();
  return Buffer.concat([
    Buffer.from(ENROLMENT_CONTEXT, 'utf8'), Buffer.from([0]),
    Buffer.from(String(serviceName), 'utf8'), Buffer.from([0]),
    Buffer.from(String(nonce), 'utf8'), Buffer.from([0]),
    Buffer.from(String(timestamp), 'utf8'), Buffer.from([0]),
    channelBinding || Buffer.alloc(0), Buffer.from([0]),
    csrFingerprint,
  ]);
}

function computeEnrolmentProof(secret, parts) {
  return crypto.createHmac('sha256', secret).update(enrolmentTranscript(parts)).digest();
}

function timingSafeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Out-of-band shared secret, HMAC-proven and bound to the channel.
 *
 * `enrolments` maps a service name to `{ secret, subject, altNames, roles, maxUses, validityDays }`.
 * The secret is provisioned by whatever brings the service up (a sealed config value, an
 * operator pasting it once); it never crosses the wire, only an HMAC over it does.
 *
 * `requireChannelBinding` defaults to true. Turning it off is only defensible when the TLS
 * version in use genuinely cannot export keying material, and it costs the replay protection
 * described above -- so it is a deliberate, named decision rather than a silent fallback.
 */
function createSharedSecretAttestor({
  enrolments,
  clockSkewMs = 5 * 60 * 1000,
  requireChannelBinding = true,
  onConsumed = null,
} = {}) {
  if (!enrolments) throw new Error('fitdb enrol: createSharedSecretAttestor requires an `enrolments` map');
  const registry = enrolments instanceof Map ? enrolments : new Map(Object.entries(enrolments));
  const usedNonces = new Map(); // nonce -> expiry, pruned lazily
  const useCounts = new Map();  // serviceName -> uses so far

  return {
    name: 'shared-secret',

    async attest({ request, channelBinding }) {
      const { serviceName, nonce, timestamp, proof, csrPem } = request;
      if (!serviceName || !nonce || !proof) throw new EnrolmentDenied('enrolment request is missing serviceName, nonce or proof');

      const entry = registry.get(serviceName);
      // Same error text and no early return for an unknown service as for a bad proof: telling
      // an unauthenticated caller which service names exist is free reconnaissance.
      if (!entry) throw new EnrolmentDenied('enrolment rejected');

      const age = Math.abs(Date.now() - Number(timestamp || 0));
      if (!Number.isFinite(age) || age > clockSkewMs) throw new EnrolmentDenied('enrolment request timestamp is outside the accepted window');

      if (requireChannelBinding && (!channelBinding || channelBinding.length === 0)) {
        throw new EnrolmentDenied('enrolment requires TLS channel binding, which this connection cannot provide');
      }

      const expected = computeEnrolmentProof(entry.secret, { serviceName, nonce, timestamp, channelBinding, csrPem });
      if (!timingSafeEqual(expected, Buffer.from(String(proof), 'base64'))) throw new EnrolmentDenied('enrolment rejected');

      // The nonce is burned here, unconditionally: it exists to make this exact request
      // unrepeatable, and that has to hold whether or not the enrolment goes on to succeed.
      pruneNonces(usedNonces);
      if (usedNonces.has(nonce)) throw new EnrolmentDenied('enrolment nonce has already been used');
      usedNonces.set(nonce, Date.now() + clockSkewMs * 2);

      const maxUses = entry.maxUses ?? 1;
      const used = useCounts.get(serviceName) || 0;
      // A bootstrap secret that stays valid forever is a permanent backdoor into the identity
      // system; the default of one use makes it a genuinely single-shot credential, and
      // renewal goes through the mTLS re-enrolment path instead.
      if (maxUses > 0 && used >= maxUses) throw new EnrolmentDenied('this enrolment credential has already been used');

      return {
        principal: serviceName,
        spiffeId: entry.spiffeId || null,
        subject: entry.subject || { CN: serviceName },
        altNames: entry.altNames || [],
        roles: entry.roles || [],
        validityDays: entry.validityDays,
        validitySeconds: entry.validitySeconds,
        // The use is spent only once a certificate has actually been issued. Spending it here
        // would mean any request that authenticates but is then rejected downstream -- a CSR
        // asking for the wrong name, a CA that happens to be unreachable -- permanently burns
        // the credential, which turns a recoverable mistake into a re-provisioning job.
        commit: () => {
          const now = useCounts.get(serviceName) || 0;
          useCounts.set(serviceName, now + 1);
          if (onConsumed) onConsumed({ serviceName, uses: now + 1, maxUses });
        },
      };
    },
  };
}

/**
 * Delegates the decision to an existing identity provider: the peer presents a token it
 * already holds (a platform/workload token, an operator-issued JWT) and `verify` turns it into
 * a grant. This is the natural mechanism once an IdP exists -- the point of the pluggable
 * interface is that the IdP's own first enrolment can use a shared secret while everything
 * that comes after it uses the IdP.
 */
function createTokenAttestor({ verify, name = 'token' }) {
  if (typeof verify !== 'function') throw new Error('fitdb enrol: createTokenAttestor requires a `verify` function');
  return {
    name,
    async attest({ request, peer, channelBinding }) {
      if (!request.token) throw new EnrolmentDenied('enrolment request is missing a token');
      const grant = await verify(request.token, { request, peer, channelBinding });
      if (!grant) throw new EnrolmentDenied('enrolment token was not accepted');
      return {
        principal: grant.principal || grant.subject?.CN,
        spiffeId: grant.spiffeId || null,
        subject: grant.subject || { CN: grant.principal },
        altNames: grant.altNames || [],
        roles: grant.roles || [],
        validityDays: grant.validityDays,
        validitySeconds: grant.validitySeconds,
      };
    },
  };
}

/**
 * Re-enrolment (RFC 7030 `simplereenroll`): the peer already holds a valid certificate and is
 * renewing it before expiry. Authentication is the mTLS connection itself, so no bootstrap
 * credential is involved at all -- which is precisely why the bootstrap credential can be
 * single-use.
 *
 * The renewed identity is taken from the *existing certificate*, never from the request. A
 * peer renewing `dns-resolver` cannot ask to come back as `admin`.
 */
function createRenewalAttestor({
  roleResolver = null, validityDays = undefined, validitySeconds = undefined, trustDomain = null,
} = {}) {
  return {
    name: 'mtls-renewal',
    async attest({ peer }) {
      if (peer.securityLevel !== 'mtls' || !peer.certificate) {
        throw new EnrolmentDenied('re-enrolment requires an authenticated mTLS connection');
      }

      // The SPIFFE ID, when the certificate carries one, is the identity being renewed --
      // not the CN. Renewing from the CN while the certificate is authenticated by its URI
      // SAN would let the two drift apart across a renewal, and a certificate whose name means
      // one thing to the issuer and another to the verifier is worse than no renewal at all.
      const spiffeId = spiffe.fromCertificate(peer.certificate);
      if (trustDomain && spiffeId && spiffeId.trustDomain !== trustDomain) {
        throw new EnrolmentDenied(`this certificate belongs to trust domain '${spiffeId.trustDomain}', not '${trustDomain}'`);
      }

      const commonName = peer.certificate.commonName || peer.certificate.subject?.CN || null;
      if (!spiffeId && !commonName) {
        throw new EnrolmentDenied('the presented certificate carries neither a SPIFFE ID nor a common name to renew');
      }

      const altNames = (peer.certificate.altNames || [])
        .map((entry) => String(entry).replace(/^(DNS|IP Address|IP|email|URI):/i, '').trim())
        .filter(Boolean);

      return {
        // The principal stays the CN when there is one, because that is the key the server's
        // allow-list and every existing deployment is written against. The SPIFFE ID rides
        // alongside and is what the CSR is actually checked against.
        principal: commonName || spiffeId.uri,
        spiffeId: spiffeId ? spiffeId.uri : null,
        subject: peer.certificate.subject || { CN: commonName },
        altNames,
        roles: roleResolver ? await roleResolver(peer.certificate) : [],
        validityDays,
        validitySeconds,
      };
    },
  };
}

/**
 * Tries each attestor in order, first success wins. `request.method` may name one explicitly.
 * This is what lets a single enrolment endpoint serve a bootstrapping IdP, an IdP-issued
 * workload token and an ordinary renewal without three separate methods.
 */
function createCompositeAttestor(attestors) {
  const list = Array.isArray(attestors) ? attestors : Object.values(attestors);
  if (list.length === 0) throw new Error('fitdb enrol: createCompositeAttestor needs at least one attestor');

  return {
    name: `composite(${list.map((a) => a.name).join(',')})`,
    async attest(context) {
      const wanted = context.request?.method;
      const candidates = wanted ? list.filter((a) => a.name === wanted) : list;
      if (candidates.length === 0) throw new EnrolmentDenied(`no enrolment method named '${wanted}'`);

      const failures = [];
      for (const attestor of candidates) {
        try { return { ...(await attestor.attest(context)), method: attestor.name }; }
        catch (err) { failures.push(`${attestor.name}: ${err.message}`); }
      }
      throw new EnrolmentDenied(`enrolment rejected (${failures.join('; ')})`);
    },
  };
}

function pruneNonces(map) {
  const now = Date.now();
  for (const [nonce, expiry] of map) if (expiry < now) map.delete(nonce);
}

/** Generates a bootstrap secret to hand to a service being provisioned. */
function generateEnrolmentSecret() { return crypto.randomBytes(32); }

module.exports = {
  EnrolmentDenied,
  enrolmentTranscript,
  computeEnrolmentProof,
  generateEnrolmentSecret,
  createSharedSecretAttestor,
  createTokenAttestor,
  createRenewalAttestor,
  createCompositeAttestor,
  ENROLMENT_CONTEXT,
};
