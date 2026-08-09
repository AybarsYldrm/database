'use strict';

// Where certificates actually come from.
//
// This database server is NOT a certificate authority and must not become one. In this stack
// the CA is central (the ACME authority at trust.fitfak.net) and the database plays the role
// RFC 7030 calls a Registration Authority: it authenticates a peer that is not yet enrolled,
// decides what identity that peer is allowed to be issued, and then asks the real CA to issue
// it. Keeping issuance behind this interface is what makes that separation enforceable rather
// than aspirational -- the enrolment service literally cannot sign anything itself.
//
// A backend implements:
//
//   async getTrustAnchors()  -> { chainPem: string[], fingerprints: string[] }
//   async parseCsr(csrPem)   -> { subject: {CN,...}, altNames: string[], publicKeyPem, verified: boolean }
//   async issue(request)     -> { certPem, chainPem: string[], notAfter: Date, serialNumber }
//   async revoke?(serialNumber, reason)
//
// Three adapters ship here. All of them are thin: the PKI itself lives in @fitfak/ssl and in
// the ACME authority, not in this package.

const crypto = require('node:crypto');

/**
 * Adapter for @fitfak/ssl, for deployments that run their own CA in-process (the API mirrors
 * that package's `CertificateAuthority` / `issueCertificateFromCSR` / `parseCSR` surface).
 *
 * The module is required lazily and by name so that @fitfak/database keeps installing with no
 * dependencies for everyone who does not use this backend, and so that the failure -- if it
 * is missing -- is a clear message at configuration time rather than a module-not-found
 * during someone's first enrolment.
 */
/**
 * How far to backdate notBefore.
 *
 * A certificate that becomes valid at exactly the instant it is issued is rejected by any
 * verifier whose clock is a second behind the issuer's, and clocks in a fleet are always a
 * second behind something. For a 397-day certificate nobody notices; for a five-minute one this
 * is the difference between "works" and "fails on about a third of the fleet, intermittently".
 * Sixty seconds is what Let's Encrypt and SPIRE both use, and it costs one minute of a lifetime
 * that is already deliberately short.
 */
const DEFAULT_BACKDATE_SECONDS = 60;

function createFitfakSslCaBackend({
  ca, ssl = null, defaultValidityDays = 397, backdateSeconds = DEFAULT_BACKDATE_SECONDS,
} = {}) {
  const lib = ssl || requireOptional('@fitfak/ssl',
    'the @fitfak/ssl CA backend needs the @fitfak/ssl package installed, or an `ssl` module passed in');
  if (!ca) throw new Error('fitdb pki: createFitfakSslCaBackend requires a `ca` (a @fitfak/ssl CertificateAuthority)');

  const chain = () => {
    const anchors = [];
    if (typeof ca.getIntermediatePem === 'function') {
      const intermediate = ca.getIntermediatePem();
      if (intermediate) anchors.push(intermediate);
    }
    anchors.push(typeof ca.getRootPem === 'function' ? ca.getRootPem() : ca.certPem);
    return anchors.filter(Boolean);
  };

  return {
    name: '@fitfak/ssl',

    async getTrustAnchors() {
      const chainPem = chain();
      return { chainPem, fingerprints: chainPem.map(fingerprintOf) };
    },

    parseCsr: createSslCsrParser(lib),

    async issue({ csrPem, subject, validityDays = defaultValidityDays, validitySeconds = null }) {
      // Short-lived issuance goes through explicit notBefore/notAfter rather than a day count,
      // because a day count cannot express five minutes and rounding it up to one day would
      // quietly undo the entire reason the caller asked for five minutes.
      const validity = validitySeconds
        ? (() => {
          const notBefore = new Date(Date.now() - backdateSeconds * 1000);
          return { notBefore, notAfter: new Date(Date.now() + validitySeconds * 1000) };
        })()
        : { validityDays };

      // The subject is taken from the GRANT, never from the CSR.
      //
      // By default @fitfak/ssl copies the CSR's own subject into the certificate, which is
      // right when the requester and the named party are the same. Here they are not: this is
      // a Registration Authority, so "who you are" comes from what the attestor authorised,
      // not from what the applicant typed. Relying on an equality check between the two
      // instead would make the whole identity boundary depend on that one comparison never
      // being skipped -- and it was skipped, silently, for exactly as long as parseCSR
      // returned no decoded subject at all.
      const issued = lib.issueCertificateFromCSR(csrPem, ca.issuer || ca, {
        ...validity,
        ...(subject && Object.keys(subject).length ? { subjectOverride: subject } : {}),
        // The CSR's SANs are kept rather than replaced by the grant's: enrolment has already
        // checked they are a subset of what was granted -- including the SPIFFE URI, which it
        // requires to be present and to match exactly -- and issuing the full granted set to a
        // peer that asked for less would widen the certificate beyond the request.
      });
      const certPem = issued.pem || issued.certPem;
      return {
        certPem,
        chainPem: chain(),
        notAfter: notAfterOf(certPem),
        serialNumber: serialOf(certPem),
      };
    },

    async revoke(serialNumber, reason = 0) {
      if (typeof ca.revoke !== 'function') throw new Error('fitdb pki: this CA does not support revocation');
      return ca.revoke(serialNumber, reason);
    },
  };
}

/**
 * Adapter for the central ACME authority (RFC 8555). The ACME account, order and challenge
 * dance lives in the caller's ACME client -- this only needs a function that takes a CSR and
 * comes back with a certificate chain, which is exactly what `finalize` + `certificate`
 * produce.
 *
 * Note what this implies operationally: ACME issues certificates for DNS identifiers it can
 * validate, so an enrolling *service* identity (`idp.internal.fitfak.net`) has to be a name
 * the authority will actually certify. For purely internal client identities that no public
 * authority should ever vouch for, the @fitfak/ssl backend against a private CA is the right
 * choice, and mixing the two -- public names for servers, a private CA for client identities
 * -- is a perfectly normal split.
 */
function createAcmeCaBackend({ acme, trustAnchorsPem = [], defaultValidityDays = 90 } = {}) {
  if (!acme || typeof acme.orderCertificate !== 'function') {
    throw new Error('fitdb pki: createAcmeCaBackend requires an `acme` client exposing orderCertificate({ csrPem, identifiers })');
  }
  if (trustAnchorsPem.length === 0) {
    // Without anchors the enrolling peer has nothing to pin the server to on its next
    // connection, which quietly turns the upgraded mTLS channel back into trust-on-first-use.
    throw new Error('fitdb pki: createAcmeCaBackend requires trustAnchorsPem so enrolled peers can validate the server');
  }

  return {
    name: 'acme',

    async getTrustAnchors() {
      return { chainPem: trustAnchorsPem, fingerprints: trustAnchorsPem.map(fingerprintOf) };
    },

    async parseCsr(csrPem) {
      if (!acme.parseCsr) throw new Error('fitdb pki: the ACME backend needs a parseCsr implementation to validate requested identities');
      return acme.parseCsr(csrPem);
    },

    async issue({ csrPem, subject, altNames }) {
      const identifiers = (altNames && altNames.length ? altNames : [subject?.CN]).filter(Boolean);
      const result = await acme.orderCertificate({ csrPem, identifiers });
      const chainPem = splitPemChain(result.certificatePem || result.certificate);
      const certPem = chainPem.shift();
      return {
        certPem,
        chainPem: chainPem.length ? chainPem : trustAnchorsPem,
        notAfter: notAfterOf(certPem),
        serialNumber: serialOf(certPem),
        validityDays: defaultValidityDays,
      };
    },
  };
}

/**
 * Escape hatch: wrap any issuance function at all. Used by the test suite, and by anyone
 * whose CA speaks a protocol neither adapter above covers (CMP, an internal HTTP API, a
 * hardware appliance).
 */
function createCustomCaBackend({ name = 'custom', getTrustAnchors, parseCsr, issue, revoke = null }) {
  if (typeof issue !== 'function') throw new Error('fitdb pki: createCustomCaBackend requires an `issue` function');
  if (typeof getTrustAnchors !== 'function') throw new Error('fitdb pki: createCustomCaBackend requires a `getTrustAnchors` function');
  if (typeof parseCsr !== 'function') throw new Error('fitdb pki: createCustomCaBackend requires a `parseCsr` function');
  return { name, getTrustAnchors, parseCsr, issue, ...(revoke ? { revoke } : {}) };
}

// ---- helpers ---------------------------------------------------------------------------------

/**
 * Turns @fitfak/ssl's `parseCSR` into the shape the enrolment service checks grants against.
 *
 * Shared by every backend that has @fitfak/ssl available, including the one that delegates
 * signing to the identity provider: the CSR still has to be decoded HERE, because the identity
 * check it feeds is made here. Sending the request away to be parsed would put the decision and
 * the evidence for it on opposite sides of a network hop.
 */
function createSslCsrParser(lib) {
  return async function parseCsr(csrPem) {
    const parsed = lib.parseCSR(csrPem);
    const subject = subjectFromPairs(parsed.subject, lib);
    // A CSR carrying two CN attributes would let the first one satisfy an RA's equality check
    // while a relying party reads the second. `subjectAttrs` preserves DER order and every
    // occurrence, so the count is checkable.
    const commonNames = (parsed.subjectAttrs || [])
      .filter(([oidHex]) => oidHex === '550403')
      .map(([, value]) => value);
    return {
      subject,
      subjectAttrs: parsed.subjectAttrs || null,
      commonNames,
      altNames: (parsed.sans || parsed.altNames || []).map((s) => (typeof s === 'string' ? s : s.value)),
      publicKeyPem: parsed.publicKeyPem || null,
      // A CSR is self-signed by the key being certified; verifying that signature is the
      // proof-of-possession step. Skipping it would let a caller request a certificate over
      // someone else's public key.
      verified: lib.verifyCSR(parsed) === true,
      raw: parsed,
    };
  };
}

function requireOptional(moduleName, message) {
  try { return require(moduleName); }
  catch (err) { throw new Error(`fitdb pki: ${message} (${err.message})`); }
}

function fingerprintOf(pem) {
  return new crypto.X509Certificate(pem).fingerprint256;
}

function notAfterOf(pem) {
  return new Date(new crypto.X509Certificate(pem).validTo);
}

function serialOf(pem) {
  return new crypto.X509Certificate(pem).serialNumber;
}

function splitPemChain(pem) {
  const matches = String(pem || '').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\n?/g);
  return matches ? matches.map((m) => m.trim() + '\n') : [];
}

// @fitfak/ssl represents a subject as [[oid, value], ...]; everything else in this codebase
// works with { CN, O, OU, ... }.
const OID_TO_KEY = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
};

function subjectFromPairs(subject, lib) {
  if (!subject) return {};
  if (!Array.isArray(subject)) return subject;
  const out = {};
  for (const [oid, value] of subject) {
    const key = OID_TO_KEY[oid] || (lib?.oid?.nameOf ? lib.oid.nameOf(oid) : oid);
    out[key] = value;
  }
  return out;
}

module.exports = {
  createFitfakSslCaBackend,
  createAcmeCaBackend,
  createCustomCaBackend,
  createSslCsrParser,
  splitPemChain,
  fingerprintOf,
  DEFAULT_BACKDATE_SECONDS,
};
