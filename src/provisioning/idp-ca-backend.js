'use strict';

const https = require('node:https');
const http = require('node:http');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const spiffe = require('./spiffe');

// Issuance delegated to the identity provider.
//
// This is the backend that makes "the database is a Registration Authority, never a CA" true
// rather than aspirational. The enrolment service authenticates a peer and decides what identity
// that peer may hold; this adapter carries the CSR and that decision to the IdP, which owns the
// signing key and produces the certificate. No signing key is ever present in this process.
//
// The alternative -- createFitfakSslCaBackend against a CA loaded here -- is still supported and
// is the right choice for a standalone deployment. It is the wrong choice for this stack, because
// it gives the database its own root, and two roots means two answers to "who is this peer",
// which is the thing the whole design is arranged to avoid.
//
//
// WHAT THE IDENTITY PROVIDER IS EXPECTED TO CHECK
//
// This adapter authenticates with client credentials, so from the IdP's side the request says
// "the database asserts that this CSR should be certified as X". That assertion must not be
// taken at face value. The IdP is expected to independently constrain what an RA may ask for --
// typically a SPIFFE path prefix, so the database can vouch for `spiffe://fitfak.net/service/*`
// and nothing else. Without that constraint, compromising the database would be equivalent to
// compromising the CA, and the separation would be organisational rather than enforced.
//
// The `spiffePrefix` option below is the client-side half of the same rule: it refuses to ASK
// for anything outside the prefix. A check on both ends means a bug in either one is still
// caught by the other.

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * @param {object}   opts
 * @param {string}   opts.issuanceUrl        e.g. 'https://trust.fitfak.net/pki/ra/issue'
 * @param {string}   opts.anchorsUrl         e.g. 'https://trust.fitfak.net/pki/ra/anchors'
 * @param {string}   opts.clientId           this database's registered RA client id
 * @param {string}   opts.clientSecret
 * @param {string}  [opts.spiffePrefix]      refuse to request identities outside this prefix
 * @param {function}[opts.trustAnchorsProvider] () => string[] -- when the anchors are already
 *                                           known locally (they arrive with the server identity
 *                                           over the control plane), this avoids a round trip on
 *                                           every enrolment
 * @param {object}  [opts.ssl]               @fitfak/ssl, used to decode the CSR locally
 * @param {function}[opts.parseCsr]          full override for CSR decoding
 * @param {function}[opts.fetchImpl]         injectable for tests
 * @param {function}[opts.credentialsProvider] async () => { issuanceUrl, anchorsUrl?, clientId,
 *                                           clientSecret } -- resolved per request instead of at
 *                                           construction. See below for why that is necessary.
 */
function createIdpCaBackend({
  issuanceUrl,
  anchorsUrl = null,
  clientId,
  clientSecret,
  spiffePrefix = null,
  trustAnchorsProvider = null,
  credentialsProvider = null,
  ssl = null,
  parseCsr = null,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  fetchImpl = null,
  logger = null,
}) {
  // Credentials may be late-bound, and in this stack they usually are.
  //
  // The database starts before the IdP has ever run. At that moment there is no issuance URL and
  // no RA client to name, because nothing has issued one — the IdP publishes both when it
  // provisions this process. Requiring them at construction would mean the database could only be
  // started SECOND, which is the ordering constraint this whole design removes.
  //
  // Nothing is lost by deferring: an enrolment cannot succeed before the IdP exists anyway, so the
  // first call that needs these values is necessarily after they are available.
  if (!credentialsProvider) {
    if (!issuanceUrl) throw new Error('fitdb pki: createIdpCaBackend requires an issuanceUrl');
    if (!clientId || !clientSecret) {
      throw new Error('fitdb pki: createIdpCaBackend requires clientId and clientSecret; the identity '
        + 'provider has to know which registration authority is vouching for a request before it '
        + 'can decide what that authority may vouch for');
    }
  }

  // Resolved once and remembered. Re-reading on every enrolment would turn a certificate request
  // into a disk read, and these values change only when the IdP is reconfigured — which restarts
  // this process anyway, because the server identity is reinstalled with them.
  let resolved = credentialsProvider ? null : { issuanceUrl, anchorsUrl, clientId, clientSecret };
  let post = fetchImpl || (resolved ? defaultPost({ ...resolved, timeoutMs }) : null);

  async function credentials() {
    if (resolved) return resolved;
    const found = await credentialsProvider();
    if (!found || !found.issuanceUrl || !found.clientId || !found.clientSecret) {
      throw new Error(
        'fitdb pki: this database has no registration-authority credentials yet. The identity '
        + 'provider publishes them when it provisions this process; until it has, no service can '
        + 'enrol. Start the identity provider, or check that both processes agree on the pairing '
        + 'directory (FITFAK_PAIRING_DIR).',
      );
    }
    resolved = { anchorsUrl, ...found };
    if (!fetchImpl) post = defaultPost({ ...resolved, timeoutMs });
    logger?.info?.(`[pki] registration-authority credentials resolved: ${resolved.clientId} -> ${resolved.issuanceUrl}`);
    return resolved;
  }

  const prefix = spiffePrefix ? spiffe.parse(spiffePrefix) : null;

  // Cached because it is stable and because an enrolment that pays for a second round trip to
  // fetch anchors it already fetched is a slower enrolment for no benefit.
  let cachedAnchors = null;

  return {
    name: 'idp',

    async getTrustAnchors() {
      if (trustAnchorsProvider) {
        const chainPem = trustAnchorsProvider() || [];
        return { chainPem, fingerprints: chainPem.map(fingerprintOf) };
      }
      if (cachedAnchors) return cachedAnchors;
      const config = await credentials();
      if (!config.anchorsUrl) {
        throw new Error('fitdb pki: createIdpCaBackend needs either an anchorsUrl or a '
          + 'trustAnchorsProvider, otherwise an enrolling peer has nothing to validate this '
          + 'server against on its next connection');
      }
      const response = await post(config.anchorsUrl, {});
      const chainPem = response.chainPem || [];
      cachedAnchors = { chainPem, fingerprints: chainPem.map(fingerprintOf) };
      return cachedAnchors;
    },

    /**
     * Parsing stays local. The CSR has to be decoded here anyway so the enrolment service can
     * check it against the grant, and sending it to the IdP to be parsed would put the identity
     * check a network hop away from the decision it informs.
     */
    parseCsr: parseCsr || (() => {
      // eslint-disable-next-line global-require
      const { createSslCsrParser } = require('./ca-backend');
      // eslint-disable-next-line global-require
      const lib = ssl || require('@fitfak/ssl');
      return createSslCsrParser(lib);
    })(),

    async issue({ csrPem, subject, altNames, spiffeId, roles, validityDays, validitySeconds }) {
      if (prefix && spiffeId) {
        const requested = spiffe.parse(spiffeId);
        if (!requested.isUnder(prefix)) {
          throw new Error(`fitdb pki: this registration authority may only vouch for identities under `
            + `${prefix}, and '${requested}' is not one`);
        }
      }

      const config = await credentials();
      const response = await post(config.issuanceUrl, {
        csrPem,
        subject: subject || null,
        altNames: altNames || [],
        spiffeId: spiffeId || null,
        roles: roles || [],
        ...(validitySeconds ? { validitySeconds } : {}),
        ...(validityDays ? { validityDays } : {}),
      });

      if (!response.certPem) {
        throw new Error(`fitdb pki: the identity provider returned no certificate (${response.error || 'no reason given'})`);
      }
      logger?.info?.(`[pki] the identity provider issued ${response.serialNumber || 'a certificate'} for ${spiffeId || subject?.CN}`);

      return {
        certPem: response.certPem,
        chainPem: response.chainPem || (await this.getTrustAnchors()).chainPem,
        notAfter: response.notAfter ? new Date(Number(response.notAfter)) : notAfterOf(response.certPem),
        serialNumber: response.serialNumber || serialOf(response.certPem),
      };
    },

    /**
     * Revocation is the IdP's to perform -- it holds the CRL and the OCSP responder. This is a
     * pass-through so that an operator sealing off a compromised service does not have to go to
     * a different system to do half the job.
     *
     * For short-lived certificates this should almost never be needed: a credential measured in
     * minutes expires long before a revocation could propagate, so declining to renew is both
     * faster and more reliable. It exists for the service identities that are still measured in
     * months, and for the case where "wait five minutes" is not an acceptable answer.
     */
    async revoke(serialNumber, reason = 'unspecified') {
      const config = await credentials();
      if (!/\/issue$/.test(config.issuanceUrl)) {
        throw new Error("fitdb pki: revocation is derived from the issuance URL by replacing a "
          + `trailing '/issue', and '${config.issuanceUrl}' does not end in one`);
      }
      return post(config.issuanceUrl.replace(/\/issue$/, '/revoke'), { serialNumber, reason });
    },
  };
}

function defaultPost({ clientId, clientSecret, timeoutMs }) {
  return (endpoint, payload) => new Promise((resolve, reject) => {
    const url = new URL(endpoint);
    const body = JSON.stringify(payload);
    const transport = url.protocol === 'http:' ? http : https;

    const req = transport.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-client-id': clientId,
        'x-client-secret': clientSecret,
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode !== 200) {
          // The IdP's own error text is worth surfacing verbatim: "this RA may not vouch for
          // that identity" is the difference between a five-minute fix and an afternoon.
          return reject(new Error(`the identity provider refused the request (HTTP ${res.statusCode}): ${text.slice(0, 300)}`));
        }
        try { resolve(JSON.parse(text)); }
        catch (err) { reject(new Error(`the identity provider returned malformed JSON: ${err.message}`)); }
      });
    });

    req.on('timeout', () => req.destroy(new Error(`the identity provider did not respond within ${timeoutMs}ms`)));
    req.on('error', reject);
    req.end(body);
  });
}

function fingerprintOf(pem) { return new crypto.X509Certificate(pem).fingerprint256; }
function notAfterOf(pem) { return new Date(new crypto.X509Certificate(pem).validTo); }
function serialOf(pem) { return new crypto.X509Certificate(pem).serialNumber; }

module.exports = { createIdpCaBackend };
