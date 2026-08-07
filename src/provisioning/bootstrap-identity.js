'use strict';

const crypto = require('node:crypto');

// The TLS identity a sealed database wears before anyone has given it a real one.
//
// It exists for one exchange: letting the identity provider reach the control plane in order to
// hand over the certificate the database will actually serve. It is generated at boot, lives in
// this process's memory, is never written anywhere, and is replaced the moment provisioning
// succeeds.
//
// Being self-signed is not a weakness here because it is not what authenticates the server. The
// bootstrap exchange is authenticated by a pre-shared secret, confirmed in both directions and
// bound to the TLS exporter (RFC 9266) -- see control-plane-service.js. The certificate's job is
// only to get a TLS session established so that an exporter value exists to bind to. Pinning its
// fingerprint, when an operator has a way to carry one, is defence in depth rather than the
// mechanism.
//
// Why generate a throwaway CA and issue a leaf from it, rather than serving a self-signed leaf
// directly: some TLS verifiers refuse a certificate that is simultaneously the end entity and
// its own issuer with CA:TRUE, and others refuse a leaf with no chain at all. A two-element
// chain is the shape every stack already handles, and both halves are discarded together.

const DEFAULT_VALIDITY_MINUTES = 30;

/**
 * @param {object}   opts
 * @param {object}  [opts.ssl]        the @fitfak/ssl module; required lazily when omitted
 * @param {string}  [opts.commonName]
 * @param {string[]}[opts.dnsNames]
 * @param {string[]}[opts.ips]
 * @param {number}  [opts.validityMinutes] short by design -- if provisioning has not happened
 *                                         within it, the deployment is broken, not slow
 * @returns {{ key, cert, ca, fingerprint256, notAfter, wipe }}
 */
function createEphemeralBootstrapIdentity({
  ssl = null,
  commonName = 'fitdb-bootstrap',
  dnsNames = ['localhost'],
  ips = ['127.0.0.1'],
  validityMinutes = DEFAULT_VALIDITY_MINUTES,
} = {}) {
  const lib = ssl || requireSsl();

  const now = new Date();
  const notAfter = new Date(now.getTime() + validityMinutes * 60_000);

  // A fresh trust root per boot. Nothing outside this process ever sees it as an anchor.
  const anchor = lib.generateEcRootCA({
    curveName: 'P-256',
    commonName: `${commonName} transient root`,
    organization: 'FITFAK',
    country: 'TR',
    verbose: false,
  });

  const leafKey = lib.generateEcKeyPair('P-256');
  const csr = lib.generateCSR(
    { keyType: 'ec', curveName: leafKey.curve, ...leafKey },
    [[lib.oid.OIDs.commonName, commonName]],
  );
  const leaf = lib.issueCertificateFromCSR(csr, anchor, {
    profile: 'tls-server',
    notBefore: now,
    notAfter,
    sans: [
      ...dnsNames.map((value) => ({ type: 'dns', value })),
      ...ips.map((value) => ({ type: 'ip', value })),
    ],
  });

  const leafPem = (leaf.pem || leaf.certPem).trim();
  const anchorPem = anchor.certPem.trim();

  const identity = {
    key: lib.ecPrivToPem(leafKey),
    cert: `${leafPem}\n${anchorPem}\n`,
    // Its own root, so a client that chooses to validate rather than pin can. Nobody else's
    // certificate ever chains to it, which is the point of throwing it away.
    ca: `${anchorPem}\n`,
    fingerprint256: new crypto.X509Certificate(leafPem).fingerprint256,
    notAfter,
    /**
     * Best-effort scrub. JavaScript strings are immutable and the garbage collector decides
     * when the old bytes go, so this drops the reference rather than overwriting memory --
     * honest about being a hygiene measure, not a guarantee. A deployment whose threat model
     * includes reading this process's heap needs a key that never enters it, which means an
     * HSM or a TPM, not a different string.
     */
    wipe() { identity.key = null; },
  };
  return identity;
}

function requireSsl() {
  try {
    // eslint-disable-next-line global-require
    return require('@fitfak/ssl');
  } catch (err) {
    throw new Error(
      'fitdb bootstrap: generating an ephemeral bootstrap identity needs @fitfak/ssl installed, '
      + `or an \`ssl\` module passed in (${err.message}). The alternative is to supply a bootstrap `
      + 'certificate and key yourself via `tls`.',
    );
  }
}

module.exports = { createEphemeralBootstrapIdentity, DEFAULT_VALIDITY_MINUTES };
