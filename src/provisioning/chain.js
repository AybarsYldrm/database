'use strict';

const crypto = require('node:crypto');

// What to PRESENT and what to TRUST, decided by reading the certificates.
//
// This replaces `chainPem.slice(0, -1)`, which appeared in three places and meant "everything
// except the last one, because the last one is the root". That is a POSITIONAL assumption about
// a list this process did not build, and it is wrong in both directions:
//
//   [intermediate, root]  -> slice drops the root. Correct, by luck.
//   [intermediate]        -> slice drops the INTERMEDIATE, and the peer is handed a leaf whose
//                            issuer it has never seen. The handshake fails with "unable to get
//                            local issuer certificate", which reads as a trust problem rather
//                            than as a chain-assembly one.
//   [root]                -> slice drops the root, leaving a bare leaf. Fine only if the leaf
//                            was signed by the root directly.
//   [root, intermediate]  -> slice drops the intermediate. Silently broken.
//
// The one-element case is not hypothetical: the registration-authority backend falls back to
// `getTrustAnchors().chainPem` when an issuance response carries no chain, and the anchors are
// the root ALONE. Every service enrolling down that path would present a leaf with no
// intermediate, against a peer holding only the root.
//
// So the split is made by looking at the certificates instead of at their positions. RFC 5280
// §6.1 defines a trust anchor as self-signed; everything else is an intermediate that the peer
// may need in order to build a path. TLS itself says the same thing (RFC 8446 §4.4.2): send the
// chain WITHOUT the anchor, because the peer must already have it -- sending it is harmless but
// pointless, and omitting the intermediate is fatal.

/** Splits a PEM bundle into individual certificates. */
function splitPem(pem) {
  const matches = String(pem || '').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches ? matches.map((block) => `${block}\n`) : [];
}

/**
 * Is this certificate its own issuer?
 *
 * Compared as DER-encoded names rather than as strings: two names that print identically can
 * differ in encoding, and two that print differently can be the same name. `crypto.X509Certificate`
 * exposes `subject`/`issuer` as text, so the honest check is `verify(publicKey)` -- a certificate
 * is self-signed exactly when its own key validates its signature.
 */
function isSelfSigned(certPem) {
  try {
    const certificate = new crypto.X509Certificate(certPem);
    return certificate.verify(certificate.publicKey);
  } catch (_) {
    // An unparseable entry is not a trust anchor. Treating it as one would put it in the CA list,
    // where a parse failure becomes a validation failure much later and somewhere else.
    return false;
  }
}

/**
 * Sorts a chain into what a peer needs to see and what it must already trust.
 *
 * @param {string[]|string} chain  PEM certificates, in any order
 * @returns {{ intermediates: string[], anchors: string[] }}
 */
function classifyChain(chain) {
  const entries = Array.isArray(chain)
    ? chain.flatMap((entry) => splitPem(entry))
    : splitPem(chain);

  const intermediates = [];
  const anchors = [];
  for (const certPem of entries) {
    if (isSelfSigned(certPem)) anchors.push(certPem);
    else intermediates.push(certPem);
  }
  return { intermediates, anchors };
}

/**
 * The `cert` a TLS peer should present: its leaf, then every intermediate.
 *
 * The anchor is left out (RFC 8446 §4.4.2): the peer either already trusts it, in which case
 * sending it changes nothing, or it does not, in which case sending it changes nothing either.
 * What matters is that no intermediate is missing, which is exactly what the positional version
 * could not guarantee.
 */
function presentationChain(leafPem, chain) {
  const { intermediates } = classifyChain(chain);
  return [String(leafPem || '').trim(), ...intermediates.map((p) => p.trim())]
    .filter(Boolean)
    .join('\n')
    .concat('\n');
}

/**
 * The `ca` a TLS peer should verify against: the anchors.
 *
 * When a bundle contains no self-signed certificate there is nothing to anchor to, and returning
 * the intermediates instead would be worse than returning nothing: it would validate any chain
 * that happens to pass through them, including one an attacker built. The caller gets an empty
 * result and has to say so.
 */
function trustAnchors(chain) {
  const { anchors } = classifyChain(chain);
  return anchors.map((p) => p.trim()).join('\n').concat(anchors.length ? '\n' : '');
}

module.exports = { splitPem, isSelfSigned, classifyChain, presentationChain, trustAnchors };
