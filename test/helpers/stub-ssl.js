'use strict';

const crypto = require('node:crypto');
const testPki = require('./test-pki');

// TEST FIXTURE ONLY -- a stand-in for @fitfak/ssl, which is a peer dependency and is not
// installable in this checkout.
//
// It implements the handful of calls PkiVault makes, on top of test-pki.js, so the certificates
// it produces are real X.509 that `crypto.X509Certificate` parses -- which matters, because the
// vault reads notAfter and the fingerprint out of them rather than trusting the caller.
//
// What it deliberately does NOT do is reproduce @fitfak/ssl's DER surface faithfully.
// `certInfoFromPem().subjectNameDer` in particular is a convenience here rather than the
// encoded Name the real package returns. Nothing in the vault interprets that value -- it is
// carried straight through to the issuing call -- so a stub is honest for what is under test:
// the vault's bookkeeping. If this file and @fitfak/ssl ever disagree about anything, @fitfak/ssl
// is right.

function subjectObjectFrom(certPem) {
  const subject = new crypto.X509Certificate(certPem).subject;
  const out = {};
  for (const line of subject.split('\n')) {
    const index = line.indexOf('=');
    if (index > 0) out[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return out;
}

function part({ keyPair, certPem, subject }) {
  return {
    keyType: 'ec',
    curveName: 'P-256',
    hashAlg: 'sha256',
    privateKey: keyPair.privateKey,
    privateKeyPem: keyPair.privateKeyPem,
    publicKeyBuf: keyPair.publicKeyBuf,
    certPem,
    subject,
  };
}

function makeStubSsl() {
  return {
    generateEcRootCA({ commonName = 'Test Root CA', organization = 'FITFAK', country = 'TR' } = {}) {
      const keyPair = testPki.generateKeyPair();
      const subject = { C: country, O: organization, CN: commonName };
      const cert = testPki.issue({ subject, keyPair, ca: true, validityDays: 3650 });
      return part({ keyPair, certPem: cert.certPem, subject });
    },

    generateEcIntermediateCA(parent, { commonName = 'Test Issuing CA', organization = 'FITFAK', country = 'TR' } = {}) {
      const keyPair = testPki.generateKeyPair();
      const subject = { C: country, O: organization, CN: commonName };
      // The issuer's subject is read back out of its own certificate rather than taken from
      // whatever the caller passed around, which is also what the real package does -- the
      // chain has to say what the parent certificate says, not what a metadata field claims.
      const cert = testPki.issue({
        subject,
        keyPair,
        issuer: {
          privateKey: parent.privateKey,
          certPem: parent.certPem,
          subject: parent.subject || subjectObjectFrom(parent.certPem),
        },
        ca: true,
        validityDays: 1825,
      });
      return part({ keyPair, certPem: cert.certPem, subject });
    },

    ecPrivToPem(p) { return p.privateKeyPem; },

    pemToEcPriv(pem) {
      const privateKey = crypto.createPrivateKey(pem);
      const publicKey = crypto.createPublicKey(privateKey);
      return {
        curveName: 'P-256',
        privateKey,
        privateKeyPem: pem,
        publicKeyBuf: publicKey.export({ type: 'spki', format: 'der' }),
      };
    },

    certInfoFromPem(pem) {
      const certificate = new crypto.X509Certificate(pem);
      return {
        subjectNameDer: Buffer.from(certificate.subject, 'utf8'),
        certDer: certificate.raw,
        subject: subjectObjectFrom(pem),
      };
    },

    asn1: {
      computeEcSKID(publicKeyBuf) { return crypto.createHash('sha1').update(publicKeyBuf).digest(); },
    },
  };
}

module.exports = { makeStubSsl, subjectObjectFrom };
