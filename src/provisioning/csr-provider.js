'use strict';

const crypto = require('node:crypto');

// Key generation and PKCS#10 CSR construction on the enrolling side.
//
// Split out behind an interface for the same reason as the CA backend: the real
// implementation is @fitfak/ssl, and @fitfak/database should not carry a second one. A
// provider implements:
//
//   async generateKeyPair()                      -> { privateKeyPem, publicKeyPem, ...opaque }
//   async createCsr({ keyPair, subject, altNames }) -> csrPem
//
// The private key never leaves the enrolling process -- that is the entire point of enrolling
// with a CSR instead of asking a server to generate a key and send it back.

/**
 * Adapter for @fitfak/ssl's `generateCSR`, matching the key-info shape that package expects
 * (the same one the ACME client in this stack already builds).
 */
function createFitfakSslCsrProvider({ ssl = null, algorithm = 'ec', namedCurve = 'prime256v1', curveName = 'P-256', modulusLength = 2048 } = {}) {
  const lib = ssl || requireOptional('@fitfak/ssl',
    'CSR generation needs the @fitfak/ssl package installed, or an `ssl` module passed in');
  const OIDs = lib.OIDs || lib.oid?.OIDs;
  if (!OIDs) throw new Error('fitdb pki: the supplied @fitfak/ssl module does not expose OIDs');

  return {
    name: '@fitfak/ssl',

    async generateKeyPair() {
      if (algorithm === 'rsa') {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength });
        return {
          keyType: 'rsa',
          privateKey,
          publicKey,
          privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
          publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
          publicKeyBuf: publicKey.export({ type: 'spki', format: 'der' }),
          privateKeyDer: privateKey.export({ type: 'pkcs1', format: 'der' }),
        };
      }
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve });
      // @fitfak/ssl EC imzalamada özel anahtarı SKALER olarak ister (BigInt),
      // DER ya da PEM olarak değil. Aşağıdaki `privateKeyScalar` bunun için:
      // önceden buraya privateKeyDer geçiliyordu ve imzalama, ilgisiz bir
      // "Unknown encoding" hatasıyla düşüyordu -- bu yol paketin kendi
      // testlerinde bir test sahtesiyle değiştirildiği için hiç çalışmamıştı.
      const jwk = privateKey.export({ format: 'jwk' });
      return {
        keyType: 'ec',
        curveName,
        privateKey,
        privateKeyScalar: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
        publicKey,
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
        // @fitfak/ssl EC için HAM noktayı bekler (0x04 || X || Y), SPKI DER
        // değil -- SPKI'yi kendisi kurar. SPKI geçirmek, içine ikinci bir SPKI
        // gömülü bozuk bir yapı üretiyor ve sunucu tarafında "Failed to read
        // asymmetric key" olarak patlıyordu.
        publicKeyBuf: Buffer.concat([
          Buffer.from([0x04]),
          Buffer.from(jwk.x, 'base64url'),
          Buffer.from(jwk.y, 'base64url'),
        ]),
        // SPKI biçimi hâlâ gerekebilir (CA backend'leri, doğrulayıcılar).
        publicKeySpkiDer: publicKey.export({ type: 'spki', format: 'der' }),
        privateKeyDer: privateKey.export({ type: 'sec1', format: 'der' }),
      };
    },

    async createCsr({ keyPair, subject, altNames = [] }) {
      const keyInfo = keyPair.keyType === 'rsa'
        ? { keyType: 'rsa', publicKeyBuf: keyPair.publicKeyBuf, privateKey: keyPair.privateKeyDer, n: keyPair.n, e: keyPair.e }
        : { keyType: 'ec', curveName: keyPair.curveName, publicKeyBuf: keyPair.publicKeyBuf, privateKey: keyPair.privateKeyScalar };

      const subjectPairs = [];
      if (subject.C) subjectPairs.push([OIDs.country, subject.C]);
      if (subject.ST) subjectPairs.push([OIDs.stateOrProvince || OIDs.state, subject.ST]);
      if (subject.L) subjectPairs.push([OIDs.locality, subject.L]);
      if (subject.O) subjectPairs.push([OIDs.organization, subject.O]);
      if (subject.OU) subjectPairs.push([OIDs.organizationalUnit, subject.OU]);
      if (subject.CN) subjectPairs.push([OIDs.commonName, subject.CN]);

      const sans = altNames.map((value) => (typeof value === 'string' ? { type: inferAltNameType(value), value } : value));
      return lib.generateCSR(keyInfo, subjectPairs, sans);
    },
  };
}

/** Escape hatch for any other CSR implementation, and what the test suite uses. */
function createCustomCsrProvider({ name = 'custom', generateKeyPair, createCsr }) {
  if (typeof generateKeyPair !== 'function' || typeof createCsr !== 'function') {
    throw new Error('fitdb pki: createCustomCsrProvider requires generateKeyPair and createCsr');
  }
  return { name, generateKeyPair, createCsr };
}

function inferAltNameType(value) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || (value.includes(':') && !value.includes('/'))) return 'ip';
  if (value.includes('@')) return 'email';
  if (value.includes('://')) return 'uri';
  return 'dns';
}

function requireOptional(moduleName, message) {
  try { return require(moduleName); }
  catch (err) { throw new Error(`fitdb pki: ${message} (${err.message})`); }
}

module.exports = { createFitfakSslCsrProvider, createCustomCsrProvider, inferAltNameType };
