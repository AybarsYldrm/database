'use strict';

// Verifies at STARTUP that @fitfak/ssl is the version this code was written against.
//
// This file exists because of an incident. package.json said `^1.0.2`; when the library's 2.x
// was published that range never installed it, and installations stayed on the old version. The
// result was certificates whose public key did not belong to the CSR's private key.
//
// WHY A MISMATCH IS SILENT
//
// The certificate is produced, returned as PEM, parses, has correct dates, and its chain
// verifies. The only thing wrong is the public key INSIDE it, and nobody reads that. The fault
// surfaces only when the certificate is used in a TLS handshake -- as "key values mismatch" on
// the server, or a meaningless handshake failure on the client. A network hop away from the code
// that produced it.
//
// Two checks, both needed:
//
//   1. VERSION. Catches the wrong version by name and says what to install.
//   2. BEHAVIOUR. This is the actual proof: generate a key pair, build a CSR from it, sign it,
//      and verify the resulting certificate's public key belongs to the private key we started
//      with. A version number is a promise; this is a measurement.
//
// It is not free -- one key generation and one signature, a few milliseconds -- but it runs once
// at startup, and in exchange it removes a diagnosis that could otherwise take months.

const crypto = require('node:crypto');

const MIN_MAJOR = 2;

// Profile names changed in 2.x. Calling with the old names raises "unknown profile" -- a loud
// error that announces itself, but its message does not say which mapping is stale, so the names
// are checked here too.
const REQUIRED_PROFILES = ['tls-server', 'tls-client', 'email', 'code-signing', 'tsa', 'ocsp-responder'];

class SslCompatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SslCompatError';
  }
}

function installedVersion() {
  try {
    // eslint-disable-next-line global-require, import/no-unresolved
    return require('@fitfak/ssl/package.json').version || null;
  } catch (_) {
    return null;
  }
}

/**
 * Kurulu @fitfak/ssl'in bu kod tabanının beklediği şey olup olmadığı.
 *
 * @param {object} [ssl]  enjekte edilebilir (testler için)
 * @returns {{ version, profiles, keyMatch }}
 */
function assertSslCompatible(ssl = null) {
  // eslint-disable-next-line global-require, import/no-unresolved
  const lib = ssl || require('@fitfak/ssl');
  const version = installedVersion();

  // ---- 1. sürüm --------------------------------------------------------------------------
  if (version) {
    const major = Number(String(version).split('.')[0]);
    if (Number.isFinite(major) && major < MIN_MAJOR) {
      throw new SslCompatError(
        `@fitfak/ssl ${version} kurulu, ama bu kod ${MIN_MAJOR}.x bekliyor.\n\n`
        + '  Eski sürüm sessizce yanlış çalışır: CSR\'den üretilen sertifikanın içindeki açık\n'
        + '  anahtar istekteki özel anahtara ait olmaz. Sertifika geçerli görünür, zinciri\n'
        + '  doğrulanır, ve yalnızca bir TLS el sıkışmasında "key values mismatch" olarak\n'
        + '  patlar -- yani onu üreten koddan bir ağ hattı ötede.\n\n'
        + '  Çözüm:  npm install @fitfak/ssl@^2.1.0\n'
        + '          (kaynak: https://github.com/aybarsyldrm/ssl)',
      );
    }
  }

  // ---- 2. profil adları ---------------------------------------------------------------------
  const profiles = typeof lib.listProfiles === 'function' ? lib.listProfiles() : [];
  const missing = REQUIRED_PROFILES.filter((name) => !profiles.includes(name));
  if (profiles.length && missing.length) {
    throw new SslCompatError(
      `@fitfak/ssl şu profilleri tanımıyor: ${missing.join(', ')}.\n`
      + `  Tanıdıkları: ${profiles.join(', ')}\n\n`
      + '  Profil adları 2.x ile değişti (server-auth -> tls-server, client-auth -> tls-client).\n'
      + '  core/certificate-profiles.js bunları eşliyor; bu hata eşlemenin kütüphaneden\n'
      + '  ayrıştığını söyler.',
    );
  }

  // ---- 3. davranış: üretilen sertifika, isteğin anahtarına mı ait ----------------------------
  //
  // Asıl kontrol bu. Sürüm numarası bir vaat, bu bir ölçüm.
  const keyMatch = verifyCsrKeyBinding(lib);
  if (!keyMatch) {
    throw new SslCompatError(
      '@fitfak/ssl bir CSR\'den, isteğin özel anahtarına AİT OLMAYAN bir sertifika üretti.\n\n'
      + '  Bu kurulumla üretilen her sertifika, kullanılmaya çalışıldığında bir TLS\n'
      + '  el sıkışmasında başarısız olacak. Sürüm kontrolünü geçtiğine göre sorun sürüm\n'
      + '  numarasında değil paketin kendisinde: kurulumu doğrulayın.\n\n'
      + `  Kurulu sürüm: ${version || 'bilinmiyor'}`,
    );
  }

  return { version, profiles, keyMatch };
}

/**
 * Bir anahtar çifti üretir, ondan bir CSR kurar, imzalar ve çıkan sertifikanın BAŞLADIĞIMIZ
 * özel anahtara ait olduğunu doğrular.
 *
 * `checkPrivateKey` Node'un kendi kontrolü: sertifikanın açık anahtarı ile verilen özel
 * anahtarın eşleşip eşleşmediğini söyler. Kendi ürettiğimiz baytları yine kendi kodumuzla
 * karşılaştırmak bir şey kanıtlamazdı -- ikisinde de aynı yanlış anlaşılma olabilir.
 */
function verifyCsrKeyBinding(lib) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = privateKey.export({ format: 'jwk' });

    const keyInfo = {
      keyType: 'ec',
      curveName: 'P-256',
      // HAM nokta (0x04 || X || Y), SPKI DER değil: kütüphane SPKI'yi kendisi kurar ve SPKI
      // geçirmek içine ikinci bir SPKI gömülü bozuk bir yapı üretir.
      publicKeyBuf: Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(jwk.x, 'base64url'),
        Buffer.from(jwk.y, 'base64url'),
      ]),
      privateKey: BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`),
    };

    const csrPem = lib.generateCSR(keyInfo, [[lib.oid.OIDs.commonName, 'ssl-compat-check']], []);
    const ca = lib.generateEcRootCA({ commonName: 'ssl-compat-check-ca' });
    const issued = lib.issueCertificateFromCSR(csrPem, ca, { profile: 'tls-client', validityDays: 1 });

    const certificate = new crypto.X509Certificate(issued.pem);
    // İki yönlü: sertifika özel anahtarımıza mı ait, ve açık anahtarı bizimkiyle aynı mı.
    // İlki Node'un kontrolü, ikincisi baytların gerçekten taşındığını gösterir.
    return certificate.checkPrivateKey(privateKey)
      && certificate.publicKey.export({ type: 'spki', format: 'pem' }).trim()
        === publicKey.export({ type: 'spki', format: 'pem' }).trim();
  } catch (err) {
    throw new SslCompatError(
      `@fitfak/ssl ile bir sertifika üretilemedi: ${err.message}\n\n`
      + '  Bu, kurulu sürümün bu kod tabanının beklediği arayüze sahip olmadığını gösterir.\n'
      + '  Beklenen: @fitfak/ssl@^2.1.0 (https://github.com/aybarsyldrm/ssl)',
    );
  }
}

module.exports = { assertSslCompatible, verifyCsrKeyBinding, SslCompatError, MIN_MAJOR };
