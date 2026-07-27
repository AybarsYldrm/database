'use strict';

const path = require('node:path');
const fsp = require('node:fs/promises');

const { requireGrpc } = require('./helpers/require-grpc');
requireGrpc();
const { createDatabaseServer } = require('../src/grpc/server');
const { enroll, resume } = require('../src/provisioning/enrollment-client');
const {
  createSharedSecretAttestor, createRenewalAttestor, createCompositeAttestor,
  generateEnrolmentSecret,
} = require('../src/provisioning/attestor');
const { createTestCaBackend, createTestCsrProvider, createServerIdentity } = require('./helpers/test-pki');

// Surviving a restart without spending the bootstrap credential again.
//
// The bootstrap secret is single-use by design: a credential that stays valid forever is a
// permanent way into the identity system, sitting right next to it. But single-use only works
// if a restart is not indistinguishable from a first run -- and it was. enroll() was the only
// way onto the data plane, so every process restart needed the secret again, which in practice
// means the secret must be multi-use and long-lived, which removes the property it was
// supposed to have.
//
// resume() closes that: the certificate obtained once is reloaded from disk, and renewal
// happens over mTLS. The secret is needed exactly once in the lifetime of the service.

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-bootstrap-resume');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const authority = createTestCaBackend();
  const serverTls = createServerIdentity(authority, { commonName: 'localhost' });
  const secret = generateEnrolmentSecret();

  let consumed = 0;
  const server = createDatabaseServer({
    baseDir,
    principals: { 'idp-service': { roles: ['admin'] } },
    enrollment: {
      caBackend: authority,
      attestor: createCompositeAttestor([
        createSharedSecretAttestor({
          enrolments: {
            'idp-service': {
              secret, subject: { CN: 'idp-service' }, altNames: ['idp.internal.fitfak.net'],
              roles: ['admin'], maxUses: 1,
            },
          },
          onConsumed: () => { consumed += 1; },
        }),
        createRenewalAttestor({ roleResolver: () => ['admin'] }),
      ]),
    },
  });

  server.listen(0, { host: '127.0.0.1', tls: serverTls.tlsOptions });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;

  console.log('\n[1] First run: no certificate, so the bootstrap credential is spent');
  const first = await enroll({
    target,
    serviceName: 'idp-service',
    csrProvider: createTestCsrProvider(),
    trust: { pinnedFingerprints: [authority.ca.fingerprint256] },
    bootstrap: { secret },
    altNames: ['idp.internal.fitfak.net'],
  });
  check('the identity is issued', first.principal === 'idp-service');
  check('the channel is mutually authenticated', first.client.channelInfo().mutual === true);
  check('the credential is now spent', consumed === 1);

  // What a service would persist across a restart.
  const persisted = {
    certPem: first.certPem,
    privateKeyPem: first.privateKeyPem,
    chainPem: first.chainPem,
    principal: first.principal,
    roles: first.roles,
    notAfter: first.notAfter,
    renewAfter: first.renewAfter,
  };
  first.close();

  console.log('\n[2] The credential really is single-use');
  let secondEnrolFailed = false;
  try {
    const again = await enroll({
      target, serviceName: 'idp-service', csrProvider: createTestCsrProvider(),
      trust: { pinnedFingerprints: [authority.ca.fingerprint256] },
      bootstrap: { secret }, altNames: ['idp.internal.fitfak.net'],
    });
    again.close();
  } catch (_) { secondEnrolFailed = true; }
  check('a second enrolment with the same secret is refused', secondEnrolFailed);

  console.log('\n[3] Restart: resume from the stored certificate, no credential involved');
  const resumed = await resume({
    target,
    certPem: persisted.certPem,
    privateKeyPem: persisted.privateKeyPem,
    chainPem: persisted.chainPem,
    principal: persisted.principal,
    roles: persisted.roles,
    notAfter: persisted.notAfter,
    renewAfter: persisted.renewAfter,
    csrProvider: createTestCsrProvider(),
  });
  check('the identity is restored', resumed.principal === 'idp-service');
  check('on a mutually authenticated channel', resumed.client.channelInfo().mutual === true);
  check('and the credential was not touched', consumed === 1);

  console.log('\n[4] The resumed identity is a real one: it can use the data plane and renew');
  const { connectDatabase } = require('../src/grpc/client');
  const handle = await connectDatabase({ target, identity: resumed });
  const who = await handle.whoAmI();
  check('the server recognises the principal', who.principal === 'idp-service');
  check('at security level mtls', who.securityLevel === 'mtls');

  const beforeRenewal = resumed.certPem;
  await resumed.renew();
  check('renewal over mTLS succeeds', resumed.certPem !== beforeRenewal);
  check('still without spending the credential', consumed === 1);
  check('and the principal is unchanged', resumed.principal === 'idp-service');

  console.log('\n[5] An expired stored certificate is reported here, not as a TLS error');
  // A certificate whose whole lifetime is already behind it.
  const stale = authority.issueDirect({
    subject: { CN: 'idp-service', O: 'fitfak' },
    keyPair: require('./helpers/test-pki').generateKeyPair(),
    eku: ['clientAuth'],
    validityDays: -1,
  });
  let expiredReason = '';
  try {
    await resume({
      target,
      certPem: stale.certPem,
      privateKeyPem: stale.privateKeyPem,
      chainPem: persisted.chainPem,
      csrProvider: createTestCsrProvider(),
    });
  } catch (err) {
    expiredReason = err.message;
  }
  check('an expired certificate is refused before connecting', /expired/i.test(expiredReason));

  handle.close();
  resumed.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - bootstrap resume: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
