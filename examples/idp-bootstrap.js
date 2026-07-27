'use strict';

// A runnable walk-through of the deployment this package is built for, in one process:
//
//   trust.fitfak.net   the central CA. Here a local stand-in; in production the ACME
//                      authority, reached through createAcmeCaBackend.
//   fitdb              the database server. Gets its own certificate from that authority,
//                      and acts as Registration Authority for everyone else.
//   idp-service        a service being brought up for the very first time. It has an
//                      enrolment secret and nothing else -- no certificate, no key.
//
// Run: node examples/idp-bootstrap.js
//
// The point of interest is the ordering. The IdP cannot authenticate itself until it has a
// certificate, and it cannot get a certificate without reaching the database. So the first
// connection is server-authenticated only, carries exactly one exchange, and is then replaced
// by a mutually authenticated one. Nothing else is reachable on the first channel.

const path = require('node:path');
const fsp = require('node:fs/promises');

const {
  createDatabaseServer, connectDatabase, enroll,
  createSharedSecretAttestor, createRenewalAttestor, createCompositeAttestor,
  generateEnrolmentSecret, SecretStore, DnsStore,
} = require('..');

// Stand-ins for @fitfak/ssl and the ACME authority. In production these two lines become
// `createFitfakSslCaBackend({ ca })` / `createAcmeCaBackend({ acme })` and
// `createFitfakSslCsrProvider()`; nothing else in this file changes.
const { createTestCaBackend, createTestCsrProvider, createServerIdentity } = require('../test/helpers/test-pki');

const step = (n, text) => console.log(`\n${'='.repeat(72)}\n  ${n}. ${text}\n${'='.repeat(72)}`);
const say = (text) => console.log(`     ${text}`);

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-idp-example');
  await fsp.rm(baseDir, { recursive: true, force: true });

  // ---------------------------------------------------------------------------------------
  step(1, 'The certificate authority issues the database server its TLS identity');

  const authority = createTestCaBackend();
  const serverTls = createServerIdentity(authority, { commonName: 'localhost' });
  say(`CA fingerprint      ${authority.ca.fingerprint256}`);
  say(`server certificate  CN=localhost, issued by the CA above`);
  say('In production this certificate comes from ACME and is renewed automatically;');
  say('server.rotateServerCertificate({key, cert, ca}) swaps it in without dropping connections.');

  // ---------------------------------------------------------------------------------------
  step(2, 'An enrolment secret is provisioned for the IdP, out of band');

  const idpSecret = generateEnrolmentSecret();
  say(`secret (base64)     ${idpSecret.toString('base64').slice(0, 24)}...`);
  say('This is the only thing the IdP starts with. It never crosses the wire --');
  say('only an HMAC over it does, bound to the TLS session and to the CSR.');

  // ---------------------------------------------------------------------------------------
  step(3, 'The database server starts as a Registration Authority');

  const server = createDatabaseServer({
    baseDir,
    principals: {
      // Also the allow-list. Removing an entry locks that certificate out on its next
      // connection, however long it remains cryptographically valid.
      'idp-service': { roles: ['admin'] },
    },
    enrollment: {
      caBackend: authority,
      attestor: createCompositeAttestor([
        createSharedSecretAttestor({
          enrolments: {
            'idp-service': {
              secret: idpSecret,
              subject: { CN: 'idp-service', O: 'fitfak' },
              altNames: ['idp.internal.fitfak.net'],
              roles: ['admin'],
              // Default. Renewal goes through mTLS, so once is genuinely enough.
              maxUses: 1,
            },
          },
        }),
        createRenewalAttestor({ roleResolver: () => ['admin'] }),
      ]),
    },
  });

  server.on('enrolled', (event) => say(`  [server] issued '${event.principal}' via ${event.method}`));
  server.on('enrolmentDenied', (event) => say(`  [server] denied '${event.serviceName}': ${event.reason}`));

  // One listener, both channels. requestCert asks every client for a certificate;
  // rejectUnauthorized:false lets a client that has none complete the handshake anyway.
  server.listen(0, { host: '127.0.0.1', tls: serverTls.tlsOptions });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;
  say(`listening on ${target}`);
  say('EnrollmentService is reachable at security level "tls"; every DatabaseService');
  say('method requires "mtls" and is refused before the handler runs.');

  // ---------------------------------------------------------------------------------------
  step(4, 'The IdP bootstraps: TLS -> enrol -> mTLS');

  const identity = await enroll({
    target,
    serviceName: 'idp-service',
    csrProvider: createTestCsrProvider(),
    // Pinning the CA rather than shipping the bundle: enough to authenticate the server on
    // first contact, and it survives a legitimate server-certificate rotation.
    trust: { pinnedFingerprints: [authority.ca.fingerprint256] },
    bootstrap: { secret: idpSecret },
    altNames: ['idp.internal.fitfak.net'],
    logger: { info: (m) => say(m), warn: (m) => say(m) },
  });

  say(`principal           ${identity.principal}`);
  say(`roles               ${identity.roles.join(', ')}`);
  say(`certificate expires ${new Date(identity.notAfter).toISOString()}`);
  say(`renewal due         ${new Date(identity.renewAfter).toISOString()}`);
  say(`channel             mutual=${identity.client.channelInfo().mutual}`);

  // Renews at ~2/3 of the lifetime, early enough that a failure leaves room for retries.
  identity.startAutoRenewal();
  identity.on('renewed', (e) => say(`certificate renewed until ${new Date(e.notAfter).toISOString()}`));

  // ---------------------------------------------------------------------------------------
  step(5, 'The IdP uses the database over the upgraded channel');

  const handle = await connectDatabase({ target, identity });
  const who = await handle.whoAmI();
  say(`the server sees: ${who.principal} (${who.securityLevel}), permissions ${who.permissions}`);

  const { dbId, clientSecret } = await handle.createDatabase('kimlik');
  say(`created database ${dbId}`);
  say('clientSecret is returned exactly once and never persisted server-side.');
  say('It is what unwraps the database key; losing it means losing the data.');

  const db = await handle.openDatabase({ dbId, clientSecret });
  await db.defineCollection('kullanicilar', {
    title: 'Kullanıcılar',
    fields: [
      // Blind: equality lookups without a plaintext-searchable table of addresses.
      { no: 2, name: 'email', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'displayName', type: 'string' },
      // Plain: browsable, because the server has to enumerate by tenant.
      { no: 4, name: 'tenant', type: 'string', index: true },
      // Bucketed by day: "who signed up this week" without exact timestamps on the index.
      { no: 5, name: 'createdAt', type: 'int64', rangeBucket: { width: 86400000 }, diskBacked: true },
    ],
  });

  const users = db.collection('kullanicilar');
  const userId = await users.insert({
    email: 'aybars@fitfak.net', displayName: 'Aybars', tenant: 'core', createdAt: Date.now(),
  });
  say(`inserted user ${userId}`);
  say(`lookup by blind-indexed email: ${(await users.findOne('email', 'aybars@fitfak.net')).displayName}`);
  say(`records created in the last day: ${(await users.findRange('createdAt', Date.now() - 86400000, Date.now())).length}`);

  // ---------------------------------------------------------------------------------------
  step(6, 'A live view instead of polling');

  const view = users.watch();
  await view.ready();
  say(`view loaded from a snapshot: ${view.size} record(s), fresh=${view.fresh}`);

  view.on('put', (event) => say(`  [view] ${event.op} ${event.id} -> ${event.record.email}`));
  await users.insert({ email: 'yeni@fitfak.net', tenant: 'core', createdAt: Date.now() });
  await new Promise((r) => setTimeout(r, 150));
  say(`view now holds ${view.size} record(s), with no read issued`);
  say('This is what makes an encrypted store usable for DNS and certificates:');
  say('the decrypt happens once, and the database says when the copy goes stale.');

  // ---------------------------------------------------------------------------------------
  step(7, 'Certificates, keys and DNS in the same encrypted database');

  // These two use the embedded API against a local database. A remote process reaches the
  // same data through the collections above; the stores are a typed convenience over them.
  const localDb = server.manager.getOpenDatabase(dbId);

  const vault = await SecretStore.open(localDb);
  await vault.putCertificate({
    name: 'api.fitfak.net',
    certPem: serverTls.certPem,
    privateKeyPem: serverTls.privateKeyPem,
    chainPem: [authority.ca.certPem],
  });
  const pair = await vault.getCertificatePair('api.fitfak.net');
  say(`stored certificate expires ${new Date(pair.notAfter).toISOString()} (read from the certificate itself)`);
  say(`renewals due in 400 days: ${(await vault.listExpiring(400 * 86400000)).map((r) => r.name).join(', ')}`);

  const dns = await DnsStore.open(localDb);
  await dns.put({ zone: 'internal.fitfak.net', name: 'internal.fitfak.net', type: 'SOA', ttl: 3600, rdata: { mname: 'ns1.internal.fitfak.net', rname: 'ops.fitfak.net', serial: 1 } });
  await dns.put({ zone: 'internal.fitfak.net', name: 'idp.internal.fitfak.net', type: 'A', ttl: 300, rdata: { address: '10.0.0.20' } });
  await dns.put({ zone: 'internal.fitfak.net', name: '*.apps.internal.fitfak.net', type: 'A', ttl: 60, rdata: { address: '10.0.1.1' } });

  const zone = await dns.zoneCache('internal.fitfak.net');
  say(`zone cache holds ${zone.size} record(s)`);
  say(`query idp.internal.fitfak.net A     -> ${JSON.stringify(zone.query('idp.internal.fitfak.net', 'A').records[0].rdata)}`);
  say(`query x.apps.internal.fitfak.net A  -> ${JSON.stringify(zone.query('x.apps.internal.fitfak.net', 'A').records[0].rdata)} (wildcard)`);
  say(`query idp.internal.fitfak.net MX    -> ${zone.query('idp.internal.fitfak.net', 'MX').status} with 0 records (NODATA, not NXDOMAIN)`);
  say(`query nope.internal.fitfak.net A    -> ${zone.query('nope.internal.fitfak.net', 'A').status}`);
  say('Answers come from memory. The encrypted store is on the write path only.');

  // ---------------------------------------------------------------------------------------
  step(8, 'Shutting down');

  zone.stop();
  view.stop();
  handle.close();
  identity.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  say('done');
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
