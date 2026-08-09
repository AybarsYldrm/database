'use strict';

// A runnable walk-through of the ordering this package is built around, in one process.
//
//   Run: node examples/idp-bootstrap.js
//
// The point of interest is what the database CANNOT do at startup:
//
//   it has no certificate authority
//   it has no server certificate anyone would trust
//   it knows no principals
//   it serves nobody -- not even the identity provider's data plane
//
// It comes up SEALED, wearing a self-signed certificate generated in memory and never written
// anywhere. The only thing reachable on it is the control plane the IdP uses to hand over the
// certificate it will actually serve, the key for it, and the anchors it will validate clients
// against. Only when the IdP comes back on a mutually authenticated connection does the database
// open to anyone else.
//
// That ordering is the whole design. Every service in this stack takes its authority from the
// IdP, so a database reachable before the IdP is up is a database answering authorisation
// questions nobody can yet ask -- and that gap is exactly where a database grows a second
// identity system.

const path = require('node:path');
const fsp = require('node:fs/promises');

const {
  createDatabaseServer, connectDatabase, enroll, resume,
  createSharedSecretAttestor, createRenewalAttestor, createCompositeAttestor,
  generateEnrolmentSecret, generateBootstrapSecret, provisionServerIdentity,
  SecretStore, DnsStore, spiffe,
} = require('..');

// Stands in for @fitfak/ssl. In production the two CA lines below become the real package and
// nothing else in this file changes.
const { createTestCaBackend, createTestCsrProvider, createServerIdentity } = require('../test/helpers/test-pki');

const TRUST_DOMAIN = 'fitfak.net';
const IDP_SPIFFE_ID = spiffe.forService(TRUST_DOMAIN, 'idp').uri;

const step = (n, text) => console.log(`\n${'='.repeat(78)}\n  ${n}. ${text}\n${'='.repeat(78)}`);
const say = (text) => console.log(`     ${text}`);

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-idp-example');
  await fsp.rm(baseDir, { recursive: true, force: true });

  // ---------------------------------------------------------------------------------------
  step(1, 'The identity provider holds the certificate authority. The database holds none.');

  const idpCa = createTestCaBackend({ caSubject: { CN: 'FITFAK Root CA G1', O: 'fitfak' } });
  const csrProvider = createTestCsrProvider();
  say(`IdP root fingerprint   ${idpCa.ca.fingerprint256}`);
  say('In production this root lives in an encrypted fitdb collection next to the IdP');
  say('(see the IdP\'s core/ca-vault.js) -- not in a PEM file, and not in this database.');

  // ---------------------------------------------------------------------------------------
  step(2, 'Two secrets are provisioned out of band, and they are NOT the same secret');

  const controlSecret = generateBootstrapSecret();
  const smtpEnrolmentSecret = generateEnrolmentSecret();
  say(`control-plane secret   ${controlSecret.toString('base64').slice(0, 24)}...  (the IdP only)`);
  say(`smtp enrolment secret  ${smtpEnrolmentSecret.toString('base64').slice(0, 24)}...`);
  say('');
  say('The control-plane secret authorises ONE thing: installing this database\'s TLS identity.');
  say('An enrolment secret authorises another: obtaining a client certificate for one named');
  say('service. Sharing one value between them would let a service re-key the database it');
  say('connects to.');

  // ---------------------------------------------------------------------------------------
  step(3, 'The database starts SEALED, on a throwaway certificate it generated itself');

  // In production this is createEphemeralBootstrapIdentity({ ssl }). Here a throwaway test CA
  // stands in for it -- same shape, same lifetime: it exists for one exchange and is discarded.
  const throwaway = createTestCaBackend({ caSubject: { CN: 'fitdb bootstrap (transient)', O: 'fitfak' } });
  const bootstrapTls = createServerIdentity(throwaway, { commonName: 'localhost' });
  const bootstrapIdentity = {
    key: bootstrapTls.privateKeyPem,
    cert: bootstrapTls.certPem,
    ca: throwaway.ca.certPem,
    fingerprint256: bootstrapTls.fingerprint256,
  };

  const server = createDatabaseServer({
    baseDir,
    principals: {
      // Also the allow-list, and it pins the workload identity as well as the name: a CN
      // collision from a second CA cannot become an impersonation.
      'idp-service': { roles: ['admin'], spiffeId: IDP_SPIFFE_ID },
      'smtp-service': { roles: ['writer'], spiffeId: spiffe.forService(TRUST_DOMAIN, 'smtp').uri },
    },
    trustDomain: TRUST_DOMAIN,

    admission: {
      controlPrincipal: 'idp-service',
      controlSpiffeId: IDP_SPIFFE_ID,
      bootstrapSecret: controlSecret,
      bootstrapIdentity,
      // Short for the demo. The production default is 120 000: long enough for a slow IdP
      // start, short enough that an installed-but-uncommitted identity does not linger.
      holdMs: 30_000,
    },

    enrollment: {
      // In production this is createIdpCaBackend(...) and carries the CSR to the IdP over
      // HTTP. Here the IdP's CA is in the same process, so it is passed directly -- but note
      // that it is still the IDP's CA, not one this database owns.
      caBackend: idpCa,
      attestor: createCompositeAttestor([
        createSharedSecretAttestor({
          enrolments: {
            'smtp-service': {
              secret: smtpEnrolmentSecret,
              subject: { CN: 'smtp-service', O: 'fitfak' },
              spiffeId: spiffe.forService(TRUST_DOMAIN, 'smtp').uri,
              altNames: [spiffe.forService(TRUST_DOMAIN, 'smtp').uri, 'smtp.internal.fitfak.net'],
              roles: ['writer'],
              maxUses: 1, // renewal goes through mTLS, so once is genuinely enough
            },
          },
        }),
        createRenewalAttestor({ trustDomain: TRUST_DOMAIN, roleResolver: () => ['writer'] }),
      ]),
    },
  });

  server.on('enrolled', (e) => say(`  [server] issued '${e.principal}' via ${e.method}`));
  server.on('enrolmentDenied', (e) => say(`  [server] denied '${e.serviceName}': ${e.reason}`));
  server.on('admissionOpened', (e) => say(`  [server] OPEN -- '${e.principal}' connected with mTLS`));
  server.on('admissionSealed', (e) => say(`  [server] SEALED -- ${e.reason}`));

  server.listen(0, {
    host: '127.0.0.1',
    tls: {
      key: bootstrapIdentity.key,
      cert: bootstrapIdentity.cert,
      ca: bootstrapIdentity.ca,
      requestCert: true,
      rejectUnauthorized: false,
    },
  });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;

  say(`listening on ${target}`);
  say(`admission state: ${server.gate.state}`);
  say(`bootstrap fingerprint ${bootstrapIdentity.fingerprint256}`);

  // ---------------------------------------------------------------------------------------
  step(4, 'A service that tries to connect first is refused -- and told why');

  const smtpEarly = await tryEnrol({
    target, csrProvider, secret: smtpEnrolmentSecret, anchor: throwaway.ca.fingerprint256,
  });
  say(`smtp-service enrolment: ${smtpEarly}`);
  say('Not a transient error. Nothing gets in before the identity provider does.');

  // ---------------------------------------------------------------------------------------
  step(5, 'The IdP mints the database a server identity and installs it');

  // Signed directly rather than through a CSR: the IdP owns this CA, so there is no second
  // party whose key possession needs proving. A registration authority asking on someone
  // else's behalf is the case that needs a CSR, and that is the /pki/ra/issue path.
  const dbServerKey = await csrProvider.generateKeyPair();
  const dbServerCert = idpCa.issueDirect({
    subject: { CN: 'localhost', O: 'fitfak' },
    spkiDer: dbServerKey.publicKey.export({ type: 'spki', format: 'der' }),
    altNames: ['localhost', '127.0.0.1'],
    eku: ['serverAuth'],
    validityDays: 90,
  });
  const provisioned = await provisionServerIdentity({
    target,
    bootstrapSecret: controlSecret,
    serverIdentity: {
      certPem: dbServerCert.certPem,
      privateKeyPem: dbServerKey.privateKeyPem,
      chainPem: [idpCa.ca.certPem],
    },
    // What the database will validate CLIENT certificates against from now on. It arrives from
    // the IdP rather than from local configuration, because "whose certificates do I believe"
    // and "who is my identity provider" are the same question and should have one answer.
    trustAnchorsPem: [idpCa.ca.certPem],
    controlSpiffeId: IDP_SPIFFE_ID,
    pinnedFingerprints: [bootstrapIdentity.fingerprint256],
    logger: { info: (m) => say(m) },
  });

  say(`admission state: ${provisioned.state}`);
  say('The private key just crossed the wire. That is why the control plane authenticates in');
  say('BOTH directions: the IdP verified the database holds the shared secret BEFORE sending');
  say('anything. Without that step an interceptor receives the key and can impersonate the');
  say('database from then on.');

  // ---------------------------------------------------------------------------------------
  step(6, 'Still closed. Provisioning is not admission.');

  say(`admission state: ${server.gate.state}`);
  const smtpStillDenied = await tryEnrol({
    target, csrProvider, secret: smtpEnrolmentSecret, anchor: idpCa.ca.fingerprint256,
  });
  say(`smtp-service enrolment: ${smtpStillDenied}`);
  say(`re-seals at ${new Date(provisioned.holdExpiresAt).toISOString()} if the IdP stops here`);

  // ---------------------------------------------------------------------------------------
  step(7, "The IdP connects with its own client certificate. THIS is what opens the database.");

  const idpKey = await csrProvider.generateKeyPair();
  const idpCert = idpCa.issueDirect({
    subject: { CN: 'idp-service', O: 'fitfak' },
    spkiDer: idpKey.publicKey.export({ type: 'spki', format: 'der' }),
    altNames: [IDP_SPIFFE_ID],
    eku: ['clientAuth'],
    validityDays: 1,
  });

  // resume(), not enroll(): the IdP owns the CA, so asking this database to arrange a
  // certificate for it would be asking for something it already has.
  const identity = await resume({
    target,
    certPem: idpCert.certPem,
    privateKeyPem: idpKey.privateKeyPem,
    chainPem: [idpCa.ca.certPem],
    principal: 'idp-service',
    roles: ['admin'],
    csrProvider,
  });

  const handle = await connectDatabase({ target, identity });
  const who = await handle.whoAmI();
  say(`the server sees: ${who.principal} (${who.securityLevel}), permissions ${who.permissions}`);
  say(`admission state: ${server.gate.state}`);

  // ---------------------------------------------------------------------------------------
  step(8, 'Now everything else works');

  const smtp = await enroll({
    target,
    serviceName: 'smtp-service',
    csrProvider,
    trust: { pinnedFingerprints: [idpCa.ca.fingerprint256] },
    bootstrap: { secret: smtpEnrolmentSecret },
    subject: { CN: 'smtp-service', O: 'fitfak' },
    altNames: [spiffe.forService(TRUST_DOMAIN, 'smtp').uri, 'smtp.internal.fitfak.net'],
    logger: { info: (m) => say(m), warn: (m) => say(m) },
  });
  say(`smtp-service enrolled as ${smtp.principal}, roles ${smtp.roles.join(', ')}`);
  say(`certificate expires ${new Date(smtp.notAfter).toISOString()}`);
  say(`renewal due         ${new Date(smtp.renewAfter).toISOString()}`);
  smtp.startAutoRenewal();

  // ---------------------------------------------------------------------------------------
  step(9, 'Using the database over the upgraded channel');

  const { dbId, clientSecret } = await handle.createDatabase('kimlik');
  say(`created database ${dbId}`);
  say('clientSecret is returned exactly once and never persisted server-side.');

  const db = await handle.openDatabase({ dbId, clientSecret });
  await db.defineCollection('kullanicilar', {
    title: 'Kullanıcılar',
    fields: [
      // Blind: equality lookups without a plaintext-searchable table of addresses.
      { no: 2, name: 'email', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'displayName', type: 'string' },
      { no: 4, name: 'tenant', type: 'string', index: true },
      { no: 5, name: 'createdAt', type: 'int64', rangeBucket: { width: 86400000 }, diskBacked: true },
    ],
  });

  const users = db.collection('kullanicilar');
  await users.insert({ email: 'aybars@fitfak.net', displayName: 'Aybars', tenant: 'core', createdAt: Date.now() });
  say(`lookup by blind-indexed email: ${(await users.findOne('email', 'aybars@fitfak.net')).displayName}`);

  // ---------------------------------------------------------------------------------------
  step(10, 'Certificates, keys and DNS in the same encrypted store');

  const localDb = server.manager.getOpenDatabase(dbId);

  const vault = await SecretStore.open(localDb);
  await vault.putCertificate({
    name: 'db.fitfak.net',
    certPem: dbServerCert.certPem,
    privateKeyPem: dbServerKey.privateKeyPem,
    chainPem: [idpCa.ca.certPem],
  });
  const pair = await vault.getCertificatePair('db.fitfak.net');
  say(`stored certificate expires ${new Date(pair.notAfter).toISOString()} (read from the certificate itself)`);

  const dns = await DnsStore.open(localDb);
  await dns.put({ zone: 'internal.fitfak.net', name: 'internal.fitfak.net', type: 'SOA', ttl: 3600, rdata: { mname: 'ns1.internal.fitfak.net', rname: 'ops.fitfak.net', serial: 1 } });
  await dns.put({ zone: 'internal.fitfak.net', name: 'idp.internal.fitfak.net', type: 'A', ttl: 300, rdata: { address: '10.0.0.20' } });
  const zone = await dns.zoneCache('internal.fitfak.net');
  say(`zone cache holds ${zone.size} record(s); answers come from memory`);

  // ---------------------------------------------------------------------------------------
  step(11, 'An operator can shut the door on a running database');

  server.gate.seal('the identity provider is believed compromised');
  say(`admission state: ${server.gate.state}`);
  say('An incident where the IdP is suspect is exactly the case where "stop admitting anyone');
  say('until this is sorted out" is the right action, and it should not need a restart.');

  // ---------------------------------------------------------------------------------------
  step(12, 'Shutting down');

  zone.stop();
  handle.close();
  identity.close();
  smtp.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  say('done');
}

/** Attempts an enrolment and reports what came back, rather than throwing. */
async function tryEnrol({ target, csrProvider, secret, anchor }) {
  try {
    const identity = await enroll({
      target,
      serviceName: 'smtp-service',
      csrProvider,
      trust: { pinnedFingerprints: [anchor] },
      bootstrap: { secret },
      subject: { CN: 'smtp-service', O: 'fitfak' },
      altNames: [spiffe.forService(TRUST_DOMAIN, 'smtp').uri],
    });
    identity.close();
    return 'SUCCEEDED (unexpected)';
  } catch (err) {
    return `refused -- ${err.message}`;
  }
}

main().then(() => process.exit(0), (err) => { console.error('\nFAILED:', err); process.exit(1); });
