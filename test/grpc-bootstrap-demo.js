'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');

const { requireGrpc } = require('./helpers/require-grpc');
const { GrpcClient, GRPC_STATUS } = requireGrpc();
const { createDatabaseServer } = require('../src/grpc/server');
const { connectDatabase } = require('../src/grpc/client');
const { enroll, TrustError } = require('../src/provisioning/enrollment-client');
const { createSharedSecretAttestor, createRenewalAttestor, createCompositeAttestor, generateEnrolmentSecret } = require('../src/provisioning/attestor');
const { createCustomCaBackend } = require('../src/provisioning/ca-backend');
const { DATABASE_SCHEMAS } = require('../src/grpc/schemas');
const { DB_PERMISSIONS, combine } = require('../src/rbac');
const { createTestCaBackend, createTestCsrProvider, createServerIdentity, generateKeyPair, createCsr } = require('./helpers/test-pki');

// End-to-end exercise of the deployment this package is built for:
//
//   a service with no certificate  ->  bootstrap TLS  ->  enrol  ->  mTLS  ->  data plane
//
// The database server is the Registration Authority: it authenticates the bootstrapping peer
// and decides what identity it may hold, but the certificate itself is signed by the CA
// backend (here a local test CA; in production the central ACME authority or @fitfak/ssl).

let checks = 0;
function check(name, condition) {
  if (!condition) throw new Error(`FAILED: ${name}`);
  checks++;
  console.log(`  ok ${name}`);
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-grpc-bootstrap');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const caBackend = createTestCaBackend();
  const csrProvider = createTestCsrProvider();
  const serverIdentity = createServerIdentity(caBackend);

  // Bootstrap credentials are provisioned out of band -- a sealed config value, an operator
  // pasting it once. They never cross the wire; only an HMAC over them does.
  const idpSecret = generateEnrolmentSecret();
  const resolverSecret = generateEnrolmentSecret();

  const attestor = createCompositeAttestor([
    createSharedSecretAttestor({
      enrolments: {
        'idp-service': {
          secret: idpSecret,
          subject: { CN: 'idp-service', O: 'fitfak' },
          altNames: ['idp.internal.fitfak.net'],
          roles: ['admin'],
        },
        'dns-resolver': {
          secret: resolverSecret,
          subject: { CN: 'dns-resolver', O: 'fitfak' },
          roles: ['reader'],
          // This test enrols the resolver twice (once at the wire level to prove channel
          // binding works, once through the client API) and then checks that a third attempt
          // is refused. One use is the default and the right value in production.
          maxUses: 2,
        },
      },
    }),
    createRenewalAttestor(),
  ]);

  const server = createDatabaseServer({
    baseDir,
    principals: {
      // The allow-list is also the revocation mechanism at this layer: removing an entry
      // locks that certificate out on its next connection, however long it stays valid.
      'idp-service': { roles: ['admin'] },
      'dns-resolver': { roles: ['reader'] },
    },
    enrollment: {
      caBackend,
      attestor,
      renewalAttestor: createRenewalAttestor({ roleResolver: () => ['admin'] }),
      serverName: 'fitdb-test',
    },
  });

  const issuedEvents = [];
  server.on('enrolled', (event) => issuedEvents.push(event));

  server.listen(0, { host: '127.0.0.1', tls: serverIdentity.tlsOptions });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;

  console.log('\n[1] Before enrolment, the data plane is unreachable');
  {
    const anonymous = new GrpcClient(target, { credentials: { ca: caBackend.ca.certPem } });
    await assert.rejects(
      () => anonymous.unary(`/custom.network.DatabaseService/WhoAmI`, DATABASE_SCHEMAS,
        'DatabaseService_WhoAmIReq', 'DatabaseService_WhoAmIRes', {}, { retry: { maxAttempts: 1 } }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED,
    );
    check('a client with no certificate cannot call DatabaseService', true);

    // ...but the enrolment endpoint is reachable, which is the whole point.
    const anchors = await anonymous.unary('/custom.network.EnrollmentService/GetTrustAnchors',
      require('../src/provisioning/enrollment-service').ENROLMENT_SCHEMAS,
      'EnrollmentService_GetTrustAnchorsReq', 'EnrollmentService_GetTrustAnchorsRes', {});
    check('GetTrustAnchors is reachable on the bootstrap channel', anchors.chainPem.length === 1);
    check('it returns the CA fingerprint for pinning', anchors.fingerprints[0] === caBackend.ca.fingerprint256);
    check('and reports that channel binding is available', anchors.channelBindingSupported === true);
    anonymous.close();
  }

  console.log('\n[2] Bootstrapping without any way to verify the server is refused');
  {
    await assert.rejects(
      () => enroll({ target, serviceName: 'idp-service', csrProvider, trust: {}, bootstrap: { secret: idpSecret } }),
      // Silently falling back to an unverified connection here would mean handing an
      // enrolment credential to whoever answered on that address.
      (err) => err instanceof TrustError,
    );
    check('no CA, no pin and no explicit opt-in is a hard error', true);

    await assert.rejects(
      () => enroll({
        target, serviceName: 'idp-service', csrProvider,
        trust: { pinnedFingerprints: ['AA:BB:CC'] },
        bootstrap: { secret: idpSecret },
      }),
      (err) => err instanceof TrustError && /No enrolment credential was sent/.test(err.message),
    );
    check('a wrong pin aborts before any credential is sent', true);
  }

  console.log('\n[3] Enrolment over the bootstrap channel, then upgrade to mTLS');
  let idp;
  {
    idp = await enroll({
      target,
      serviceName: 'idp-service',
      csrProvider,
      // Pinning the CA fingerprint rather than shipping the bundle: enough to authenticate
      // the server on first contact, and it survives a server-certificate rotation.
      trust: { pinnedFingerprints: [caBackend.ca.fingerprint256] },
      bootstrap: { secret: idpSecret },
      altNames: ['idp.internal.fitfak.net'],
    });

    check('enrolment returns the claimed principal', idp.principal === 'idp-service');
    check('with the roles the attestor granted', idp.roles.includes('admin'));
    check('the channel is now mutually authenticated', idp.client.channelInfo().mutual === true);
    check('a renewal deadline is advertised', idp.renewAfter > Date.now() && idp.renewAfter < idp.notAfter);

    const issuedCert = new crypto.X509Certificate(idp.certPem);
    check('the issued certificate carries the requested SAN', issuedCert.subjectAltName.includes('idp.internal.fitfak.net'));
    check('and chains to the CA', issuedCert.verify(new crypto.X509Certificate(caBackend.ca.certPem).publicKey));
    check('the server recorded the issuance', issuedEvents.length === 1 && issuedEvents[0].principal === 'idp-service');

    const who = await idp.client.unary('/custom.network.DatabaseService/WhoAmI', DATABASE_SCHEMAS,
      'DatabaseService_WhoAmIReq', 'DatabaseService_WhoAmIRes', {});
    check('the data plane now identifies us from the certificate', who.principal === 'idp-service');
    check('at mtls security level', who.securityLevel === 'mtls');
    check('with the permissions its role maps to', who.permissions > 0);
  }

  console.log('\n[4] The bootstrap credential is single-use');
  {
    await assert.rejects(
      () => enroll({
        target, serviceName: 'idp-service', csrProvider,
        trust: { pinnedFingerprints: [caBackend.ca.fingerprint256] },
        bootstrap: { secret: idpSecret },
      }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED,
    );
    // A bootstrap secret that stays valid forever is a permanent backdoor into the identity
    // system; renewal goes through the mTLS path instead, which needs no secret at all.
    check('replaying a consumed enrolment credential is rejected', true);
  }

  console.log('\n[5] A CSR may not ask for an identity the credential does not authorise');
  {
    const keyPair = generateKeyPair();
    // The credential is for 'dns-resolver'; the CSR claims to be the IdP.
    const escalating = createCsr({ keyPair, subject: { CN: 'idp-service', O: 'fitfak' } });
    const bootstrapClient = new GrpcClient(target, { credentials: { ca: caBackend.ca.certPem } });
    await bootstrapClient.connect();

    const { computeEnrolmentProof } = require('../src/provisioning/attestor');
    const nonce = crypto.randomBytes(16).toString('base64');
    const timestamp = Date.now();
    const proof = computeEnrolmentProof(resolverSecret, {
      serviceName: 'dns-resolver', nonce, timestamp,
      channelBinding: bootstrapClient.channelBinding(), csrPem: escalating,
    }).toString('base64');

    await assert.rejects(
      () => bootstrapClient.unary('/custom.network.EnrollmentService/Enroll',
        require('../src/provisioning/enrollment-service').ENROLMENT_SCHEMAS,
        'EnrollmentService_EnrollReq', 'EnrollmentService_EnrollRes',
        { serviceName: 'dns-resolver', csrPem: escalating, nonce, timestamp: BigInt(timestamp), proof },
        { retry: { maxAttempts: 1 } }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED && /only authorises CN='dns-resolver'/.test(err.message),
    );
    check('a valid credential cannot be redeemed for a different identity', true);
    bootstrapClient.close();
  }

  console.log('\n[6] An enrolment proof cannot be replayed onto another connection');
  {
    const keyPair = generateKeyPair();
    const csrPem = createCsr({ keyPair, subject: { CN: 'dns-resolver', O: 'fitfak' } });

    const first = new GrpcClient(target, { credentials: { ca: caBackend.ca.certPem } });
    await first.connect();
    const { computeEnrolmentProof } = require('../src/provisioning/attestor');
    const nonce = crypto.randomBytes(16).toString('base64');
    const timestamp = Date.now();
    // Built over the FIRST connection's channel binding...
    const proof = computeEnrolmentProof(resolverSecret, {
      serviceName: 'dns-resolver', nonce, timestamp,
      channelBinding: first.channelBinding(), csrPem,
    }).toString('base64');

    // ...and presented on a SECOND one, which is what an interposing proxy would do.
    const second = new GrpcClient(target, { credentials: { ca: caBackend.ca.certPem } });
    await second.connect();
    await assert.rejects(
      () => second.unary('/custom.network.EnrollmentService/Enroll',
        require('../src/provisioning/enrollment-service').ENROLMENT_SCHEMAS,
        'EnrollmentService_EnrollReq', 'EnrollmentService_EnrollRes',
        { serviceName: 'dns-resolver', csrPem, nonce, timestamp: BigInt(timestamp), proof },
        { retry: { maxAttempts: 1 } }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED,
    );
    check('RFC 9266 channel binding defeats the relay', true);

    // The same proof on its own connection is accepted, proving the rejection above was the
    // binding and not something incidental about the request.
    const accepted = await first.unary('/custom.network.EnrollmentService/Enroll',
      require('../src/provisioning/enrollment-service').ENROLMENT_SCHEMAS,
      'EnrollmentService_EnrollReq', 'EnrollmentService_EnrollRes',
      { serviceName: 'dns-resolver', csrPem, nonce, timestamp: BigInt(timestamp), proof });
    check('the same proof on its own connection is accepted', accepted.principal === 'dns-resolver');
    first.close();
    second.close();
  }

  console.log('\n[7] Renewal over mTLS needs no bootstrap credential');
  {
    const before = idp.certPem;
    const beforeKey = idp.privateKeyPem;
    await idp.renew();
    check('the certificate is replaced', idp.certPem !== before);
    // Renewing onto the same key would carry any past exposure forward for another full
    // lifetime, so a fresh key pair is generated every time.
    check('on a freshly generated key', idp.privateKeyPem !== beforeKey);
    check('and the channel still works', (await idp.client.unary('/custom.network.DatabaseService/WhoAmI',
      DATABASE_SCHEMAS, 'DatabaseService_WhoAmIReq', 'DatabaseService_WhoAmIRes', {})).principal === 'idp-service');
  }

  console.log('\n[8] Database operations over the enrolled channel');
  let handle;
  let db;
  {
    handle = await connectDatabase({ target, identity: idp });
    const created = await handle.createDatabase('kimlik');
    check('CreateDatabase returns a one-time client secret', created.clientSecret.length >= 44);

    db = await handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
    const { collection } = await db.defineCollection('kullanicilar', {
      title: 'Kullanıcılar',
      fields: [
        { no: 2, name: 'email', type: 'string', blindIndex: true, required: true },
        { no: 3, name: 'displayName', type: 'string' },
        { no: 4, name: 'tenant', type: 'string', index: true },
        { no: 5, name: 'createdAt', type: 'int64' },
        { no: 6, name: 'active', type: 'bool' },
      ],
    });

    const id = await collection.insert({
      email: 'aybars@fitfak.net', displayName: 'Aybars', tenant: 'core',
      createdAt: Date.now(), active: true,
    });
    check('insert returns a Snowflake id', /^\d{15,}$/.test(id));

    const fetched = await collection.get(id);
    check('get round trips the record', fetched.displayName === 'Aybars' && fetched.active === true);
    // JSON has no int64: a Snowflake id parsed as a JSON number would come back rounded, so
    // ids and int64 fields cross the wire as strings and are coerced back by schema type.
    check('the id survives without precision loss', String(fetched._id) === id);

    const byEmail = await collection.findOne('email', 'aybars@fitfak.net');
    check('blind-index equality lookup works remotely', byEmail && String(byEmail._id) === id);

    const byTenant = await collection.find('tenant', 'core');
    check('plain index lookup works remotely', byTenant.length === 1);

    const version = await collection.update(id, { displayName: 'Aybars Y.' });
    check('update returns the new version', version === 2);

    await assert.rejects(
      () => collection.update(id, { displayName: 'x' }, { expectedVersion: 1 }),
      (err) => err.code === GRPC_STATUS.ABORTED,
    );
    check('a stale expectedVersion is refused instead of losing the other write', true);

    for (let i = 0; i < 25; i++) {
      await collection.insert({ email: `u${i}@fitfak.net`, tenant: 'bulk', createdAt: Date.now(), active: true });
    }
    check('count reflects every insert', await collection.count() === 26);

    const seen = [];
    for await (const record of collection.scan({ pageSize: 10 })) seen.push(record);
    check('scan pages transparently', seen.length === 26);

    const described = await collection.describe();
    check('DescribeCollection exposes the schema', described.fields.some((f) => f.name === 'email' && f.blindIndex));
    check('and the human-readable title', described.title === 'Kullanıcılar');

    check('delete removes the record', await collection.delete(id) === true);
    check('and it is gone', await collection.get(id) === null);
  }

  console.log('\n[9] A live view kept current by the change stream, not by polling');
  {
    const collection = db.collection('kullanicilar');
    const view = collection.watch();
    await view.ready();

    check('the view starts from a snapshot', view.size === 25);
    check('and reports itself fresh', view.fresh === true);

    const changes = [];
    view.on('change', (event) => changes.push(event));

    const newId = await collection.insert({ email: 'canli@fitfak.net', tenant: 'live', createdAt: Date.now(), active: true });
    await waitFor(() => view.size === 26, 3000);
    check('an insert reaches the view without any read', view.get(newId)?.email === 'canli@fitfak.net');

    await collection.update(newId, { email: 'canli@fitfak.net', tenant: 'live', displayName: 'güncel' });
    await waitFor(() => view.get(newId)?.displayName === 'güncel', 3000);
    check('an update is applied in place', view.get(newId).displayName === 'güncel');

    await collection.delete(newId);
    await waitFor(() => view.size === 25, 3000);
    check('a delete removes it', view.get(newId) === null);
    check('every change was observed exactly once', changes.length === 3);

    view.stop();
  }

  console.log('\n[10] Authorisation is per principal, per database');
  {
    // Enrol the second service for real, then confirm its reader role does not let it write.
    const resolver = await enroll({
      target, serviceName: 'dns-resolver', csrProvider,
      trust: { caPem: caBackend.ca.certPem },
      bootstrap: { secret: resolverSecret },
    });
    check('the second service enrolled', resolver.principal === 'dns-resolver');

    // Both configured uses are now spent. A rejected attempt earlier (step 5, wrong CN) did
    // NOT count against them -- spending a use on a request that never produced a certificate
    // would turn a recoverable mistake into a re-provisioning job.
    await assert.rejects(
      () => enroll({
        target, serviceName: 'dns-resolver', csrProvider,
        trust: { caPem: caBackend.ca.certPem }, bootstrap: { secret: resolverSecret },
      }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED,
    );
    check('the credential is refused once its uses are exhausted', true);

    const resolverHandle = await connectDatabase({ target, identity: resolver });
    const who = await resolverHandle.whoAmI();
    check('it is identified as the resolver', who.principal === 'dns-resolver');
    check('with reader permissions only', who.permissions === DB_PERMISSIONS.READ);

    await assert.rejects(
      () => resolverHandle.openDatabase({ dbId: db.dbId, clientSecret: 'AAAA' }),
      (err) => err.code === GRPC_STATUS.INVALID_ARGUMENT || err.code === GRPC_STATUS.UNAUTHENTICATED,
    );
    check('it cannot open a database without the real secret', true);

    resolverHandle.close();
  }

  console.log('\n[11] Schema evolution over the wire');
  {
    const collection = db.collection('kullanicilar');
    const current = (await collection.describe({ refresh: true })).fields.filter((f) => f.no !== 1);

    const plan = await db.defineCollection('kullanicilar', {
      fields: [...current, { no: 7, name: 'lastSeenAt', type: 'int64', index: true }],
      dryRun: true,
    });
    check('a dry run reports the change without applying it', plan.migrated && plan.changes[0].kind === 'add-field');
    check('and nothing changed', (await collection.describe({ refresh: true })).fields.every((f) => f.name !== 'lastSeenAt'));

    const applied = await db.defineCollection('kullanicilar', {
      fields: [...current, { no: 7, name: 'lastSeenAt', type: 'int64', index: true }],
    });
    check('applying it reports the migration', applied.migrated === true && applied.indexesRebuilt === true);
    check('and bumps the schema version', applied.schemaVersion === 2);

    const id = await collection.insert({ email: 'sema@fitfak.net', tenant: 'core', lastSeenAt: 1700000000000 });
    check('the new field round trips', String((await collection.get(id)).lastSeenAt) === '1700000000000');
    check('and is queryable', (await collection.find('lastSeenAt', '1700000000000')).length === 1);

    await assert.rejects(
      () => db.defineCollection('kullanicilar', { fields: current.map((f) => (f.no === 3 ? { ...f, type: 'int64' } : f)) }),
      // A refused migration is the caller's schema being wrong, not a server fault.
      (err) => err.code === GRPC_STATUS.INVALID_ARGUMENT,
    );
    check('a breaking change is refused over the wire too', true);
  }

  console.log('\n[12] An open-ended range query over the wire');
  {
    // The remote path is how @fitfak/smtp's outbound queue actually asks "what is due
    // now?", and it is where the engine's unbounded bucket probe took the whole server
    // down: findRange(field, 0, Date.now()) on a minute-width field walked ~30 million
    // buckets synchronously, so the gRPC server answered nothing at all -- to every
    // client, not just the one that asked -- for over two minutes per call.
    const MINUTE = 60_000;
    await db.defineCollection('giden_kuyruk', {
      fields: [
        { no: 2, name: 'queueId', type: 'string', index: true },
        { no: 3, name: 'nextAttemptAt', type: 'int64', rangeBucket: { width: MINUTE } },
      ],
    });
    const queue = db.collection('giden_kuyruk');

    const now = Date.now();
    await queue.insert({ queueId: 'due-a', nextAttemptAt: now - 1000 });
    await queue.insert({ queueId: 'due-b', nextAttemptAt: now - 45 * MINUTE });
    await queue.insert({ queueId: 'later', nextAttemptAt: now + 30 * MINUTE });

    const startedAt = Date.now();
    const due = await queue.findRange('nextAttemptAt', 0, now);
    const elapsed = Date.now() - startedAt;

    check('an open-ended range returns exactly the due rows', due.length === 2);
    check('the exact bound is still applied after the bucket sweep',
      due.every((r) => Number(r.nextAttemptAt) <= now));
    // The assertion that matters is the clock: the answer was always correct, it just
    // took minutes and blocked every other request while it ran.
    check(`and answers promptly rather than scanning the range (${elapsed}ms)`, elapsed < 5000);

    const capped = await queue.findRange('nextAttemptAt', 0, now, { limit: 1 });
    check('the wire-level limit caps the result set', capped.length === 1);

    // The server is still serving other calls, which is the property the stall destroyed.
    const stillAlive = await idp.client.unary('/custom.network.DatabaseService/WhoAmI',
      DATABASE_SCHEMAS, 'DatabaseService_WhoAmIReq', 'DatabaseService_WhoAmIRes', {});
    check('the server is still answering other requests', stillAlive.principal === 'idp-service');
  }

  console.log('\n[13] Capability tokens may only narrow authority');
  {
    const capability = await db.issueCapability({
      collection: 'kullanicilar',
      scope: combine(DB_PERMISSIONS.READ),
      ttlMs: 5000,
    });
    check('a narrower capability is issued', capability.token.split('.').length === 3);
    check('with an expiry in the near future', capability.expiresAt - Date.now() <= 5000);

    await assert.rejects(
      // 1 << 20 is outside DB_PERMISSIONS entirely, so no principal can ever hold it.
      () => db.issueCapability({ collection: 'kullanicilar', scope: 1 << 20, ttlMs: 5000 }),
      (err) => err.code === GRPC_STATUS.PERMISSION_DENIED,
    );
    check('a capability wider than the issuer\'s own grant is refused', true);
  }

  handle.close();
  idp.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - grpc bootstrap: ${checks} checks passed.`);
}

async function waitFor(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('timed out waiting for a condition');
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
