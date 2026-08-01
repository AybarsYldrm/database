'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');

const { requireGrpc } = require('./helpers/require-grpc');
requireGrpc();

const { DatabaseManager } = require('../src/database-manager');
const { ClientSecretKeyProvider } = require('../src/key-provider');
const { AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK } = require('../src/rbac');
const { SnowflakeGenerator } = require('../src/snowflake');
const { createDatabaseServer } = require('../src/grpc/server');
const { connectDatabase } = require('../src/grpc/client');
const { enroll } = require('../src/provisioning/enrollment-client');
const {
  createSharedSecretAttestor, createRenewalAttestor, createCompositeAttestor, generateEnrolmentSecret,
} = require('../src/provisioning/attestor');
const { createTestCaBackend, createTestCsrProvider, createServerIdentity } = require('./helpers/test-pki');

// One server, several clients, all of them active at the same time.
//
// Everything here failed before the concurrency work: the engine was written as if exactly one
// caller could ever be opening a database, defining a collection or reading a segment, and a
// second service arriving turned each of those check-then-act sequences into a race. The most
// damaging one leaked a file handle per concurrent request, which is invisible until the
// process hits its descriptor limit and then stops answering EVERY client at once -- including
// the one that had been working fine -- with a restart as the only cure.

let checks = 0;
function check(name, condition) {
  if (!condition) throw new Error(`FAILED: ${name}`);
  checks++;
  console.log(`  ok ${name}`);
}

const fdCount = () => (fs.existsSync('/proc/self/fd') ? fs.readdirSync('/proc/self/fd').length : null);

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-multi-client');
  await fsp.rm(baseDir, { recursive: true, force: true });

  console.log('\n[1] ADMIN implies every other permission, in both authorisation checks');
  {
    const acl = new AccessControlList('idp-service');
    acl.grant('smtp-service', DB_PERMISSIONS.ADMIN);
    // DatabaseManager.openDatabase gates on can(); identity.js's requirePermission has always
    // treated ADMIN as full control. When the two disagreed, granting a second service ADMIN
    // produced a principal that could not open the database it now administered.
    check('an ADMIN grant satisfies READ', acl.can('smtp-service', DB_PERMISSIONS.READ));
    check('and WRITE', acl.can('smtp-service', DB_PERMISSIONS.WRITE));
    check('and CREATE_COLLECTION', acl.can('smtp-service', DB_PERMISSIONS.CREATE_COLLECTION));
    check('the stored grant is still reported verbatim', acl.maskFor('smtp-service') === DB_PERMISSIONS.ADMIN);
    check('while the effective grant is the full mask', acl.effectiveMaskFor('smtp-service') === OWNER_DEFAULT_MASK);

    acl.revoke('smtp-service', DB_PERMISSIONS.ADMIN);
    check('revoking ADMIN takes away what it implied', acl.maskFor('smtp-service') === 0);
    check('an absent principal has nothing', acl.effectiveMaskFor('nobody') === 0);
  }

  console.log('\n[2] Ids stay unique when the clock steps backwards');
  {
    const snowflake = new SnowflakeGenerator({ workerId: 1 });
    const realNow = Date.now;
    const seen = new Set();
    let fake = realNow();
    Date.now = () => fake;
    try {
      for (let i = 0; i < 500; i++) seen.add(snowflake.nextIdString());
      fake -= 5000; // NTP correction, VM restore, an operator setting the clock
      for (let i = 0; i < 500; i++) seen.add(snowflake.nextIdString());
    } finally {
      Date.now = realNow;
    }
    // These ids are the primary keys of every collection that does not supply its own, and a
    // repeated key does not fail -- it overwrites the earlier record.
    check('1000 ids across a 5s backwards clock step are all distinct', seen.size === 1000);
  }

  console.log('\n[3] Concurrent opens converge on one handle instead of racing');
  let dbId; let clientSecret;
  {
    let manager = new DatabaseManager({ baseDir });
    const created = await manager.createDatabase({ ownerId: 'idp-service', name: 'ortak' });
    dbId = created.dbId;
    clientSecret = created.clientSecret;
    await created.db.defineCollectionAsync('kayitlar', {
      fields: [
        { no: 2, name: 'key', type: 'string', blindIndex: true, required: true },
        { no: 3, name: 'value', type: 'string' },
      ],
    });
    for (let i = 0; i < 20; i++) await created.db.collection('kayitlar').insert({ key: `seed-${i}`, value: `v${i}` });
    await manager.closeDatabase(dbId);

    const secret = Buffer.from(clientSecret, 'base64');
    manager = new DatabaseManager({ baseDir });
    const before = fdCount();
    const handles = await Promise.all(Array.from({ length: 40 }, () => manager.openDatabase({
      ownerId: 'idp-service', dbId, requesterId: 'idp-service',
      keyProvider: new ClientSecretKeyProvider(secret), requiredPermission: DB_PERMISSIONS.READ,
    })));

    check('40 concurrent opens all return the same Database', handles.every((h) => h === handles[0]));
    check('and it is the one the manager tracks', handles[0] === manager.getOpenDatabase(dbId));

    // Two handles over one directory each track their own activeSegmentOffset, so writes
    // through the loser recorded locations that did not match the file and reads came back as
    // AEAD authentication failures.
    await handles[0].collection('kayitlar').insert({ key: 'after-race', value: 'ok' });
    const readBack = [];
    for await (const record of handles[0].collection('kayitlar').scan()) readBack.push(record);
    check('every record still decrypts after the concurrent opens', readBack.length === 21);

    await manager.closeDatabase(dbId);
    const after = fdCount();
    if (before !== null) {
      // The orphaned handles were unreachable, so closeDatabase() could not close them and
      // their descriptors survived until garbage collection.
      check(`closing the database gives every descriptor back (${before} -> ${after})`, after <= before);
    }

    // A wrong secret must be refused even when the database is already open for someone else.
    manager = new DatabaseManager({ baseDir });
    await manager.openDatabase({
      ownerId: 'idp-service', dbId, requesterId: 'idp-service',
      keyProvider: new ClientSecretKeyProvider(secret), requiredPermission: DB_PERMISSIONS.READ,
    });
    await assert.rejects(
      () => manager.openDatabase({
        ownerId: 'idp-service', dbId, requesterId: 'idp-service',
        keyProvider: new ClientSecretKeyProvider(Buffer.alloc(32, 7)), requiredPermission: DB_PERMISSIONS.READ,
      }),
      (err) => /authenticate/i.test(err.message),
    );
    check('a wrong clientSecret is refused on an already-open database', true);
    await manager.closeDatabase(dbId);
  }

  console.log('\n[4] Two enrolled services against one server');
  const caBackend = createTestCaBackend();
  const csrProvider = createTestCsrProvider();
  const serverIdentity = createServerIdentity(caBackend);
  const secrets = {
    'idp-service': generateEnrolmentSecret(),
    'smtp-service': generateEnrolmentSecret(),
  };

  const server = createDatabaseServer({
    baseDir,
    principals: {
      'idp-service': { roles: ['admin'] },
      'smtp-service': { roles: ['admin'] },
    },
    enrollment: {
      caBackend,
      attestor: createCompositeAttestor([
        createSharedSecretAttestor({
          enrolments: {
            'idp-service': { secret: secrets['idp-service'], subject: { CN: 'idp-service' }, roles: ['admin'] },
            'smtp-service': { secret: secrets['smtp-service'], subject: { CN: 'smtp-service' }, roles: ['admin'] },
          },
        }),
        createRenewalAttestor({ roleResolver: () => ['admin'] }),
      ]),
    },
  });
  server.listen(0, { host: '127.0.0.1', tls: serverIdentity.tlsOptions });
  await new Promise((resolve) => server.app.server.server.once('listening', resolve));
  const target = `https://localhost:${server.address().port}`;

  // Both bootstrap at the same time, which is what happens when a stack comes up together.
  const [idp, smtp] = await Promise.all(['idp-service', 'smtp-service'].map((serviceName) => enroll({
    target, serviceName, csrProvider,
    trust: { pinnedFingerprints: [caBackend.ca.fingerprint256] },
    bootstrap: { secret: secrets[serviceName] },
  })));
  check('both services enrol concurrently', idp.principal === 'idp-service' && smtp.principal === 'smtp-service');

  const idpHandle = await connectDatabase({ target, identity: idp });
  const smtpHandle = await connectDatabase({ target, identity: smtp });

  console.log('\n[5] A shared database, granted with ADMIN and actually usable');
  const shared = await idpHandle.createDatabase('ortak');
  const idpDb = await idpHandle.openDatabase({ dbId: shared.dbId, clientSecret: shared.clientSecret });
  await idpDb.defineCollection('kayitlar', {
    fields: [
      { no: 2, name: 'key', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'value', type: 'string' },
      { no: 4, name: 'at', type: 'int64' },
    ],
  });
  await idpDb.grantAccess('smtp-service', DB_PERMISSIONS.ADMIN);

  const smtpDb = await smtpHandle.openDatabase({
    dbId: shared.dbId, clientSecret: shared.clientSecret, ownerId: shared.ownerId,
  });
  check('the second service can open the database it was made an admin of', !!smtpDb);
  check('and write to it', typeof (await smtpDb.collection('kayitlar').insert({ key: 'smtp-first', value: 'x', at: Date.now() })) === 'string');

  console.log('\n[6] An ACL grant survives a later manifest write');
  {
    // GrantAccess used to persist a throwaway copy of the manifest, leaving the database's own
    // manifest.acl holding the pre-grant table; the next thing to persist for any other reason
    // wrote that stale copy back and silently undid the grant on disk.
    await idpDb.defineCollection('ikinci', { fields: [{ no: 2, name: 'k', type: 'string' }] });
    const dir = path.join(baseDir, shared.ownerId, shared.dbId);
    const manager = new DatabaseManager({ baseDir });
    const reopened = await manager.openDatabase({
      ownerId: shared.ownerId, dbId: shared.dbId, requesterId: 'smtp-service',
      keyProvider: new ClientSecretKeyProvider(Buffer.from(shared.clientSecret, 'base64')),
      requiredPermission: DB_PERMISSIONS.WRITE,
    });
    check('the grant is still on disk after an unrelated collection was defined',
      reopened.acl.can('smtp-service', DB_PERMISSIONS.WRITE));
    check('read from the persisted manifest, not from memory', fs.existsSync(path.join(dir, 'manifest.bin')));
    await manager.closeDatabase(shared.dbId);
  }

  console.log('\n[7] Both services hammer the same collection at once');
  {
    const before = fdCount();
    async function writer(tag, db, rounds) {
      const collection = db.collection('kayitlar');
      for (let i = 0; i < rounds; i++) {
        const id = await collection.insert({ key: `${tag}-${i}`, value: 'v'.repeat(120), at: Date.now() });
        const fetched = await collection.get(id);
        if (!fetched || fetched.value.length !== 120) throw new Error(`${tag}: record ${id} did not survive the round trip`);
        if (!(await collection.findOne('key', `${tag}-${i}`))) throw new Error(`${tag}: blind index missed ${tag}-${i}`);
      }
    }
    await Promise.all([writer('idp', idpDb, 40), writer('smtp', smtpDb, 40)]);
    check('80 interleaved writes from two clients all land', await idpDb.collection('kayitlar').count() === 81);

    const seen = [];
    for await (const record of smtpDb.collection('kayitlar').scan({ pageSize: 25 })) seen.push(record);
    check('and every one of them reads back through the other client', seen.length === 81);

    const after = fdCount();
    if (before !== null) {
      // The read-FD pool had the same check-then-act as openDatabase: two readers missing on
      // the same segment both opened it and the second overwrote the first in the pool.
      check(`the descriptor count is stable under concurrent reads (${before} -> ${after})`, after - before <= 4);
    }
  }

  console.log('\n[8] Concurrent schema changes on one collection');
  {
    const fields = [
      { no: 2, name: 'key', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'value', type: 'string' },
      { no: 4, name: 'at', type: 'int64' },
      { no: 5, name: 'tenant', type: 'string', index: true },
    ];
    // Two clients applying the same migration simultaneously: one applies it, the other finds
    // nothing left to do. Neither may run a rebuild while the other is mid-flight.
    const [a, b] = await Promise.all([
      idpDb.defineCollection('kayitlar', { fields }),
      smtpDb.defineCollection('kayitlar', { fields }),
    ]);
    check('exactly one of the two concurrent migrations reports a change', (a.migrated ? 1 : 0) + (b.migrated ? 1 : 0) === 1);
    const id = await idpDb.collection('kayitlar').insert({ key: 'tenant-test', value: 'y', at: Date.now(), tenant: 'core' });
    check('the new field is written and indexed', (await smtpDb.collection('kayitlar').find('tenant', 'core')).length === 1);
    check('and reads back', String((await smtpDb.collection('kayitlar').get(id)).key) === 'tenant-test');
  }

  console.log('\n[9] A watch snapshot larger than one wire message');
  {
    const bulk = await idpHandle.createDatabase('buyuk');
    const bulkDb = await idpHandle.openDatabase({ dbId: bulk.dbId, clientSecret: bulk.clientSecret });
    await bulkDb.defineCollection('kayitlar', {
      fields: [{ no: 2, name: 'key', type: 'string', required: true }, { no: 3, name: 'blob', type: 'string' }],
    });
    // ~6 MB of records: past the transport's 4 MiB per-message ceiling, which used to kill the
    // stream with RESOURCE_EXHAUSTED and send the client into a reconnect loop that
    // re-decrypted the entire collection on every pass and never made progress.
    const blob = 'z'.repeat(4096);
    const collection = bulkDb.collection('kayitlar');
    for (let i = 0; i < 1500; i++) await collection.insert({ key: `k${i}`, blob });

    const view = collection.watch();
    const failures = [];
    view.on('warning', (err) => failures.push(err));
    await Promise.race([
      view.ready(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('the watch never became ready')), 30000).unref()),
    ]);
    check('a multi-megabyte snapshot arrives in chunks and lands whole', view.size === 1500);
    check('with no stream failures on the way', failures.length === 0);
    check('and the view reports itself fresh', view.fresh === true);

    const newId = await collection.insert({ key: 'canli', blob: 'q' });
    await waitFor(() => view.size === 1501, 5000);
    check('live changes still follow the chunked snapshot', view.get(newId)?.key === 'canli');
    view.stop();
    await bulkDb.close();
  }

  console.log('\n[10] A watcher that vanishes mid-snapshot does not strand the server');
  {
    const database = server.manager.getOpenDatabase(shared.dbId);
    const before = database.changes.subscriberCount('kayitlar');
    for (let i = 0; i < 5; i++) {
      const view = idpDb.collection('kayitlar').watch();
      view.on('warning', () => {});
      // Cancelled immediately, so some of these die while the snapshot is still being built --
      // the case where 'cancelled' fired before the handler was listening for it, leaving the
      // handler awaiting an event that could never come again, along with its change-stream
      // subscription and its keepalive timer.
      view.stop();
    }
    await waitFor(() => database.changes.subscriberCount('kayitlar') <= before, 10000);
    check('every abandoned watch releases its subscription', database.changes.subscriberCount('kayitlar') <= before);
  }

  idpHandle.close();
  smtpHandle.close();
  await server.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - multi client: ${checks} checks passed.`);
}

async function waitFor(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
