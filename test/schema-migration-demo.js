'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');

const { DatabaseManager, ClientSecretKeyProvider, SchemaMigrationError, diffSchemas } = require('../src');

// Schema evolution.
//
// The bug this suite pins: redefining an open collection with an extra field used to return
// the existing collection untouched. The new field was not in the in-memory schema, so the TLV
// encoder had no tag for it, every value written to it was discarded, `get()` never returned
// it and `find()` threw "no such field" -- with no error at any point. Adding a field to a
// schema registry and redeploying is completely ordinary, so it has to work or fail loudly.

let checks = 0;
function check(name, condition) {
  if (!condition) throw new Error(`FAILED: ${name}`);
  checks++;
  console.log(`  ok ${name}`);
}

// A trimmed version of a real registry, with the field numbers it actually uses.
const REGISTRY_V1 = {
  users: {
    fields: [
      { no: 2, name: 'username', type: 'string', index: true, required: true },
      { no: 3, name: 'email', type: 'string', blindIndex: true, required: true },
      { no: 4, name: 'passwordHash', type: 'string' },
      { no: 8, name: 'createdAt', type: 'uint64' },
    ],
  },
  certificates: {
    fields: [
      { no: 2, name: 'serialNumberHex', type: 'string', index: true, required: true },
      { no: 3, name: 'userId', type: 'string', index: true },
      { no: 4, name: 'subjectCn', type: 'string' },
      { no: 6, name: 'certPem', type: 'string' },
      { no: 9, name: 'status', type: 'string' },
    ],
  },
  sessions: {
    fields: [
      { no: 2, name: 'sessionId', type: 'string', index: true, required: true },
      { no: 3, name: 'userId', type: 'string', index: true },
      { no: 11, name: 'revoked', type: 'bool' },
    ],
  },
};

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-schema-migration');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir, sessionTtlMs: 120000 });
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'idp', name: 'kimlik' });
  const reopen = async () => manager.openDatabase({
    ownerId: 'idp', dbId, requesterId: 'idp',
    keyProvider: new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64')),
  });

  console.log('\n[1] A registry defines every collection');
  {
    const applied = await db.applySchemaRegistry(REGISTRY_V1);
    check('all three collections are created', Object.keys(applied).length === 3);
    check('and report no migration on first definition', applied.users.changed === false);

    await db.collection('users').insert({ username: 'aybars', email: 'a@fitfak.net', passwordHash: 'x', createdAt: BigInt(Date.now()) });
    await db.collection('certificates').insert({ serialNumberHex: 'AA01', userId: 'u1', subjectCn: 'api.fitfak.net', certPem: '-----PEM-----', status: 'valid' });
    await db.collection('certificates').insert({ serialNumberHex: 'BB02', userId: 'u2', subjectCn: 'idp.fitfak.net', certPem: '-----PEM-----', status: 'revoked' });
    check('records are stored under v1', await db.collection('certificates').count() === 2);
  }

  console.log('\n[2] Adding a field later — the case that used to be silently dropped');
  {
    await manager.closeDatabase(dbId);
    const db2 = await reopen();

    // Exactly the change described: field 14 added to an existing collection, indexed.
    const withSkid = {
      ...REGISTRY_V1.certificates,
      fields: [
        ...REGISTRY_V1.certificates.fields,
        { no: 14, name: 'skidHex', type: 'string', index: true },
      ],
    };
    const certificates = await db2.defineCollectionAsync('certificates', withSkid);

    check('the migration is reported, not silently skipped', certificates.migration.changed === true);
    check('as an added field', certificates.migration.changes[0].kind === 'add-field' && certificates.migration.changes[0].field === 'skidHex');
    // The new field is indexed, so the index has to be built from the records already stored.
    check('and the indexes are rebuilt because it is indexed', certificates.migration.rebuilt === true);
    check('the schema version is bumped', certificates.migration.schemaVersion === 2);

    const id = await certificates.insert({ serialNumberHex: 'CC03', userId: 'u3', skidHex: 'DEADBEEF', status: 'valid' });
    const stored = await certificates.get(id);
    check('the new field is actually written', stored.skidHex === 'DEADBEEF');
    check('and is queryable through its index', (await certificates.find('skidHex', 'DEADBEEF')).length === 1);

    // Records written before the field existed simply lack it -- the same as protobuf.
    const old = await certificates.findOne('serialNumberHex', 'AA01');
    check('records predating the field are still readable', old.subjectCn === 'api.fitfak.net');
    check('and report the new field as absent', old.skidHex === undefined);
    check('pre-existing indexes still resolve', (await certificates.find('userId', 'u2')).length === 1);
  }

  console.log('\n[3] The migration survives a reopen');
  {
    await manager.closeDatabase(dbId);
    const db3 = await reopen();
    const certificates = db3.collection('certificates');
    check('the field is in the schema loaded from the manifest',
      certificates.schema.some((f) => f.no === 14 && f.name === 'skidHex'));
    check('its index was persisted, not just rebuilt in memory',
      (await certificates.find('skidHex', 'DEADBEEF')).length === 1);
    check('redefining with the same fields is a no-op',
      (await db3.defineCollectionAsync('certificates', {
        fields: certificates.schema.filter((f) => f.no !== 1),
      })).migration.changed === false);
  }

  console.log('\n[4] Changes that would misread stored data are refused');
  {
    const db4 = await reopen();
    const current = db4.collection('certificates').schema.filter((f) => f.no !== 1);

    // Same wire type, different JS type: every stored record would start decoding as BigInt.
    await assert.rejects(
      () => db4.defineCollectionAsync('certificates', {
        fields: current.map((f) => (f.no === 9 ? { ...f, type: 'uint64' } : f)),
      }),
      (err) => err instanceof SchemaMigrationError && /different wire type|different JavaScript type/.test(err.message),
    );
    check('changing a field\'s type is refused', true);

    await assert.rejects(
      () => db4.defineCollectionAsync('certificates', { fields: current.filter((f) => f.no !== 4) }),
      (err) => err instanceof SchemaMigrationError && /dropFields/.test(err.message),
    );
    check('removing a field is refused unless named in dropFields', true);

    // A refusal that only says "no" makes the caller guess. The message has to name the
    // field, say why its bytes are still a problem, and give the exact opt-in.
    const message = await db4.defineCollectionAsync('certificates', { fields: current.filter((f) => f.no !== 4) })
      .then(() => '', (err) => err.message);
    check('and the message names the field, the reason and the remedy',
      message.includes('subjectCn') && /bytes remain/.test(message) && message.includes("dropFields: ['subjectCn']"));

    // Nothing was applied by the refusals.
    check('the collection is untouched after a refusal',
      db4.collection('certificates').schema.some((f) => f.name === 'subjectCn'));
    check('and its records are intact', await db4.collection('certificates').count() === 3);
  }

  console.log('\n[5] A deliberate removal reserves the number forever');
  {
    const db5 = await reopen();
    const current = db5.collection('certificates').schema.filter((f) => f.no !== 1);

    const certificates = await db5.defineCollectionAsync('certificates', {
      fields: current.filter((f) => f.no !== 4),
      dropFields: ['subjectCn'],
    });
    check('an authorised removal applies', certificates.migration.changes.some((c) => c.kind === 'remove-field'));
    check('the number is reserved', certificates.migration.reserved.includes(4));
    check('and the field is gone from reads', (await certificates.findOne('serialNumberHex', 'AA01')).subjectCn === undefined);

    // The classic protobuf hazard: months later, someone adds a new field and picks a number
    // that looks free. Records written while it was live still carry bytes under that tag and
    // would be decoded as the new field.
    await assert.rejects(
      () => db5.defineCollectionAsync('certificates', {
        fields: [...certificates.schema.filter((f) => f.no !== 1), { no: 4, name: 'issuerCn', type: 'string' }],
      }),
      (err) => err instanceof SchemaMigrationError && /previously used and retired/.test(err.message),
    );
    check('reusing a reserved number is refused', true);

    await manager.closeDatabase(dbId);
    const db5b = await reopen();
    check('the reservation survives a reopen', db5b.manifest.collections.certificates.reserved.includes(4));
  }

  console.log('\n[6] Index changes rebuild from the records');
  {
    const db6 = await reopen();
    const current = db6.collection('certificates').schema.filter((f) => f.no !== 1);

    // status was unindexed; make it a blind index. Every stored record has to end up in it.
    const certificates = await db6.defineCollectionAsync('certificates', {
      fields: current.map((f) => (f.name === 'status' ? { ...f, blindIndex: true } : f)),
    });
    check('an index change is classified as needing a rebuild', certificates.migration.rebuilt === true);
    check('and every pre-existing record is in the new index',
      (await certificates.find('status', 'valid')).length === 2);

    // A rename keeps the field number, so the bytes are untouched, but the index tables are
    // keyed by name and have to be rebuilt.
    const renamed = await db6.defineCollectionAsync('certificates', {
      fields: certificates.schema.filter((f) => f.no !== 1).map((f) => (f.no === 3 ? { ...f, name: 'ownerId' } : f)),
    });
    check('a rename is recognised as a rename, not a drop plus an add',
      renamed.migration.changes.some((c) => c.kind === 'rename-field' && c.from === 'userId'));
    check('data written under the old name reads back under the new one',
      (await renamed.findOne('serialNumberHex', 'AA01')).ownerId === 'u1');
    check('and the index follows the new name', (await renamed.find('ownerId', 'u2')).length === 1);
  }

  console.log('\n[7] Inspecting a migration without applying it');
  {
    const db7 = await reopen();
    const current = db7.collection('users').schema.filter((f) => f.no !== 1);

    const plan = db7.inspectMigration('users', [...current, { no: 10, name: 'role', type: 'string', index: true }]);
    check('a dry run reports the change', plan.changed && plan.changes[0].kind === 'add-field');
    check('and that it is applicable', plan.applicable === true);
    check('without having applied it', db7.collection('users').schema.every((f) => f.name !== 'role'));

    const blockedPlan = db7.inspectMigration('users', current.filter((f) => f.no !== 4));
    check('a refusal is visible before deploying', blockedPlan.applicable === false);
    // This is what makes it useful in a pipeline: the failure is found by CI, not by the
    // first write after a rollout.
    check('with the reason attached', /dropFields/.test(blockedPlan.blocked[0].reason));
  }

  console.log('\n[8] A registry is applied atomically or not at all');
  {
    const db8 = await reopen();
    const before = db8.collection('users').schema.length;

    const badRegistry = {
      users: { fields: [...db8.collection('users').schema.filter((f) => f.no !== 1), { no: 10, name: 'role', type: 'string' }] },
      // sessions asks for a type change, which is refused.
      sessions: { fields: db8.collection('sessions').schema.filter((f) => f.no !== 1).map((f) => (f.no === 11 ? { ...f, type: 'string' } : f)) },
    };

    await assert.rejects(() => db8.applySchemaRegistry(badRegistry), (err) => err instanceof SchemaMigrationError);
    // The whole point: `users` was applicable, but applying it while `sessions` is refused
    // would leave the application facing a schema that is half old and half new.
    check('one refused collection blocks the entire registry', db8.collection('users').schema.length === before);
    check('nothing was partially applied', db8.collection('users').schema.every((f) => f.name !== 'role'));

    const goodRegistry = { users: badRegistry.users };
    const applied = await db8.applySchemaRegistry(goodRegistry);
    check('a clean registry applies', applied.users.changed === true);
    check('and the new field works',
      (await db8.collection('users').findOne('username', 'aybars')) !== null
      && (await db8.collection('users').get((await db8.collection('users').findOne('username', 'aybars'))._id)) !== null);
  }

  console.log('\n[9] The diff itself');
  {
    const base = [{ no: 2, name: 'a', type: 'string' }];
    check('adding an unindexed field is safe',
      diffSchemas(base, [...base, { no: 3, name: 'b', type: 'string' }]).safety === 'safe');
    check('adding an indexed field needs a reindex',
      diffSchemas(base, [...base, { no: 3, name: 'b', type: 'string', index: true }]).safety === 'reindex');
    check('a type change is breaking',
      diffSchemas(base, [{ no: 2, name: 'a', type: 'int32' }]).safety === 'breaking');
    check('a removal is breaking', diffSchemas(base, []).safety === 'breaking');
    check('an identical schema reports no changes', diffSchemas(base, base).changes.length === 0);
    check('a reserved number cannot be reused',
      diffSchemas(base, [...base, { no: 5, name: 'c', type: 'string' }], [5]).safety === 'breaking');
    // Matching is by field number, so this is a rename rather than a drop plus an add.
    const renamed = diffSchemas(base, [{ no: 2, name: 'renamed', type: 'string' }]);
    check('matching is by number, so a renamed field is not a removal',
      renamed.changes.length === 1 && renamed.changes[0].kind === 'rename-field');
  }

  await manager.closeDatabase(dbId);
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - schema migration: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
