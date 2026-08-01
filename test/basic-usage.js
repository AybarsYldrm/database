'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const {
  DatabaseManager, ClientSecretKeyProvider, DB_PERMISSIONS,
} = require('../src');

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-basic-usage');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir, sessionTtlMs: 60000 });

  // 1) create a database for owner 'u1'
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'u1', name: 'main' });
  console.log('created database', dbId, 'clientSecret (returned once):', clientSecret.slice(0, 12) + '...');

  // 2) schema: one plain index (username), one blind index (email - equality queryable while
  //    encrypted at rest), one plain field (age)
  const users = await db.defineCollectionAsync('users', {
    fields: [
      { no: 2, name: 'username', type: 'string', index: true },
      { no: 3, name: 'email', type: 'string', blindIndex: true, required: true },
      { no: 4, name: 'age', type: 'int32' },
    ],
  });

  // 3) insert
  const id1 = await users.insert({ username: 'abuzer', email: 'abuzer@fitfak.net', age: 30 });
  const id2 = await users.insert({ username: 'test_user', email: 'test@fitfak.net', age: 22 });
  console.log('inserted', id1, id2);

  // 4) point lookup
  const rec1 = await users.get(id1);
  assert.strictEqual(rec1.username, 'abuzer');
  assert.strictEqual(rec1.age, 30);
  console.log('get by id OK:', rec1);

  // 5) plain index lookup
  const byUsername = await users.findOne('username', 'abuzer');
  assert.strictEqual(byUsername._id, rec1._id);
  console.log('findOne(username) OK');

  // 6) blind (encrypted-but-searchable) index lookup
  const byEmail = await users.findOne('email', 'abuzer@fitfak.net');
  assert.strictEqual(byEmail._id, rec1._id);
  console.log('findOne(email) via blind index OK');

  // 7) update + verify secondary index reconciles (old value no longer matches)
  await users.update(id1, { age: 31, username: 'abuzer_v2' });
  const staleLookup = await users.findOne('username', 'abuzer');
  assert.strictEqual(staleLookup, null);
  const freshLookup = await users.findOne('username', 'abuzer_v2');
  assert.strictEqual(freshLookup.age, 31);
  console.log('update + index reconciliation OK');

  // 8) delete
  await users.delete(id2);
  assert.strictEqual(await users.get(id2), null);
  assert.strictEqual(await users.findOne('email', 'test@fitfak.net'), null);
  console.log('delete + index cleanup OK');

  // 9) bulk insert to exercise segment rotation + measure throughput at modest scale
  const N = 4000;
  const t0 = Date.now();
  for (let i = 0; i < N; i++) {
    await users.insert({ username: `user_${i}`, email: `user_${i}@fitfak.net`, age: 18 + (i % 40) });
  }
  const t1 = Date.now();
  console.log(`bulk inserted ${N} records in ${t1 - t0}ms (${((t1 - t0) / N).toFixed(3)}ms/rec)`);

  const lookupT0 = Date.now();
  const found = await users.findOne('email', 'user_1234@fitfak.net');
  const lookupT1 = Date.now();
  assert.ok(found && found.username === 'user_1234');
  console.log(`indexed point lookup after ${N} inserts: ${lookupT1 - lookupT0}ms (age=${found.age})`);

  // 10) close cleanly (writes index.snapshot) and REOPEN in a fresh manager instance,
  //     simulating a process restart -- must reload without a full data replay.
  await manager.closeDatabase(dbId);

  const manager2 = new DatabaseManager({ baseDir });
  const keyProvider = new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64'));
  const reopenT0 = Date.now();
  const db2 = await manager2.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider, requiredPermission: DB_PERMISSIONS.READ });
  const reopenT1 = Date.now();
  console.log(`reopened database after clean close in ${reopenT1 - reopenT0}ms (fast path via index.snapshot)`);

  const users2 = db2.collection('users');
  assert.strictEqual(users2.count(), N + 1); // id1 survives, id2 deleted, N bulk inserts
  const reloaded = await users2.get(id1);
  assert.strictEqual(reloaded.username, 'abuzer_v2');
  assert.strictEqual(reloaded.age, 31);
  console.log('post-reopen data integrity OK, live count:', users2.count());

  // 11) wrong clientSecret must fail to even read the manifest (zero-knowledge check) --
  //     must be tried against a manager instance that has NOT already opened this dbId,
  //     otherwise the in-process "already open" fast path would short-circuit past the key
  //     check entirely (which is correct behavior for a live session, just not what this
  //     particular check is testing).
  try {
    const freshManager = new DatabaseManager({ baseDir });
    const wrongProvider = new ClientSecretKeyProvider(Buffer.alloc(32, 7));
    await freshManager.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: wrongProvider });
    throw new Error('SHOULD NOT REACH: opened with wrong secret');
  } catch (e) {
    assert.ok(/unable to authenticate/i.test(e.message), `unexpected error: ${e.message}`);
    console.log('wrong-secret open correctly rejected:', e.message);
  }

  // 12) compaction: delete a chunk of records then compact, verify segment count drops and
  //     data integrity is preserved for what remains.
  for (let i = 0; i < 1000; i++) {
    const target = await users2.findOne('username', `user_${i}`);
    if (target) await users2.delete(target._id);
  }
  const beforeFiles = (await fsp.readdir(path.join(db2.dir, 'collections', 'users'))).filter((f) => f.startsWith('seg-'));
  const compactResult = await users2.compact();
  const afterFiles = (await fsp.readdir(path.join(db2.dir, 'collections', 'users'))).filter((f) => f.startsWith('seg-'));
  console.log(`compaction: ${beforeFiles.length} segment file(s) -> ${afterFiles.length}, live records: ${compactResult.liveRecords}`);
  assert.ok(afterFiles.length <= beforeFiles.length);
  const stillThere = await users2.get(id1);
  assert.strictEqual(stillThere.username, 'abuzer_v2');
  console.log('post-compaction integrity OK');

  // 13) simulate an unclean shutdown (no close(), so no fresh snapshot) then reopen -- must
  //     recover correctly via tail-replay from the last snapshot rather than losing data.
  const idPreCrash = await users2.insert({ username: 'pre_crash_user', email: 'precrash@fitfak.net', age: 40 });
  // deliberately skip manager2.closeDatabase()/db2.close() here to emulate a crash after a
  // write landed on disk but before any snapshot captured it.
  manager2.openDatabases.delete(dbId); // drop the in-process handle without flushing

  const manager3 = new DatabaseManager({ baseDir });
  const db3 = await manager3.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64')) });
  const users3 = db3.collection('users');
  const recoveredAfterCrash = await users3.get(idPreCrash);
  assert.ok(recoveredAfterCrash, 'record written before an unclean shutdown must survive via tail-replay');
  assert.strictEqual(recoveredAfterCrash.username, 'pre_crash_user');
  console.log('tail-replay recovery after unclean shutdown OK:', recoveredAfterCrash);

  await manager3.closeDatabase(dbId);

  // 14) a host application's own logger must not be able to break the engine.
  //
  // Passing a caller-supplied logger straight through to the storage layer meant an
  // application that supplied a perfectly ordinary { info, warn, error } hit
  // "this.log.timer is not a function" the moment a collection opened -- and because that
  // throw happens inside open(), the collection stayed permanently unusable. Diagnostic
  // equipment must never break the thing it is there to observe, so anything partial is
  // adapted rather than trusted.
  {
    const forwarded = [];
    const hostLogger = {
      info: (o) => forwarded.push(o),
      warn: (o) => forwarded.push(o),
      error: (o) => forwarded.push(o),
      // deliberately no child(), timer(), hex() or enabled()
    };

    const managerL = new DatabaseManager({ baseDir, logger: hostLogger });
    const createdL = await managerL.createDatabase({ ownerId: 'logger-owner', name: 'logged' });
    const logged = await createdL.db.defineCollectionAsync('entries', {
      fields: [
        { no: 2, name: 'label', type: 'string', index: true },
        { no: 3, name: 'at', type: 'uint64', rangeBucket: { width: 60000 } },
      ],
    });

    const failed = forwarded.filter((o) => o && /failed to open/.test(String(o.msg || '')));
    assert.strictEqual(failed.length, 0,
      `a partial host logger must not stop a collection opening: ${JSON.stringify(failed[0] || {})}`);

    const loggedId = await logged.insert({ label: 'first', at: Date.now() });
    assert.strictEqual((await logged.get(loggedId)).label, 'first');
    assert.strictEqual((await logged.findRange('at', 0, Date.now())).length, 1,
      'the range sweep also calls timer(), so it must survive a partial logger too');

    // Reopen exercises replay and index rebuild, which are timed as well.
    await managerL.closeDatabase(createdL.dbId);
    const managerL2 = new DatabaseManager({ baseDir, logger: hostLogger });
    const dbL2 = await managerL2.openDatabase({
      ownerId: 'logger-owner', dbId: createdL.dbId, requesterId: 'logger-owner',
      keyProvider: new ClientSecretKeyProvider(Buffer.from(createdL.clientSecret, 'base64')),
    });
    assert.ok(await dbL2.collection('entries').get(loggedId), 'reopen must work under a partial logger');
    await managerL2.closeDatabase(createdL.dbId);

    assert.ok(forwarded.length > 0, 'engine lines must actually reach the supplied logger');
    assert.ok(forwarded.every((o) => typeof o === 'object' && o !== null),
      'forwarded lines keep the object shape a host logger expects');
    console.log(`partial host logger: collection opened, ${forwarded.length} line(s) forwarded`);
  }

  console.log('\nALL BASIC-USAGE CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
