'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const { DatabaseManager, ClientSecretKeyProvider } = require('../src');

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-disk-backed-index-demo');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'u1', name: 'x' });

  const DAY = 86400000;
  const items = await db.defineCollectionAsync('items', {
    fields: [
      { no: 2, name: 'username', type: 'string', index: true, diskBacked: true },
      { no: 3, name: 'email', type: 'string', blindIndex: true, diskBacked: true },
      { no: 4, name: 'age', type: 'int32', index: true }, // plain, in-RAM, for comparison
      { no: 5, name: 'score', type: 'int32', index: true, diskBacked: true }, // native ordered range
      { no: 6, name: 'createdAt', type: 'int64', rangeBucket: { width: DAY }, diskBacked: true },
    ],
  });

  // small flush threshold on purpose: forces MANY flush/merge cycles during this test
  // instead of exercising it once at the end, since flushThreshold is baked into how
  // defineCollectionAsync builds the CollectionStorage. We reopen with a custom threshold
  // by constructing the collection storage directly for this test's needs.
  await manager.closeDatabase(dbId);

  const { CollectionStorage } = require('../src/storage-engine');
  const kp = () => new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64'));
  const manager2 = new DatabaseManager({ baseDir });
  const db2 = await manager2.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: kp() });
  // patch the flush threshold on the already-open collection's storage for this test run
  const items2 = db2.collection('items');
  items2.storage.diskStores.forEach((store) => { store.flushThreshold = 300; });

  const N = 5000;
  const base = 1_700_000_000_000;
  const ids = [];
  for (let i = 0; i < N; i++) {
    const id = await items2.insert({
      username: `user_${i}`,
      email: `user_${i}@x.com`,
      age: 18 + (i % 50),
      score: i,
      createdAt: BigInt(base + Math.floor(i / 20) * DAY),
    });
    ids.push(id);
  }
  console.log(`inserted ${N} records with 4 diskBacked indexed fields + 1 plain index field`);

  // --- 1) bounded-memory check: the memtable must NOT hold anywhere near N entries, and the
  //        sparse index (the only thing fully RAM-resident from the disk segment) must be a
  //        small fraction of N -----------------------------------------------------------
  const usernameStore = items2.storage.diskStores.get('username');
  console.log(`username diskStore: memtable=${usernameStore.memtable.size} entries, sparseIndex=${usernameStore.diskSegment ? usernameStore.diskSegment.sparseIndex.length : 0} blocks (total live values: ${N})`);
  assert.ok(usernameStore.memtable.size < 350, 'memtable must stay bounded near the flush threshold, not grow with N');
  assert.ok(usernameStore.diskSegment.sparseIndex.length < N / 50, 'sparse index must be a small fraction of total entries (bounded-memory property)');

  // --- 2) correctness spot checks across the whole range ------------------------------------
  for (const i of [0, 1, 299, 300, 301, 2500, 4999]) {
    const found = await items2.findOne('username', `user_${i}`);
    assert.ok(found && found.username === `user_${i}`, `username lookup failed at i=${i}`);
    const foundByEmail = await items2.findOne('email', `user_${i}@x.com`);
    assert.strictEqual(foundByEmail._id, found._id, `blind email lookup mismatch at i=${i}`);
  }
  console.log('correctness spot checks across flush boundaries (i=0,1,299,300,301,2500,4999) all OK');

  // --- 3) update: rename a record whose original entry is already flushed to disk, confirm
  //        old value gone, new value found (tombstone + re-add across the disk/memtable split)
  const target = await items2.findOne('username', 'user_150');
  await items2.update(target._id, { username: 'user_150_renamed' });
  assert.strictEqual(await items2.findOne('username', 'user_150'), null);
  const renamed = await items2.findOne('username', 'user_150_renamed');
  assert.ok(renamed && renamed._id === target._id);
  console.log('update (rename) correctly reconciles a diskBacked equality index across the flush boundary');

  // --- 4) delete: remove a record, confirm it disappears from all diskBacked indexes -------
  const toDelete = await items2.findOne('username', 'user_4000');
  await items2.delete(toDelete._id);
  assert.strictEqual(await items2.findOne('username', 'user_4000'), null);
  assert.strictEqual(await items2.findOne('email', 'user_4000@x.com'), null);
  console.log('delete correctly removes entries from diskBacked equality + blind indexes');

  // --- 5) native ordered range query on a diskBacked plain-index numeric field -------------
  const rangeResult = await items2.findRangePlain('score', 100, 110);
  assert.strictEqual(rangeResult.length, 11);
  assert.ok(rangeResult.every((r) => r.score >= 100 && r.score <= 110));
  console.log(`findRangePlain(score, 100, 110) correctly returned ${rangeResult.length} records via the disk-backed sorted segment`);

  // --- 6) bucketized range query on a diskBacked rangeBucket field --------------------------
  const bucketResult = await items2.findRange('createdAt', BigInt(base + 10 * DAY), BigInt(base + 12 * DAY - 1));
  const expectedBucket = ids.length ? Array.from({ length: N }, (_, i) => i).filter((i) => {
    const ts = base + Math.floor(i / 20) * DAY;
    return ts >= base + 10 * DAY && ts < base + 12 * DAY;
  }).length : 0;
  assert.strictEqual(bucketResult.length, expectedBucket);
  console.log(`findRange (bucketed, diskBacked) correctly returned ${bucketResult.length}/${expectedBucket} expected records`);

  // --- 7) clean close/reopen persistence -----------------------------------------------------
  await manager2.closeDatabase(dbId);
  const manager3 = new DatabaseManager({ baseDir });
  const db3 = await manager3.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: kp() });
  const items3 = db3.collection('items');
  assert.ok(await items3.findOne('username', 'user_150_renamed'));
  assert.strictEqual(await items3.findOne('username', 'user_4000'), null);
  const rangeAfterReopen = await items3.findRangePlain('score', 100, 110);
  assert.strictEqual(rangeAfterReopen.length, 11);
  console.log('all diskBacked index state (equality, blind, plain-range, bucketed-range) correctly survives a clean close/reopen');

  // --- 8) crash recovery: writes after the last flush/close must survive via tail-replay ---
  const crashId = await items3.insert({ username: 'post_crash_user', email: 'post_crash@x.com', age: 33, score: 99999, createdAt: BigInt(base) });
  manager3.openDatabases.delete(dbId); // drop without close -> no final flush/snapshot

  const manager4 = new DatabaseManager({ baseDir });
  const db4 = await manager4.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: kp() });
  const items4 = db4.collection('items');
  const recovered = await items4.findOne('username', 'post_crash_user');
  assert.ok(recovered && String(recovered._id) === crashId, 'a diskBacked-indexed record written after the last flush must survive tail-replay');
  console.log('diskBacked index correctly recovers a post-crash tail write via replay:', recovered.username);

  await manager4.closeDatabase(dbId);
  console.log('\nALL DISK-BACKED-INDEX CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
