'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const { DatabaseManager, ClientSecretKeyProvider } = require('../src');

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-index-snapshot-demo');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'u1', name: 'x' });
  const users = await db.defineCollectionAsync('users', {
    fields: [
      { no: 2, name: 'username', type: 'string', index: true },
      { no: 3, name: 'email', type: 'string', blindIndex: true },
    ],
  });
  const N = 3000;
  for (let i = 0; i < N; i++) await users.insert({ username: `user_${i}`, email: `user_${i}@x.com` });
  await manager.closeDatabase(dbId);

  const kp = () => new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64'));
  const collDir = path.join(baseDir, 'u1', dbId, 'collections', 'users');
  const snapPath = path.join(collDir, 'index.snapshot');

  // --- A) measured cost with NO snapshot (forces the O(live records) decrypt-based rebuild)
  await fsp.unlink(snapPath);
  const managerA = new DatabaseManager({ baseDir });
  let t0 = Date.now();
  await managerA.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: kp() });
  const fullRebuildMs = Date.now() - t0;
  await managerA.closeDatabase(dbId); // regenerates a fresh (correct-format) snapshot

  // --- B) measured cost WITH the persisted secondary/blind snapshot ------------------------
  const managerB = new DatabaseManager({ baseDir });
  t0 = Date.now();
  const dbB = await managerB.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: kp() });
  const snapshotMs = Date.now() - t0;
  console.log(`${N} records, 2 indexed fields: full decrypt-rebuild=${fullRebuildMs}ms vs persisted-snapshot=${snapshotMs}ms (${(fullRebuildMs / Math.max(snapshotMs, 1)).toFixed(1)}x)`);
  assert.ok(snapshotMs < fullRebuildMs, 'persisted snapshot path should beat a full decrypt-based rebuild');

  const usersB = dbB.collection('users');
  const mid = await usersB.findOne('username', 'user_1500');
  assert.ok(mid && mid.username === 'user_1500');
  const midByEmail = await usersB.findOne('email', 'user_1500@x.com');
  assert.strictEqual(midByEmail._id, mid._id);
  console.log('secondary + blind index lookups correct after snapshot-based reopen');

  // --- C) unclean shutdown: writes AFTER the last clean snapshot must still be searchable
  //        via the small tail-replay reconciliation, without a full rebuild -----------------
  const tailId = await usersB.insert({ username: 'tail_user', email: 'tail_user@x.com' });
  await usersB.update(mid._id, { username: 'user_1500_renamed', email: mid.email });
  managerB.openDatabases.delete(dbId); // drop the handle WITHOUT close() -> no fresh snapshot written

  const managerC = new DatabaseManager({ baseDir });
  const dbC = await managerC.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: kp() });
  const usersC = dbC.collection('users');

  const tailFound = await usersC.findOne('username', 'tail_user');
  assert.ok(tailFound && String(tailFound._id) === tailId, 'a record written after the last snapshot must be found via tail-replay index reconciliation');

  const staleGone = await usersC.findOne('username', 'user_1500');
  assert.strictEqual(staleGone, null, 'the OLD username must no longer resolve after an update, even across a tail-replayed reopen');
  const renamedFound = await usersC.findOne('username', 'user_1500_renamed');
  assert.ok(renamedFound && renamedFound._id === mid._id, 'the NEW username must resolve after a tail-replayed reopen');
  console.log('tail-replay correctly reconciles secondary/blind indexes for records written after the last snapshot (insert + update both verified)');

  await managerC.closeDatabase(dbId);
  console.log('\nALL INDEX-SNAPSHOT CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
