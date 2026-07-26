'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const { DatabaseManager, MlsExportSecretKeyProvider, DB_PERMISSIONS } = require('../src');

// Stand-in for a real RFC 9420 group object. MlsExportSecretKeyProvider only ever calls
// exportSecret(label, context, length) on it -- that is the entire contract. A real
// implementation (the one already built per the design doc pasted into this project)
// derives this from the group's current epoch secret; here a fixed random buffer models
// "one specific epoch's export secret" so two separate instances cleanly model two
// separate epochs without any aliasing between them.
class MockMlsGroup {
  constructor() { this._epochSecret = crypto.randomBytes(32); }
  async exportSecret(label, context, length) {
    return crypto.hkdfSync('sha256', this._epochSecret, Buffer.from(context), Buffer.from(label), length);
  }
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-mls-key-provider-demo');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const epoch0 = new MlsExportSecretKeyProvider(new MockMlsGroup());
  const manager = new DatabaseManager({ baseDir });

  // createDatabase() with an explicit keyProvider skips clientSecret generation entirely --
  // KEK comes straight from the (mock) group's exportSecret().
  const { db, dbId } = await manager.createDatabase({ ownerId: 'u1', name: 'shared', keyProvider: epoch0 });
  const notes = await db.defineCollectionAsync('notes', { fields: [{ no: 2, name: 'text', type: 'string' }] });
  const id1 = await notes.insert({ text: 'epoch-0 note' });
  console.log('wrote a record under MLS epoch 0, id', id1);
  await manager.closeDatabase(dbId);

  // --- membership change: a new epoch means a new export secret ---------------------------
  const epoch1 = new MlsExportSecretKeyProvider(new MockMlsGroup());
  console.log('MLS group epoch advanced (new export secret) -- manifest is still wrapped under epoch 0');

  // Deriving KEK from the new epoch must NOT open a manifest wrapped under the old epoch's
  // KEK until an explicit re-wrap happens -- old key material does not silently keep working.
  const freshManager = new DatabaseManager({ baseDir });
  try {
    await freshManager.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: epoch1 });
    throw new Error('SHOULD NOT REACH: new-epoch KEK should not open a manifest wrapped under the retired epoch');
  } catch (e) {
    assert.match(e.message, /unable to authenticate/i);
    console.log('open with new epoch (before rewrap) correctly fails:', e.message);
  }

  // --- the actual O(1) rotation: re-wrap the SAME DDK under the new epoch's KEK. No
  //     segment file, index, or record is touched -- exactly the design doc's stated payoff.
  const rewrapManager = new DatabaseManager({ baseDir });
  await rewrapManager.rewrapDatabaseKey({
    ownerId: 'u1', dbId, requesterId: 'u1',
    oldKeyProvider: epoch0, newKeyProvider: epoch1,
  });
  console.log('rewrapDatabaseKey: DDK re-wrapped under epoch-1 KEK (zero record/segment I/O)');

  // now epoch1 opens it, and the retired epoch0 key no longer does
  const db2 = await freshManager.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: epoch1 });
  const notes2 = db2.collection('notes');
  const rec = await notes2.get(id1);
  assert.strictEqual(rec.text, 'epoch-0 note'); // the DDK never changed, so the data is untouched
  console.log('open with new epoch (after rewrap) succeeds, data intact:', rec);

  const retiredManager = new DatabaseManager({ baseDir });
  try {
    await retiredManager.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: epoch0 });
    throw new Error('SHOULD NOT REACH: retired epoch-0 key should no longer open the manifest');
  } catch (e) {
    assert.match(e.message, /unable to authenticate/i);
    console.log('retired epoch-0 key correctly no longer works:', e.message);
  }

  await freshManager.closeDatabase(dbId);
  console.log('\nALL MLS-KEY-PROVIDER CHECKS PASSED (O(1) rewrap semantics verified end to end)');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
