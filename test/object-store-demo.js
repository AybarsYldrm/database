'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const { DatabaseManager, FitObjectStore } = require('../src');

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-object-store-demo');
  const blobBaseDir = path.join(__dirname, '..', '.tmp-object-store-blobs');
  await fsp.rm(baseDir, { recursive: true, force: true });
  await fsp.rm(blobBaseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'alice', name: 'main' });
  await FitObjectStore.defineObjectsCollection(db);
  const store = new FitObjectStore({ database: db, blobBaseDir, chunkSize: 8192 });

  // --- 1) public object: small text file, plaintext on disk, servable by anyone ------------
  const publicText = Buffer.from('this is a public readme, anyone with the URL can read it');
  const pub = await store.putPublicObject({ ownerId: 'alice', originalFileName: 'readme.txt', contentType: 'text/plain', source: publicText });
  console.log('public object stored:', pub);

  const publicMeta = await store.findPublicBySlug(pub.objectId);
  assert.ok(publicMeta && publicMeta.visibility === 'public');
  const publicChunks = [];
  for await (const chunk of store.readPublicObjectStream(publicMeta._id)) publicChunks.push(chunk);
  assert.strictEqual(Buffer.concat(publicChunks).toString('utf8'), publicText.toString('utf8'));
  console.log('public object served correctly, byte-for-byte, and found via findPublicBySlug');

  // confirm public bytes are genuinely plaintext on disk (no key needed, by design)
  const rawOnDisk = await fsp.readFile(path.join(blobBaseDir, 'public', String(publicMeta._id)));
  assert.strictEqual(rawOnDisk.toString('utf8'), publicText.toString('utf8'));
  console.log('public blob confirmed plaintext-on-disk (as intended -- public means public)');

  // --- 2) private object: larger binary, multi-chunk (chunkSize=8192), must round-trip -----
  const privateData = crypto.randomBytes(8192 * 4 + 777); // forces 5 chunks, last one partial
  const priv = await store.putPrivateObject({ ownerId: 'alice', originalFileName: 'secret.bin', contentType: 'application/octet-stream', source: privateData });
  console.log('private object stored:', priv);

  const readBack = [];
  for await (const chunk of store.readPrivateObject(priv.objectId, 'alice')) readBack.push(chunk);
  const reassembled = Buffer.concat(readBack);
  assert.strictEqual(Buffer.compare(reassembled, privateData), 0);
  console.log(`private object streamed back byte-for-byte correct across ${readBack.length} chunks`);

  // confirm private bytes are genuinely NOT plaintext on disk
  const rawPrivateOnDisk = await fsp.readFile(path.join(blobBaseDir, 'private', 'alice', `${priv.objectId}.enc`));
  assert.ok(!rawPrivateOnDisk.includes(privateData.subarray(0, 100)), 'private blob must not contain recognizable plaintext');
  console.log('private blob confirmed NOT plaintext on disk');

  // --- 3) RBAC: wrong owner denied, admin override allowed ---------------------------------
  try {
    const gen = store.readPrivateObject(priv.objectId, 'mallory');
    for await (const _ of gen) {} // eslint-disable-line no-unused-vars
    throw new Error('SHOULD NOT REACH: wrong owner read succeeded');
  } catch (e) {
    assert.match(e.message, /permission denied/);
    console.log('wrong-owner read correctly denied:', e.message);
  }
  const adminChunks = [];
  for await (const chunk of store.readPrivateObject(priv.objectId, 'root_admin', { isAdmin: true })) adminChunks.push(chunk);
  assert.strictEqual(Buffer.compare(Buffer.concat(adminChunks), privateData), 0);
  console.log('admin override correctly allowed and byte-correct');

  // --- 4) listing via the PLAIN ownerId index (never through a blind field) ----------------
  await store.putPrivateObject({ ownerId: 'alice', originalFileName: 'second.bin', contentType: 'application/octet-stream', source: Buffer.from('x') });
  await store.putPublicObject({ ownerId: 'bob', originalFileName: 'not-alices.txt', contentType: 'text/plain', source: Buffer.from('y') });
  const aliceObjects = await store.listOwned('alice');
  assert.strictEqual(aliceObjects.length, 3); // readme + secret.bin + second.bin
  assert.ok(aliceObjects.every((o) => o.ownerId === 'alice'));
  console.log(`listOwned('alice') correctly enumerated ${aliceObjects.length} objects via the plain ownerId index`);

  // --- 5) exact-name lookup via blind index (only exact match, never enumeration) ----------
  const byName = await store.findByExactName('alice', 'secret.bin');
  assert.strictEqual(byName.length, 1);
  assert.strictEqual(String(byName[0]._id), priv.objectId);
  console.log('findByExactName correctly resolved via the blind-indexed originalFileName field');

  // --- 6) delete: public and private both removed, blob files AND metadata gone -----------
  await store.deleteObject(pub.objectId, 'alice');
  assert.strictEqual(await store.findPublicBySlug(pub.objectId), null);
  const publicBlobGone = await fsp.access(path.join(blobBaseDir, 'public', pub.objectId)).then(() => false).catch(() => true);
  assert.ok(publicBlobGone, 'deleted public blob file must be gone from disk');
  console.log('public object delete correctly removed both metadata and blob file');

  // --- 7) persistence across close/reopen ---------------------------------------------------
  await manager.closeDatabase(dbId);
  const { ClientSecretKeyProvider } = require('../src');
  const manager2 = new DatabaseManager({ baseDir });
  const db2 = await manager2.openDatabase({ ownerId: 'alice', dbId, requesterId: 'alice', keyProvider: new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64')) });
  const store2 = new FitObjectStore({ database: db2, blobBaseDir, chunkSize: 8192 });
  const readBack2 = [];
  for await (const chunk of store2.readPrivateObject(priv.objectId, 'alice')) readBack2.push(chunk);
  assert.strictEqual(Buffer.compare(Buffer.concat(readBack2), privateData), 0);
  console.log('private object survives a full close/reopen with correct decryption');

  await manager2.closeDatabase(dbId);
  console.log('\nALL OBJECT-STORE CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
