'use strict';

const assert = require('node:assert');
const net = require('node:net');
const path = require('node:path');
const fsp = require('node:fs/promises');
const {
  DatabaseManager, DB_PERMISSIONS, CapabilityKeyRing, CapabilityTokenService,
  DirectAccessServer, DIRECT_OPS, VersionWatermark, SnowflakeGenerator,
} = require('../src');
const { buildRequestFrame, createResponseFrameReader } = require('../src/direct-protocol');

// A tiny multiplexed client: one socket, many concurrent in-flight requests, responses
// matched back to callers by requestId regardless of the order they complete in.
class DirectClient {
  constructor(port) {
    this.port = port;
    this.nextId = 1;
    this.pending = new Map();
    this.socket = null;
  }
  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, '127.0.0.1', resolve);
      this.socket.on('data', createResponseFrameReader((frame) => {
        const { parseResponseFrame } = require('../src/direct-protocol');
        const { requestId, body } = parseResponseFrame(frame);
        const p = this.pending.get(requestId);
        if (p) { this.pending.delete(requestId); p.resolve(body); }
      }));
      this.socket.on('error', reject);
    });
  }
  send(req) {
    const requestId = this.nextId++;
    return new Promise((resolve) => {
      this.pending.set(requestId, { resolve });
      this.socket.write(buildRequestFrame({ ...req, requestId }));
    });
  }
  close() { this.socket.end(); }
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-direct-access-demo');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const { db, dbId } = await manager.createDatabase({ ownerId: 'u1', name: 'main' });
  const items = await db.defineCollectionAsync('items', {
    fields: [{ no: 2, name: 'label', type: 'string', index: true }, { no: 3, name: 'owner', type: 'string' }],
  });
  const id1 = await items.insert({ label: 'first', owner: 'alice' });
  console.log('seeded record', id1);

  const snowflake = new SnowflakeGenerator({ workerId: 2 });
  const keyRing = new CapabilityKeyRing();
  const tokens = new CapabilityTokenService(keyRing, snowflake);

  const directServer = new DirectAccessServer({ databaseManager: manager, capabilityTokens: tokens });
  directServer.listen(0);
  await new Promise((resolve) => directServer.server.once('listening', resolve));
  const port = directServer.server.address().port;
  console.log('direct-access listener up on port', port);

  const client = new DirectClient(port);
  await client.connect();

  // --- 1) basic GET over the persistent connection -----------------------------------------
  const readToken = tokens.issue({ sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.READ, ttlMs: 5000, singleUse: true });
  const res1 = await client.send({ opCode: DIRECT_OPS.GET, token: readToken, dbId, collection: 'items', args: { id: id1 } });
  assert.ok(res1.ok && res1.value.label === 'first');
  const watermark = new VersionWatermark();
  watermark.check(id1, res1.version);
  console.log('direct GET over multiplexed connection OK, version', res1.version);

  // --- 2) single-use replay on the SAME connection must still be rejected ------------------
  const res2 = await client.send({ opCode: DIRECT_OPS.GET, token: readToken, dbId, collection: 'items', args: { id: id1 } });
  assert.strictEqual(res2.ok, false);
  assert.match(res2.error, /already used|replay/i);
  console.log('single-use replay correctly rejected on a reused connection:', res2.error);

  // --- 3) TRUE multiplexing: fire many concurrent requests on ONE connection, confirm all
  //        come back correctly matched by requestId even though they may complete out of
  //        the order they were sent in ---------------------------------------------------
  const bulkIds = [];
  for (let i = 0; i < 30; i++) bulkIds.push(await items.insert({ label: `bulk_${i}`, owner: i % 2 === 0 ? 'alice' : 'bob' }));

  const manyToken = tokens.issue({ sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.READ, ttlMs: 10000, singleUse: false });
  const concurrentPromises = bulkIds.map((id) => client.send({ opCode: DIRECT_OPS.GET, token: manyToken, dbId, collection: 'items', args: { id } }));
  const concurrentResults = await Promise.all(concurrentPromises);
  assert.strictEqual(concurrentResults.length, 30);
  concurrentResults.forEach((r, i) => assert.strictEqual(r.value.label, `bulk_${i}`));
  console.log('30 concurrent multiplexed requests on one connection all correctly matched by requestId');

  // --- 4) SCAN/cursor pagination over the persistent connection ----------------------------
  let cursor = null;
  let scanned = [];
  for (let page = 0; page < 10; page++) {
    const res = await client.send({ opCode: DIRECT_OPS.SCAN, token: manyToken, dbId, collection: 'items', args: { afterId: cursor, limit: 10 } });
    assert.ok(res.ok);
    scanned.push(...res.records);
    cursor = res.nextCursor;
    if (!cursor) break;
  }
  assert.strictEqual(scanned.length, 31); // id1 + 30 bulk inserts
  console.log(`paginated SCAN across ${scanned.length} records via repeated cursor calls on one connection`);

  // --- 5) row-scoped capability: a token restricted to owner=='alice' must only see alice's
  //        records via GET/FIND_ONE/SCAN, and must refuse to write a record for someone else -
  const aliceOnlyRead = tokens.issue({
    sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.READ, ttlMs: 5000, singleUse: false,
    rowFilter: { field: 'owner', value: 'alice' },
  });
  const bobRecordId = bulkIds[1]; // i=1 -> owner 'bob'
  const hiddenRes = await client.send({ opCode: DIRECT_OPS.GET, token: aliceOnlyRead, dbId, collection: 'items', args: { id: bobRecordId } });
  assert.strictEqual(hiddenRes.value, null, "a row-scoped token must not reveal a record outside its filter, even if the id is valid");
  const visibleId = bulkIds[0]; // i=0 -> owner 'alice'
  const visibleRes = await client.send({ opCode: DIRECT_OPS.GET, token: aliceOnlyRead, dbId, collection: 'items', args: { id: visibleId } });
  assert.strictEqual(visibleRes.value.owner, 'alice');
  console.log('row-scoped (owner==alice) token correctly hides bob\'s record and reveals alice\'s');

  let aliceScanCursor = null, aliceScanned = [];
  for (let page = 0; page < 10; page++) {
    const res = await client.send({ opCode: DIRECT_OPS.SCAN, token: aliceOnlyRead, dbId, collection: 'items', args: { afterId: aliceScanCursor, limit: 10 } });
    aliceScanned.push(...res.records);
    aliceScanCursor = res.nextCursor;
    if (!aliceScanCursor) break;
  }
  assert.ok(aliceScanned.every((r) => r.owner === 'alice'), 'row-scoped SCAN must only ever return matching records');
  console.log(`row-scoped SCAN correctly returned only alice's ${aliceScanned.length} records`);

  const aliceOnlyWrite = tokens.issue({
    sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.WRITE, ttlMs: 5000, singleUse: false,
    rowFilter: { field: 'owner', value: 'alice' },
  });
  const badWrite = await client.send({ opCode: DIRECT_OPS.PUT, token: aliceOnlyWrite, dbId, collection: 'items', args: { record: { _id: bobRecordId, label: 'hijacked', owner: 'bob' } } });
  assert.strictEqual(badWrite.ok, false);
  assert.match(badWrite.error, /row scope/i);
  console.log('row-scoped WRITE token correctly refuses to write a record outside its own row filter:', badWrite.error);

  // --- 6) insufficient-scope DELETE still rejected (unchanged behavior, now over v2) -------
  const res3 = await client.send({ opCode: DIRECT_OPS.DELETE, token: manyToken, dbId, collection: 'items', args: { id: id1 } });
  assert.strictEqual(res3.ok, false);
  assert.match(res3.error, /scope/i);
  console.log('insufficient-scope DELETE correctly rejected:', res3.error);

  // --- 7) expiry --------------------------------------------------------------------------
  const shortLivedToken = tokens.issue({ sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.READ, ttlMs: 50, singleUse: false });
  await new Promise((r) => setTimeout(r, 120));
  const res5 = await client.send({ opCode: DIRECT_OPS.GET, token: shortLivedToken, dbId, collection: 'items', args: { id: id1 } });
  assert.strictEqual(res5.ok, false);
  assert.match(res5.error, /expired/i);
  console.log('expired token correctly rejected:', res5.error);

  // --- 8) WRITE + version increment + VersionWatermark rollback detection -----------------
  const writeToken = tokens.issue({ sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.WRITE, ttlMs: 5000, singleUse: false });
  await client.send({ opCode: DIRECT_OPS.PUT, token: writeToken, dbId, collection: 'items', args: { record: { _id: id1, label: 'updated-direct', owner: 'alice' } } });
  const readAgainToken = tokens.issue({ sub: 'u1', dbId, collection: 'items', scope: DB_PERMISSIONS.READ, ttlMs: 5000, singleUse: false });
  const res6 = await client.send({ opCode: DIRECT_OPS.GET, token: readAgainToken, dbId, collection: 'items', args: { id: id1 } });
  assert.strictEqual(res6.value.label, 'updated-direct');
  assert.ok(res6.version > res1.version);
  watermark.check(id1, res6.version);
  console.log('direct PUT + version increment observed:', res1.version, '->', res6.version);
  try {
    watermark.check(id1, res1.version);
    throw new Error('SHOULD NOT REACH: watermark accepted a version rollback');
  } catch (e) {
    assert.match(e.message, /rollback/i);
    console.log('VersionWatermark correctly rejects a rollback replay:', e.message);
  }

  client.close();
  await directServer.close();
  await manager.closeDatabase(dbId);
  console.log('\nALL DIRECT-ACCESS CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
