'use strict';

const assert = require('node:assert');
const net = require('node:net');
const http = require('node:http');
const path = require('node:path');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');
const {
  DatabaseManager, FitObjectStore, DB_PERMISSIONS, CapabilityKeyRing, CapabilityTokenService,
  DirectAccessServer, DIRECT_OPS, SnowflakeGenerator, createPublicObjectServer,
} = require('../src');
const { buildRequestFrame, createResponseFrameReader, parseResponseFrame } = require('../src/direct-protocol');

function httpGet(port, urlPath) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: urlPath }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
}

// Streaming-aware client for OBJECT_DOWNLOAD: many response frames share one requestId,
// terminated by {done:true}.
class DirectClient {
  constructor(port) { this.port = port; this.nextId = 1; this.pending = new Map(); this.streams = new Map(); }
  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, '127.0.0.1', resolve);
      this.socket.on('data', createResponseFrameReader((frame) => {
        const { requestId, body } = parseResponseFrame(frame);
        if (body.streaming) {
          const s = this.streams.get(requestId);
          if (!s) return;
          if (body.done) { this.streams.delete(requestId); s.resolveAll({ ok: true, chunkCount: body.chunkCount }); }
          else s.chunks[body.index] = Buffer.from(body.data, 'base64');
          return;
        }
        const p = this.pending.get(requestId);
        if (p) { this.pending.delete(requestId); p.resolve(body); }
      }));
      this.socket.on('error', reject);
    });
  }
  send(req) {
    const requestId = this.nextId++;
    return new Promise((resolve) => { this.pending.set(requestId, { resolve }); this.socket.write(buildRequestFrame({ ...req, requestId })); });
  }
  async downloadObject(req) {
    const requestId = this.nextId++;
    const chunks = [];
    const resultPromise = new Promise((resolveAll, rejectAll) => { this.streams.set(requestId, { chunks, resolveAll, rejectAll }); });
    // errors for a streaming request still arrive as a single non-streaming frame (thrown
    // before the first chunk was ever written), so also listen on `pending` for that case.
    const errorPromise = new Promise((resolve) => this.pending.set(requestId, { resolve }));
    this.socket.write(buildRequestFrame({ ...req, requestId }));
    const winner = await Promise.race([resultPromise.then((r) => ({ kind: 'done', r })), errorPromise.then((r) => ({ kind: 'error', r }))]);
    this.pending.delete(requestId);
    if (winner.kind === 'error') return winner.r; // { ok:false, error }
    return { ok: true, buffer: Buffer.concat(chunks) };
  }
  close() { this.socket.end(); }
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-object-direct-demo');
  const blobBaseDir = path.join(__dirname, '..', '.tmp-object-direct-blobs');
  await fsp.rm(baseDir, { recursive: true, force: true });
  await fsp.rm(blobBaseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const { db, dbId } = await manager.createDatabase({ ownerId: 'alice', name: 'main' });
  await FitObjectStore.defineObjectsCollection(db);
  const store = new FitObjectStore({ database: db, blobBaseDir, chunkSize: 16384 });

  // --- public object served over a REAL HTTP server, S3-URL style --------------------------
  const publicContent = Buffer.from('hello from a public S3-style URL, no auth needed');
  const pub = await store.putPublicObject({ ownerId: 'alice', originalFileName: 'hello.txt', contentType: 'text/plain', source: publicContent });
  const httpServer = createPublicObjectServer(store);
  await new Promise((resolve) => httpServer.listen(0, resolve));
  const httpPort = httpServer.address().port;

  const res = await httpGet(httpPort, pub.url);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.toString('utf8'), publicContent.toString('utf8'));
  assert.strictEqual(res.headers['content-type'], 'text/plain');
  console.log(`public object served over real HTTP at ${pub.url}, byte-for-byte correct, content-type preserved`);

  const missingRes = await httpGet(httpPort, '/objects/public/does-not-exist');
  assert.strictEqual(missingRes.statusCode, 404);
  console.log('nonexistent public object correctly 404s');

  // --- private object streamed over the capability-token-gated direct-access connection ----
  const privateData = crypto.randomBytes(16384 * 3 + 500); // multi-chunk
  const priv = await store.putPrivateObject({ ownerId: 'alice', originalFileName: 'private.bin', contentType: 'application/octet-stream', source: privateData });

  const snowflake = new SnowflakeGenerator({ workerId: 5 });
  const keyRing = new CapabilityKeyRing();
  const tokens = new CapabilityTokenService(keyRing, snowflake);
  const directServer = new DirectAccessServer({ databaseManager: manager, capabilityTokens: tokens });
  directServer.registerObjectStore(dbId, store);
  directServer.listen(0);
  await new Promise((resolve) => directServer.server.once('listening', resolve));
  const directPort = directServer.server.address().port;

  const client = new DirectClient(directPort);
  await client.connect();

  const aliceToken = tokens.issue({ sub: 'alice', dbId, collection: 'objects', scope: DB_PERMISSIONS.READ, ttlMs: 10000, singleUse: false });
  const dl = await client.downloadObject({ opCode: DIRECT_OPS.OBJECT_DOWNLOAD, token: aliceToken, dbId, collection: 'objects', args: { objectId: priv.objectId } });
  assert.ok(dl.ok, JSON.stringify(dl));
  assert.strictEqual(Buffer.compare(dl.buffer, privateData), 0);
  console.log(`private object streamed byte-for-byte correct over the direct-access connection (${dl.buffer.length} bytes)`);

  // --- a token for a DIFFERENT user must not be able to download alice's private object ----
  const malloryToken = tokens.issue({ sub: 'mallory', dbId, collection: 'objects', scope: DB_PERMISSIONS.READ, ttlMs: 10000, singleUse: false });
  const dl2 = await client.downloadObject({ opCode: DIRECT_OPS.OBJECT_DOWNLOAD, token: malloryToken, dbId, collection: 'objects', args: { objectId: priv.objectId } });
  assert.strictEqual(dl2.ok, false);
  assert.match(dl2.error, /permission denied/);
  console.log('a different user\'s token correctly cannot download alice\'s private object:', dl2.error);

  // --- an ADMIN-scoped token CAN download someone else's private object --------------------
  const adminToken = tokens.issue({ sub: 'root', dbId, collection: 'objects', scope: DB_PERMISSIONS.READ | DB_PERMISSIONS.ADMIN, ttlMs: 10000, singleUse: false });
  const dl3 = await client.downloadObject({ opCode: DIRECT_OPS.OBJECT_DOWNLOAD, token: adminToken, dbId, collection: 'objects', args: { objectId: priv.objectId } });
  assert.ok(dl3.ok);
  assert.strictEqual(Buffer.compare(dl3.buffer, privateData), 0);
  console.log('an ADMIN-scoped token correctly CAN download another user\'s private object, byte-for-byte correct');

  client.close();
  await directServer.close();
  httpServer.close();
  await manager.closeDatabase(dbId);
  console.log('\nALL OBJECT-STORE DIRECT-ACCESS CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
