'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const { DatabaseManager, CryptoWorkerPool } = require('../src');
const { CollectionStorage } = require('../src/storage-engine');
const crypto = require('node:crypto');

async function main() {
  const dir = path.join(__dirname, '..', '.tmp-crypto-offload-demo');
  await fsp.rm(dir, { recursive: true, force: true });

  const pool = new CryptoWorkerPool({ poolSize: 2 });
  let poolCalls = 0;
  const trackedPool = {
    encrypt: (...a) => { poolCalls++; return pool.encrypt(...a); },
    decrypt: (...a) => { poolCalls++; return pool.decrypt(...a); },
  };

  const ddk = crypto.randomBytes(32);
  const schema = [
    { no: 1, name: '_id', type: 'uint64' },
    { no: 2, name: 'blob', type: 'bytes' },
  ];

  // threshold set low (1KB) on purpose so this test can exercise the pool path without
  // needing a genuinely 128KB+ fixture; production default stays 128KB (see crypto-worker-pool.js).
  const storage = new CollectionStorage({
    dir, ddk, schema,
    cryptoOffload: { pool: trackedPool, thresholdBytes: 1024 },
  });
  await storage.open();

  // small record: must NOT engage the pool
  await storage.put({ _id: 1n, blob: Buffer.from('small payload') });
  await storage.get('1');
  assert.strictEqual(poolCalls, 0, 'small payload should never touch the worker pool');
  console.log('small record correctly bypassed the worker pool (poolCalls=0)');

  // large record: MUST engage the pool, and must round-trip correctly
  const bigBlob = crypto.randomBytes(200 * 1024); // 200KB, above the 1KB test threshold
  await storage.put({ _id: 2n, blob: bigBlob });
  const readBack = await storage.get('2');
  assert.ok(Buffer.compare(readBack.blob, bigBlob) === 0, 'large payload must round-trip byte-for-byte through the worker pool');
  assert.ok(poolCalls >= 2, `expected at least one encrypt + one decrypt dispatched to the pool, got ${poolCalls} calls`);
  console.log(`large (200KB) record correctly routed through the worker pool (poolCalls=${poolCalls}), data integrity verified`);

  await storage.close();
  await pool.terminate();
  console.log('\nALL CRYPTO-OFFLOAD CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
