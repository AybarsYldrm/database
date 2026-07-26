'use strict';

const { Worker, isMainThread, parentPort } = require('node:worker_threads');
const path = require('node:path');
const crypto = require('node:crypto');

// Measured, not assumed: benchmarking AES-256-GCM dispatched to node:worker_threads against
// the same work done inline on the main thread (see the benchmark this module's threshold
// default is based on) showed:
//   1KB payload:  worker ~7x SLOWER than main thread (per-message overhead dominates)
//   20000 x 200B records, even BATCHED into single messages of up to 1000 records: worker
//     pool still ~3.4-3.7x SLOWER than a plain main-thread loop
//   100KB+ payload, pool of 4 workers under real concurrent load: worker pool ~28% FASTER
// fitdb records are small structured rows (strings/ints/small blobs) -- large binary blobs
// already have a dedicated path in the existing ObjectStoreService (server.js), not this
// engine. So this pool is OPT-IN and gated by a size threshold close to where the
// measurements actually crossed over (default 128KB, comfortably past the 100KB point):
// below it, storage-engine.js does exactly what it always did (inline, main thread, and
// simpler to reason about); above it, and only if a pool was explicitly configured, the
// encrypt/decrypt call is dispatched here instead.
if (!isMainThread) {
  parentPort.on('message', ({ id, op, key, aad, data }) => {
    try {
      let result;
      if (op === 'encrypt') {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key), iv);
        if (aad) cipher.setAAD(Buffer.from(aad));
        const ct = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
        result = Buffer.concat([iv, cipher.getAuthTag(), ct]);
      } else if (op === 'decrypt') {
        const framed = Buffer.from(data);
        const iv = framed.subarray(0, 12), tag = framed.subarray(12, 28), ct = framed.subarray(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key), iv);
        if (aad) decipher.setAAD(Buffer.from(aad));
        decipher.setAuthTag(tag);
        result = Buffer.concat([decipher.update(ct), decipher.final()]);
      } else {
        throw new Error(`unknown worker op '${op}'`);
      }
      parentPort.postMessage({ id, ok: true, result });
    } catch (e) {
      parentPort.postMessage({ id, ok: false, error: e.message });
    }
  });
}

class CryptoWorkerPool {
  constructor({ poolSize = 4 } = {}) {
    this.workers = Array.from({ length: poolSize }, () => {
      const w = new Worker(__filename);
      w.setMaxListeners(0);
      w.on('message', (msg) => this._onMessage(w, msg));
      return w;
    });
    this.next = 0;
    this.pending = new Map(); // id -> {resolve, reject}
    this.seq = 0;
  }

  _onMessage(_worker, msg) {
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    if (msg.ok) p.resolve(msg.result); else p.reject(new Error(msg.error));
  }

  _dispatch(op, key, aad, data) {
    return new Promise((resolve, reject) => {
      const id = ++this.seq;
      this.pending.set(id, { resolve, reject });
      const w = this.workers[this.next];
      this.next = (this.next + 1) % this.workers.length;
      w.postMessage({ id, op, key, aad, data });
    });
  }

  encrypt(key, plaintext, aad) { return this._dispatch('encrypt', key, aad, plaintext); }
  decrypt(key, framed, aad) { return this._dispatch('decrypt', key, aad, framed); }

  async terminate() { await Promise.all(this.workers.map((w) => w.terminate())); }
}

const DEFAULT_OFFLOAD_THRESHOLD_BYTES = 128 * 1024;

module.exports = { CryptoWorkerPool, DEFAULT_OFFLOAD_THRESHOLD_BYTES };
