'use strict';

const fsp = require('node:fs/promises');
const { aesGcmEncrypt, aesGcmDecrypt } = require('./crypto-core');
const { idToBuf } = require('./id-codec');

// A single AES-256-GCM tag authenticates everything seen by that point and nothing more,
// so a naive "encrypt the whole file as one blob" scheme forces buffering the ENTIRE
// plaintext (to encrypt) or ciphertext (to verify the tag before releasing any plaintext)
// in memory -- unworkable for large files. Instead, following the same reasoning already
// applied to every record in storage-engine.js, each fixed-size chunk is its own
// independent AEAD frame with its own nonce and tag, letting a reader decrypt-and-emit
// chunk by chunk. AAD binds each chunk to (objectId, chunkIndex), so chunks cannot be
// reordered or attributed to the wrong object; the header's declared totalChunks is
// separately checked against how many chunks were actually read, catching truncation
// (dropped trailing chunks) without needing a two-pass write to bind totalChunks into the
// AAD itself.
//
// File layout:
//   [magic:4 'FBLB'][version:1][chunkSize:4 BE][totalSize:8 BE][totalChunks:4 BE]
//   totalChunks * { [chunkPlainLen:4 BE][encChunk: iv(12)+tag(16)+ciphertext] }

const MAGIC = Buffer.from('FBLB');
const VERSION = 1;
const HEADER_SIZE = 4 + 1 + 4 + 8 + 4;
const DEFAULT_CHUNK_SIZE = 64 * 1024; // matches the highWaterMark already used elsewhere in this stack

function chunkAad(objectIdBuf, chunkIndex) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(chunkIndex, 0);
  return Buffer.concat([objectIdBuf, b]);
}

// `source` may be a Buffer or an async-iterable of Buffers (e.g. a Node Readable stream) --
// either way this never holds more than one chunk of plaintext and one chunk of ciphertext
// in memory at a time, so encrypting a multi-GB source costs O(chunkSize) RAM, not O(size).
async function writeEncryptedBlob(filePath, source, { key, objectId, chunkSize = DEFAULT_CHUNK_SIZE }) {
  const objectIdBuf = idToBuf(objectId);
  const tmpPath = filePath + '.tmp';
  const fd = await fsp.open(tmpPath, 'w');
  try {
    await fd.write(Buffer.alloc(HEADER_SIZE), 0, HEADER_SIZE, 0); // reserved, patched below once totals are known

    let totalSize = 0n;
    let chunkIndex = 0;
    let writeOffset = HEADER_SIZE;
    let pending = Buffer.alloc(0);

    const flushOneChunk = async (plainChunk) => {
      const enc = aesGcmEncrypt(key, plainChunk, chunkAad(objectIdBuf, chunkIndex));
      const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32BE(plainChunk.length, 0);
      const frame = Buffer.concat([lenBuf, enc]);
      await fd.write(frame, 0, frame.length, writeOffset);
      writeOffset += frame.length;
      totalSize += BigInt(plainChunk.length);
      chunkIndex += 1;
    };

    const iterable = Buffer.isBuffer(source) ? [source] : source;
    for await (const piece of iterable) {
      pending = pending.length ? Buffer.concat([pending, piece]) : piece;
      while (pending.length >= chunkSize) {
        await flushOneChunk(pending.subarray(0, chunkSize));
        pending = pending.subarray(chunkSize);
      }
    }
    if (pending.length > 0 || chunkIndex === 0) await flushOneChunk(pending); // always >=1 chunk, even for an empty object

    const header = Buffer.alloc(HEADER_SIZE);
    MAGIC.copy(header, 0);
    header.writeUInt8(VERSION, 4);
    header.writeUInt32BE(chunkSize, 5);
    header.writeBigUInt64BE(totalSize, 9);
    header.writeUInt32BE(chunkIndex, 17);
    await fd.write(header, 0, HEADER_SIZE, 0);
  } finally {
    await fd.close();
  }
  await fsp.rename(tmpPath, filePath);
}

async function readEncryptedBlobHeader(filePath) {
  const fd = await fsp.open(filePath, 'r');
  try {
    const header = Buffer.alloc(HEADER_SIZE);
    await fd.read(header, 0, HEADER_SIZE, 0);
    if (!header.subarray(0, 4).equals(MAGIC)) throw new Error('fitdb: corrupt object blob (bad magic)');
    if (header.readUInt8(4) !== VERSION) throw new Error('fitdb: unsupported object blob version');
    return {
      chunkSize: header.readUInt32BE(5),
      totalSize: header.readBigUInt64BE(9),
      totalChunks: header.readUInt32BE(17),
    };
  } finally {
    await fd.close();
  }
}

// Streams decrypted plaintext chunks in order, one at a time -- a reader never holds more
// than one chunk of plaintext/ciphertext in memory regardless of total object size. Verifies
// at the end that the number of chunks actually read matches the header's declared
// totalChunks (catches truncation).
async function* readEncryptedBlob(filePath, { key, objectId }) {
  const objectIdBuf = idToBuf(objectId);
  const meta = await readEncryptedBlobHeader(filePath);
  const fd = await fsp.open(filePath, 'r');
  try {
    let offset = HEADER_SIZE;
    let chunkIndex = 0;
    const stat = await fd.stat();
    while (offset < stat.size) {
      const lenBuf = Buffer.alloc(4);
      await fd.read(lenBuf, 0, 4, offset);
      const plainLen = lenBuf.readUInt32BE(0);
      offset += 4;
      const encLen = 12 + 16 + plainLen; // iv + tag + ciphertext
      const encBuf = Buffer.alloc(encLen);
      await fd.read(encBuf, 0, encLen, offset);
      offset += encLen;
      const plain = aesGcmDecrypt(key, encBuf, chunkAad(objectIdBuf, chunkIndex));
      yield plain;
      chunkIndex += 1;
    }
    if (chunkIndex !== meta.totalChunks) {
      throw new Error(`fitdb: object blob truncated (expected ${meta.totalChunks} chunks, read ${chunkIndex})`);
    }
  } finally {
    await fd.close();
  }
}

module.exports = { writeEncryptedBlob, readEncryptedBlob, readEncryptedBlobHeader, DEFAULT_CHUNK_SIZE };
