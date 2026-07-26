'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { hkdf } = require('./crypto-core');
const { writeEncryptedBlob, readEncryptedBlob, readEncryptedBlobHeader, DEFAULT_CHUNK_SIZE } = require('./encrypted-blob');

// Metadata schema for the 'objects' collection. Note what IS and ISN'T blind-indexed, on
// purpose:
//   - ownerId: PLAIN index. The server already has to know who owns what to do RBAC at
//     all, so hiding it here buys no real confidentiality -- and it's the field enumeration
//     (listOwned) is actually built on. Blind indexes structurally only answer "does a
//     record with this EXACT already-known value exist", never "list everything" (that
//     would require trying every possible value against the index, which is the whole
//     leakage a blind index exists to prevent) -- so anything meant to be *browsable*
//     belongs on a plain index or the primary-key scan, never a blind one.
//   - originalFileName / publicSlug: blindIndex, for "does the exact file I'm thinking of
//     already exist" lookups without the server holding a plaintext-searchable filename
//     table.
const OBJECTS_SCHEMA_FIELDS = [
  { no: 2, name: 'ownerId', type: 'string', index: true, diskBacked: true },
  { no: 3, name: 'visibility', type: 'string', index: true },
  { no: 4, name: 'originalFileName', type: 'string', blindIndex: true, diskBacked: true },
  { no: 5, name: 'contentType', type: 'string' },
  { no: 6, name: 'size', type: 'int64' },
  { no: 7, name: 'chunkSize', type: 'int32' },
  { no: 8, name: 'createdAt', type: 'int64', rangeBucket: { width: 86400000 }, diskBacked: true },
  { no: 9, name: 'publicSlug', type: 'string', blindIndex: true },
];

function deriveObjectBlobKey(ddk, objectId) {
  return hkdf(ddk, Buffer.alloc(0), Buffer.from(`fitdb-object-blob-v1:${objectId}`), 32);
}

class FitObjectStore {
  constructor({ database, blobBaseDir, chunkSize = DEFAULT_CHUNK_SIZE }) {
    this.database = database;
    this.blobBaseDir = blobBaseDir;
    this.chunkSize = chunkSize;
    this.objects = database.collection('objects'); // must already exist, see defineObjectsCollection
  }

  static async defineObjectsCollection(database, opts = {}) {
    return database.defineCollectionAsync('objects', {
      title: 'Objects', description: 'S3-bucket-style file storage metadata',
      fields: OBJECTS_SCHEMA_FIELDS, ...opts,
    });
  }

  _publicBlobPath(objectId) { return path.join(this.blobBaseDir, 'public', String(objectId)); }
  _privateBlobPath(ownerId, objectId) { return path.join(this.blobBaseDir, 'private', String(ownerId), `${objectId}.enc`); }

  // `source`: a Buffer, or an async-iterable of Buffers (e.g. a Node Readable stream) --
  // either way this streams to disk without buffering the whole object in RAM.
  async putPublicObject({ ownerId, originalFileName, contentType, source }) {
    const objectId = this.objects.generateId();
    const blobPath = this._publicBlobPath(objectId);
    await fsp.mkdir(path.dirname(blobPath), { recursive: true });

    // Public means public: bytes are stored PLAINTEXT. Encrypting them would just relocate
    // the plaintext-exposure point to wherever the "public" decryption key gets handed out
    // (which would have to be to literally anyone, since that's what public means), with no
    // actual confidentiality gained and real complexity added.
    const tmpPath = blobPath + '.tmp';
    const writeStream = fs.createWriteStream(tmpPath);
    let size = 0;
    const iterable = Buffer.isBuffer(source) ? [source] : source;
    for await (const piece of iterable) {
      size += piece.length;
      if (!writeStream.write(piece)) await new Promise((resolve) => writeStream.once('drain', resolve));
    }
    await new Promise((resolve, reject) => writeStream.end((err) => (err ? reject(err) : resolve())));
    await fsp.rename(tmpPath, blobPath);

    const publicSlug = String(objectId);
    await this.objects.insert({
      _id: objectId, ownerId: String(ownerId), visibility: 'public', originalFileName,
      contentType: contentType || 'application/octet-stream', size: BigInt(size),
      chunkSize: 0, createdAt: BigInt(Date.now()), publicSlug,
    });
    return { objectId: String(objectId), url: `/objects/public/${publicSlug}` };
  }

  async putPrivateObject({ ownerId, originalFileName, contentType, source }) {
    const objectId = this.objects.generateId();
    const blobPath = this._privateBlobPath(ownerId, objectId);
    await fsp.mkdir(path.dirname(blobPath), { recursive: true });

    const objectKey = deriveObjectBlobKey(this.database.ddk, objectId);
    await writeEncryptedBlob(blobPath, source, { key: objectKey, objectId, chunkSize: this.chunkSize });
    const header = await readEncryptedBlobHeader(blobPath);

    await this.objects.insert({
      _id: objectId, ownerId: String(ownerId), visibility: 'private', originalFileName,
      contentType: contentType || 'application/octet-stream', size: header.totalSize,
      chunkSize: header.chunkSize, createdAt: BigInt(Date.now()), publicSlug: '',
    });
    return { objectId: String(objectId) };
  }

  async getMeta(objectId) { return this.objects.get(objectId); }

  // The ONLY way to reach private bytes: RBAC-checked (owner or explicit admin override),
  // decrypted chunk by chunk as it streams out. There is no other code path to private blob
  // bytes anywhere in this module.
  async *readPrivateObject(objectId, requesterId, { isAdmin = false } = {}) {
    const meta = await this.objects.get(objectId);
    if (!meta) throw new Error('object not found');
    if (meta.visibility !== 'private') throw new Error('use the public URL for a public object');
    if (meta.ownerId !== String(requesterId) && !isAdmin) throw new Error('permission denied');
    const objectKey = deriveObjectBlobKey(this.database.ddk, objectId);
    const blobPath = this._privateBlobPath(meta.ownerId, objectId);
    yield* readEncryptedBlob(blobPath, { key: objectKey, objectId });
  }

  // Public bytes need no key and no RBAC check by construction (that's what "public"
  // means) -- this is what an HTTP GET handler calls.
  readPublicObjectStream(objectId) {
    return fs.createReadStream(this._publicBlobPath(objectId));
  }

  async findPublicBySlug(slug) {
    const meta = await this.objects.findOne('publicSlug', slug);
    return meta && meta.visibility === 'public' ? meta : null;
  }

  // See the schema comment above: this is the sanctioned way to browse "my objects" --
  // through the plain ownerId index, never through a blind-indexed field.
  async listOwned(ownerId) {
    return this.objects.find('ownerId', String(ownerId));
  }

  async findByExactName(ownerId, originalFileName) {
    const candidates = await this.objects.find('originalFileName', originalFileName);
    return candidates.filter((o) => o.ownerId === String(ownerId));
  }

  async deleteObject(objectId, requesterId, { isAdmin = false } = {}) {
    const meta = await this.objects.get(objectId);
    if (!meta) return false;
    if (meta.ownerId !== String(requesterId) && !isAdmin) throw new Error('permission denied');
    const blobPath = meta.visibility === 'public' ? this._publicBlobPath(objectId) : this._privateBlobPath(meta.ownerId, objectId);
    await fsp.unlink(blobPath).catch(() => {});
    await this.objects.delete(objectId);
    return true;
  }
}

module.exports = { FitObjectStore, OBJECTS_SCHEMA_FIELDS, deriveObjectBlobKey };
