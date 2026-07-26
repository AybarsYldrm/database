'use strict';

const { SnowflakeGenerator } = require('./src/snowflake');
const { defineBitmask, combine, has, hasAny, AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK } = require('./src/rbac');
const codec = require('./src/binary-codec');
const crypto = require('./src/crypto-core');
const { SegmentedLRUCache } = require('./src/cache');
const { CollectionStorage } = require('./src/storage-engine');
const { Collection, Database, deriveCollectionKey, normalizeSchema } = require('./src/database');
const { DatabaseManager } = require('./src/database-manager');
const { ClientSecretKeyProvider, MlsExportSecretKeyProvider, StaticKeyProvider, randomClientSecret } = require('./src/key-provider');
const { CapabilityKeyRing, CapabilityTokenService } = require('./src/capability-token');
const { DirectAccessServer, OPS: DIRECT_OPS } = require('./src/direct-server');
const { VersionWatermark } = require('./src/version-watermark');
const directProtocol = require('./src/direct-protocol');
const { CryptoWorkerPool, DEFAULT_OFFLOAD_THRESHOLD_BYTES } = require('./src/crypto-worker-pool');
const { SortedIndexSegment } = require('./src/sorted-index-segment');
const { SecondaryIndexStore } = require('./src/secondary-index-store');
const { FitObjectStore, OBJECTS_SCHEMA_FIELDS, deriveObjectBlobKey } = require('./src/object-store');
const { writeEncryptedBlob, readEncryptedBlob, readEncryptedBlobHeader } = require('./src/encrypted-blob');
const { createPublicObjectHandler, createPublicObjectServer } = require('./src/object-http-server');

module.exports = {
  SnowflakeGenerator,
  defineBitmask, combine, has, hasAny, AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK,
  codec, crypto,
  SegmentedLRUCache,
  CollectionStorage,
  Collection, Database, deriveCollectionKey, normalizeSchema,
  DatabaseManager,
  ClientSecretKeyProvider, MlsExportSecretKeyProvider, StaticKeyProvider, randomClientSecret,
  CapabilityKeyRing, CapabilityTokenService,
  DirectAccessServer, DIRECT_OPS,
  VersionWatermark,
  directProtocol,
  CryptoWorkerPool, DEFAULT_OFFLOAD_THRESHOLD_BYTES,
  SortedIndexSegment,
  SecondaryIndexStore,
  FitObjectStore, OBJECTS_SCHEMA_FIELDS, deriveObjectBlobKey,
  writeEncryptedBlob, readEncryptedBlob, readEncryptedBlobHeader,
  createPublicObjectHandler, createPublicObjectServer,
};
