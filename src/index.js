'use strict';

// Barrel for the engine's internals. `require('@fitfak/database')` resolves to the package
// root index.js, which re-exports everything here plus the gRPC client/server surface;
// `require('@fitfak/database/src')` (and every file under test/) resolves to this one.
// Keeping both in sync matters: the test suite imports '../src', so a symbol that only
// exists in the root barrel is a symbol no test can reach.

const { SnowflakeGenerator } = require('./snowflake');
const { defineBitmask, combine, has, hasAny, AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK } = require('./rbac');
const codec = require('./binary-codec');
const crypto = require('./crypto-core');
const { AsyncQueue } = require('./async-queue');
const { SegmentedLRUCache } = require('./cache');
const { CollectionStorage, UniqueConstraintError } = require('./storage-engine');
const { Collection, Database, deriveCollectionKey, normalizeSchema } = require('./database');
const { DatabaseManager } = require('./database-manager');
const { ClientSecretKeyProvider, MlsExportSecretKeyProvider, StaticKeyProvider, randomClientSecret } = require('./key-provider');
const { CapabilityKeyRing, CapabilityTokenService } = require('./capability-token');
const { DirectAccessServer, OPS: DIRECT_OPS } = require('./direct-server');
const { VersionWatermark } = require('./version-watermark');
const directProtocol = require('./direct-protocol');
const { CryptoWorkerPool, DEFAULT_OFFLOAD_THRESHOLD_BYTES } = require('./crypto-worker-pool');
const { SortedIndexSegment } = require('./sorted-index-segment');
const { SecondaryIndexStore } = require('./secondary-index-store');
const { FitObjectStore, OBJECTS_SCHEMA_FIELDS, deriveObjectBlobKey } = require('./object-store');
const { writeEncryptedBlob, readEncryptedBlob, readEncryptedBlobHeader } = require('./encrypted-blob');
const { createPublicObjectHandler, createPublicObjectServer } = require('./object-http-server');
const { ChangeHub, ReplicatedView, CHANGE_OPS } = require('./change-stream');
const { diffSchemas, planMigration, describeBlockers, SchemaMigrationError, SAFETY: MIGRATION_SAFETY } = require('./schema-migration');
const { SecretStore, SECRETS_SCHEMA_FIELDS, SECRET_KINDS, SECRET_STATES } = require('./secret-store');
const { DnsStore, ZoneCache, DNS_RECORDS_SCHEMA_FIELDS, DNS_RECORD_TYPES } = require('./dns-store');

module.exports = {
  SnowflakeGenerator,
  defineBitmask, combine, has, hasAny, AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK,
  codec, crypto,
  AsyncQueue,
  SegmentedLRUCache,
  CollectionStorage, UniqueConstraintError,
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
  ChangeHub, ReplicatedView, CHANGE_OPS,
  diffSchemas, planMigration, describeBlockers, SchemaMigrationError, MIGRATION_SAFETY,
  SecretStore, SECRETS_SCHEMA_FIELDS, SECRET_KINDS, SECRET_STATES,
  DnsStore, ZoneCache, DNS_RECORDS_SCHEMA_FIELDS, DNS_RECORD_TYPES,
};
