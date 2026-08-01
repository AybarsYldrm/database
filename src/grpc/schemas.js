'use strict';

// Wire schemas for the database services.
//
// Two conventions carried over from the clients already written against this stack:
// message types are named `<Service>_<Method>Req` / `<Service>_<Method>Res`, and dynamic
// record data travels in a `payloadJson` string. The second one is why `InsertRecord` and
// friends look untyped: a collection's schema is defined at runtime, so there is no fixed
// protobuf message that can describe an arbitrary record. `payloadBin` sits alongside it for
// clients that have called DescribeCollection and can use the collection's own TLV encoding
// instead -- same method, same call, roughly 2.5x less on the wire.

const DB = 'DatabaseService';

const DATABASE_SCHEMAS = {
  // ---- lifecycle -------------------------------------------------------------------------
  [`${DB}_CreateDatabaseReq`]: [
    { no: 1, name: 'name', type: 'string' },
    { no: 2, name: 'ownerId', type: 'string' },
  ],
  [`${DB}_CreateDatabaseRes`]: [
    { no: 1, name: 'dbId', type: 'string' },
    // Returned exactly once, never persisted server-side. Losing it means losing the data.
    { no: 2, name: 'clientSecret', type: 'string' },
    { no: 3, name: 'ownerId', type: 'string' },
  ],

  [`${DB}_OpenDatabaseReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'clientSecret', type: 'string' },
    { no: 3, name: 'ownerId', type: 'string' },
  ],
  [`${DB}_OpenDatabaseRes`]: [
    { no: 1, name: 'message', type: 'string' },
    { no: 2, name: 'collections', type: 'string', repeated: true },
    { no: 3, name: 'dbId', type: 'string' },
    { no: 4, name: 'sessionExpiresAt', type: 'int64' },
  ],

  [`${DB}_CloseDatabaseReq`]: [{ no: 1, name: 'dbId', type: 'string' }],
  [`${DB}_CloseDatabaseRes`]: [{ no: 1, name: 'message', type: 'string' }],

  [`${DB}_ListDatabasesReq`]: [{ no: 1, name: 'ownerId', type: 'string' }],
  [`${DB}_ListDatabasesRes`]: [{ no: 1, name: 'payloadJson', type: 'string' }],

  // ---- schema ----------------------------------------------------------------------------
  [`${DB}_DefineCollectionReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'fieldsJson', type: 'string' },
    { no: 4, name: 'title', type: 'string' },
    { no: 5, name: 'description', type: 'string' },
    { no: 6, name: 'compress', type: 'bool' },
    { no: 7, name: 'segmentMaxBytes', type: 'int64' },
    // Redefining an existing collection is a migration. Additive changes and index changes
    // apply automatically; removing a field needs naming it here, because its bytes stay in
    // every record already written and its number is reserved forever afterwards.
    { no: 8, name: 'dropFields', type: 'string', repeated: true },
    // Report what would happen without doing it -- for a deploy-time check, where a refused
    // migration is far better found by a pipeline than by the first write after a rollout.
    { no: 9, name: 'dryRun', type: 'bool' },
    { no: 10, name: 'allowRetype', type: 'bool' },
  ],
  [`${DB}_DefineCollectionRes`]: [
    { no: 1, name: 'message', type: 'string' },
    { no: 2, name: 'created', type: 'bool' },
    { no: 3, name: 'migrated', type: 'bool' },
    { no: 4, name: 'changesJson', type: 'string' },
    { no: 5, name: 'indexesRebuilt', type: 'bool' },
    { no: 6, name: 'schemaVersion', type: 'int32' },
    { no: 7, name: 'reserved', type: 'int32', repeated: true },
  ],

  [`${DB}_DescribeCollectionReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
  ],
  [`${DB}_DescribeCollectionRes`]: [
    { no: 1, name: 'payloadJson', type: 'string' },
  ],

  [`${DB}_ListCollectionsReq`]: [{ no: 1, name: 'dbId', type: 'string' }],
  [`${DB}_ListCollectionsRes`]: [{ no: 1, name: 'payloadJson', type: 'string' }],

  // ---- records ----------------------------------------------------------------------------
  [`${DB}_InsertRecordReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'payloadJson', type: 'string' },
    { no: 4, name: 'payloadBin', type: 'bytes' },
    // Fields that must not already hold this value in a live record. Checked and written as
    // one atomic step, which the read-then-insert equivalent over a network round trip cannot
    // be: two callers racing to certify the same key would both see "absent" and both insert.
    { no: 5, name: 'uniqueFields', type: 'string', repeated: true },
  ],
  [`${DB}_InsertRecordRes`]: [{ no: 1, name: 'recordId', type: 'string' }],

  [`${DB}_GetRecordReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'recordId', type: 'string' },
    { no: 4, name: 'binary', type: 'bool' },
  ],
  [`${DB}_GetRecordRes`]: [
    { no: 1, name: 'payloadJson', type: 'string' },
    { no: 2, name: 'payloadBin', type: 'bytes' },
    { no: 3, name: 'found', type: 'bool' },
    // The AEAD-authenticated per-id counter. A client tracking watermarks uses it to detect a
    // storage node serving a stale-but-authentic record (see version-watermark.js).
    { no: 4, name: 'version', type: 'int32' },
  ],

  [`${DB}_UpdateRecordReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'recordId', type: 'string' },
    { no: 4, name: 'payloadJson', type: 'string' },
    { no: 5, name: 'payloadBin', type: 'bytes' },
    // Optimistic concurrency: refuse the write if the record moved since this version.
    { no: 6, name: 'expectedVersion', type: 'int32' },
  ],
  [`${DB}_UpdateRecordRes`]: [
    { no: 1, name: 'message', type: 'string' },
    { no: 2, name: 'version', type: 'int32' },
  ],

  [`${DB}_DeleteRecordReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'recordId', type: 'string' },
  ],
  [`${DB}_DeleteRecordRes`]: [
    { no: 1, name: 'message', type: 'string' },
    { no: 2, name: 'deleted', type: 'bool' },
  ],

  [`${DB}_FindRecordReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'field', type: 'string' },
    { no: 4, name: 'value', type: 'string' },
    { no: 5, name: 'limit', type: 'int32' },
  ],
  [`${DB}_FindRecordRes`]: [
    { no: 1, name: 'payloadJson', type: 'string' },
    { no: 2, name: 'count', type: 'int32' },
  ],

  [`${DB}_FindRangeReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'field', type: 'string' },
    { no: 4, name: 'min', type: 'string' },
    { no: 5, name: 'max', type: 'string' },
    // false: bucketed blind index (hides order, needs a post-decrypt filter)
    // true:  plain disk-backed ordered scan (server learns real value order)
    { no: 6, name: 'plain', type: 'bool' },
    // Caps how many matching records come back. Without it an open-ended range ("everything
    // due by now") makes the server decrypt and serialize the entire matching set into one
    // message, which both wastes the work the caller was going to discard and can push the
    // response past the transport's per-message limit. Absent/0 means the server's default.
    { no: 7, name: 'limit', type: 'int32' },
  ],
  [`${DB}_FindRangeRes`]: [
    { no: 1, name: 'payloadJson', type: 'string' },
    { no: 2, name: 'count', type: 'int32' },
  ],

  [`${DB}_ScanRecordsReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'afterId', type: 'string' },
    { no: 4, name: 'limit', type: 'int32' },
  ],
  [`${DB}_ScanRecordsRes`]: [
    { no: 1, name: 'payloadJson', type: 'string' },
    { no: 2, name: 'nextCursor', type: 'string' },
    { no: 3, name: 'count', type: 'int32' },
  ],

  [`${DB}_CountRecordsReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
  ],
  [`${DB}_CountRecordsRes`]: [{ no: 1, name: 'count', type: 'int64' }],

  [`${DB}_CompactReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
  ],
  [`${DB}_CompactRes`]: [
    { no: 1, name: 'liveRecords', type: 'int64' },
    { no: 2, name: 'segmentsReclaimed', type: 'int32' },
  ],

  // ---- change stream ------------------------------------------------------------------------
  [`${DB}_WatchCollectionReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'includeSnapshot', type: 'bool' },
    // Resume token from a previous stream's last event. When the server can no longer replay
    // from it, the client is told to re-snapshot rather than handed a silent gap.
    { no: 4, name: 'resumeSeq', type: 'int64' },
  ],
  [`${DB}_WatchCollectionRes`]: [{ no: 1, name: 'payloadJson', type: 'string' }],

  // ---- access control -----------------------------------------------------------------------
  [`${DB}_IssueCapabilityReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'collection', type: 'string' },
    { no: 3, name: 'scope', type: 'int32' },
    { no: 4, name: 'ttlMs', type: 'int32' },
    { no: 5, name: 'singleUse', type: 'bool' },
    { no: 6, name: 'rowFilterJson', type: 'string' },
    { no: 7, name: 'subject', type: 'string' },
  ],
  [`${DB}_IssueCapabilityRes`]: [
    { no: 1, name: 'token', type: 'string' },
    { no: 2, name: 'expiresAt', type: 'int64' },
  ],

  [`${DB}_GrantAccessReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'principal', type: 'string' },
    { no: 3, name: 'mask', type: 'int32' },
  ],
  [`${DB}_GrantAccessRes`]: [{ no: 1, name: 'mask', type: 'int32' }],

  [`${DB}_RevokeAccessReq`]: [
    { no: 1, name: 'dbId', type: 'string' },
    { no: 2, name: 'principal', type: 'string' },
    { no: 3, name: 'mask', type: 'int32' },
  ],
  [`${DB}_RevokeAccessRes`]: [{ no: 1, name: 'mask', type: 'int32' }],

  [`${DB}_WhoAmIReq`]: [],
  [`${DB}_WhoAmIRes`]: [
    { no: 1, name: 'principal', type: 'string' },
    { no: 2, name: 'roles', type: 'string', repeated: true },
    { no: 3, name: 'permissions', type: 'int32' },
    { no: 4, name: 'securityLevel', type: 'string' },
    { no: 5, name: 'certificateFingerprint', type: 'string' },
  ],
};

// Watch stream payload discriminators, shared with the client so neither side hardcodes a
// string the other might change.
const WATCH_EVENTS = Object.freeze({
  SNAPSHOT: 'SNAPSHOT',
  CHANGE: 'CHANGE',
  PING: 'PING',
  RESET: 'RESET',
});

module.exports = { DATABASE_SCHEMAS, WATCH_EVENTS, DB_SERVICE_NAME: DB };
