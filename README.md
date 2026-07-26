# fitdb

A from-scratch, zero-npm-dependency, encrypted, binary-storage database engine for Node.js.
Every module under `lib/` uses only Node built-ins (`node:crypto`, `node:fs`, `node:zlib`,
`node:net`, `node:tls`, `node:events`).

```
lib/
  snowflake.js          Snowflake ID generator (also used for db ids, capability jti)
  rbac.js                Bitmask permissions + per-database AccessControlList
  async-queue.js         Serializes writes per collection (no interleaved appends)
  crypto-core.js          HKDF/AES-256-GCM/blind-index primitives
  key-provider.js         Pluggable KEK sources: ClientSecretKeyProvider, MlsExportSecretKeyProvider
  crypto-worker-pool.js   Size-gated worker_threads AES-GCM offload (measured, opt-in, off by default)
  binary-codec.js         Schema-driven TLV encoder/decoder (the "more efficient than JSON" layer)
  index-value-codec.js    Shared tagged key codec (snapshot Maps + on-disk sorted segments)
  id-codec.js             Shared id<->8-byte-buffer codec
  cache.js                Segmented LRU (probationary/protected) record cache
  sorted-index-segment.js Real disk-backed sorted structure (SSTable-style: sparse RAM index + on-disk blocks)
  secondary-index-store.js  Bounded-memory memtable+tombstones wrapper around a sorted segment
  storage-engine.js       Encrypted append-only segments, primary+secondary+blind+range indexes, compaction
  version-watermark.js    Client-side rollback/replay detection
  database.js             Collection/Database, per-collection HKDF subkeys, findRange/findRangePlain
  database-manager.js     create/open/close database, manifest, session cache, key rewrap
  capability-token.js     kid+HMAC scoped, single-use, short-lived, row-filterable tokens
  direct-protocol.js      Wire framing (v2: multiplexed, requestId-correlated) for direct access
  direct-server.js        TCP/TLS listener authenticated purely by capability token, SCAN/cursor, object streaming
  encrypted-blob.js       Chunked AEAD encryption for large private object bytes (true streaming)
  object-store.js         FitObjectStore: S3-bucket-style file storage integrated with fitdb
  object-http-server.js   Real HTTP server for public objects (S3 URL pattern)
  index.js                barrel export
examples/
  basic-usage.js                    CRUD, indexing, persistence, compaction, crash recovery
  direct-access-demo.js             multiplexed capability-token access, SCAN, row-scoped tokens
  mls-key-provider-demo.js          pluggable KeyProvider + O(1) MLS-style key rotation
  crypto-offload-demo.js            size-gated worker-pool crypto offload, verified on/off boundary
  index-snapshot-demo.js            persisted secondary/blind index snapshot, measured vs full rebuild
  range-query-demo.js               bucketized range queries, boundary correctness, persistence
  disk-backed-index-demo.js         real disk-backed index: bounded memory (measured), flush/merge correctness
  object-store-demo.js              public/private objects, RBAC, ownerId listing, exact-name blind lookup
  object-store-direct-access-demo.js  public HTTP URL serving + private capability-token gRPC-style streaming
  grpc-integration-sketch.js        illustrative-only wiring into the existing gRPC layer
```

Run `npm test` (or any `node examples/*.js` individually) -- every file under `examples/` is an
executable self-check, not just an illustration.

---

## 1. Key hierarchy

```
root secret                         (clientSecret, OR an MLS group's exportSecret())
  --KeyProvider.deriveKek()-->      KEK
    --HKDF(KEK, 'fitdb-manifest')-> manifestKey    (decrypts manifest.bin: schema + ACL + wrappedDDK)
    --AES-256-GCM unwrap(KEK)-->    DDK             (Database Data Key, 32 random bytes)
      --HKDF(DDK, 'collection:X')-> per-collection key   (encrypts every record in collection X)
        --HKDF(DDK,'blind:field')-> per-field blind-index key (HMAC only, never encrypts)
```

The server persists **only** `wrappedDDK`. Nobody can derive `manifestKey` or unwrap `DDK`
without first being able to derive `KEK`, and `KEK` derivation is delegated entirely to a
`KeyProvider` the storage/database layers never see the internals of. This is what makes
key management swappable without touching storage: `ClientSecretKeyProvider` (a single
32-byte secret, handed out once, for a single-operator database) and
`MlsExportSecretKeyProvider` (an adapter around an existing RFC 9420 MLS group's
`exportSecret()`, for genuinely multi-party databases) both just need to return 32 bytes.

**Honest caveat:** "the server cannot decrypt" is true of data *at rest* -- a copy of the
disk, or of `manifest.bin` + segment files, is useless without the root secret. During a
*live, authenticated session*, the DDK necessarily sits in RAM for as long as the session
cache TTL (`DatabaseManager`'s `sessionTtlMs`, default 15 min) so the engine can actually
encode/decode/index records. That is an inherent property of any queryable (as opposed to
purely blind-blob) encrypted store, not a gap specific to this design -- a memory dump of a
live process during an active session is a different threat than disk theft, and this
system does not claim to defend against the former.

## 2. Storage format

Every record is TLV-encoded (`binary-codec.js`, protobuf-style: field-number tags, varints,
no field names on the wire) before encryption -- roughly 2.5x smaller than the equivalent
JSON in the included benchmark, and unknown field numbers are skipped rather than erroring,
so schemas can gain fields later without invalidating already-written records.

On-disk frame (append-only per collection, `seg-NNNNNN.log`):

```
[op:1][flags:1][id:8 BE][version:4 BE][payloadLen:4 BE][payload = iv(12)+tag(16)+ciphertext]
```

`payload` is AES-256-GCM over the (optionally zlib-deflated) encoded record, with
`AAD = id ++ op ++ flags ++ version`. Binding `version` into the AAD is what makes a
monotonic per-id counter tamper-evident: a storage node cannot serve an older, perfectly
authentic frame for the same id without a client tracking version watermarks
(`version-watermark.js`) being able to detect the regression. See "Threat model" below --
this closes the rollback/replay gap that a bare AEAD scheme leaves open.

Recovery on open: a binary `index.snapshot` (primary index only: id -> segment/offset/
length/version/flags/deleted) means a clean-close-then-reopen doesn't replay any data at
all; an unclean shutdown replays only the tail past the snapshot's last recorded position,
not the whole collection. Secondary/blind indexes are rebuilt at open time by seeking
directly to each live record's known offset (via the now-fast primary index) and decrypting
just that record -- O(live records), not O(bytes on disk).

Compaction copies live *frames* byte-for-byte into a fresh segment (no decrypt/re-encrypt
needed, since AAD only binds id/op/flags/version, all unchanged by relocation) and deletes
the old segment files.

## 3. Capability tokens (the "database server as its own edge" path)

```
client --edge-mediated--> edge/gateway --RBAC-checked--> database
client --direct (capability token)------------------------> database
```

`DatabaseManager.openDatabase()` (called by whoever holds edge-level RBAC authority) warms
a database's DDK into memory. From then on, `IssueCapability`-style calls (see
`examples/grpc-integration-sketch.js`) mint a **kid+HMAC, scoped, short-lived, single-use**
token (`capability-token.js`) that a client can present directly to `direct-server.js`'s
TCP/TLS listener, with no further round trip through the gateway for that operation:

- `kid` lets signing keys rotate without invalidating every outstanding token.
- `scope` is a `DB_PERMISSIONS` bitmask, and must be a subset of the issuer's own ACL mask
  for that database -- a capability can only narrow authority, never grant more of it.
- `jti` (Snowflake) + `singleUse` enforce replay rejection via a small pruned-by-expiry set.
- TTLs are meant to be short (seconds), unlike the ~1h main session token.

This directly matches the "geçici hmac + kid... küçük yetkiler içerir" design from the
original brief.

## 4. On the pasted MLS/gRPC design documents

Those documents were engaged with as a design proposal to critique and build from, per the
explicit request at the end of the first one -- not as an unconditional spec, regardless of
how directively later drafts of it were phrased. Where this project agrees, disagrees, or
answers an open question differently, briefly:

- **MLS-as-KEK-source, not as a record cipher**: agreed, and it's exactly what
  `MlsExportSecretKeyProvider` implements. `rewrapDatabaseKey()` gives the O(1) rotation
  the docs describe -- re-wrap the *same* DDK under a new KEK, zero record/segment I/O,
  verified end to end in `examples/mls-key-provider-demo.js`.
- **Is full MLS warranted here?** For a genuinely single-operator database (one person,
  own devices/sessions, nobody else ever joins), probably not -- epoch ratcheting exists to
  make *group* rekeying on join/leave cheap, which has no payoff at group size 1.
  `ClientSecretKeyProvider` covers that case with a single static secret. MLS earns its
  keep specifically once real multi-party sharing exists (RFC 0002's User A <-> User B
  scenario) -- the pluggable interface means that switch costs nothing in the storage layer
  whenever it becomes real, rather than needing it to be true on day one.
- **AES Key Wrap (RFC 3394) vs AES-256-GCM for wrapping the DDK**: kept AES-256-GCM (what's
  already implemented for records). AES-KW's main advantage is legacy interop (PKCS#11,
  JOSE `A256KW`); it doesn't buy anything here that reusing one well-analyzed,
  hardware-accelerated AEAD for both records and key-wrapping doesn't already provide, and
  it avoids maintaining two different constructions.
- **Per-collection DDK**: implemented as `HKDF(DDK, 'collection:'+name)` rather than an
  independent random key per collection -- same compromise-isolation property, zero extra
  wrapped-key bookkeeping in the manifest. A fully independent key only pays for itself if a
  single collection needs to be shared/rotated without touching the rest of the database, at
  which point it likely deserves to be its own database rather than a collection of a shared
  one.
- **Per-document keys** (`HKDF(DDK, docId)`): not implemented, deliberately. AES-GCM with a
  random 96-bit nonce per record (already the design) gives strong CPA resistance on its
  own; per-document key derivation would only start to matter somewhere past ~2^32 records
  under one key, far beyond this system's scale.
- **Blind-index frequency analysis**: real, and not solved here beyond noting the mitigation
  space -- bucket/coarsen low-cardinality or highly sensitive fields rather than indexing
  exact values, and treat true frequency-hiding SSE as a research-grade separate project, not
  something to bolt on ad hoc.
- **"Cryptographically blind" needs a precise boundary.** A server holding a blind-indexing
  key (BIK) -- RFC 0002's "constrained client" -- is blind to *payload plaintext* but not
  blind to *which records share an equal value* for any blind-indexed field. That's the same
  property this project's own `blindIndex` fields already have. Worth stating precisely
  rather than accepting an unqualified "the server cannot inspect the data" for a design that
  hands the server a working equality trapdoor for some fields.
- **Rollback/snapshot replay by the storage node**: this was a real gap in the first version
  of this engine (AAD bound id+op+flags but no freshness signal across writes). Fixed by
  folding a monotonic per-id `version` into the AEAD AAD and giving clients
  `version-watermark.js` to detect a storage node serving a stale-but-authentic frame -- see
  `getWithVersion()` / the rollback check in `direct-access-demo.js`.
- **EMFILE at scale**: the first version of `storage-engine.js` opened one read file handle
  per segment and never closed any of them. `_getReadFd()` is now a small LRU-bounded pool
  (`maxOpenReadFds`, default 64) -- verified with a synthetic 150-segment stress test that
  never exceeds the configured cap regardless of access pattern.
- **Worker-thread offloading for crypto/zlib**: not applied. Node's AES-GCM and zlib calls
  are native (OpenSSL/zlib under the hood) and fast on the record sizes this engine targets;
  the "MUST offload to Worker Threads" directive reads like it's aimed at a much
  higher-throughput multi-tenant deployment than what's being built for right now. Worth
  revisiting if record sizes or write rates grow by orders of magnitude, not before.
- **Multi-tenancy, backups, recovery, cluster sync** (open questions #6-#9): mostly already
  free or straightforward given the existing partitioning --  every `(ownerId, dbId)` is
  already fully isolated with its own derived key; a raw copy of a database's directory
  *is* an encrypted backup; cluster sync of a ~60-byte wrapped key is not a hard consensus
  problem. Lost-credential recovery (an escrow/recovery-code wrapped-DDK entry) is not
  implemented and is a reasonable, small future addition, not a redesign.

## 5. Responses to the RFC 0003 scaling directive

RFC 0003 asked for disk-backed indexes, connection multiplexing, row-level ACL, range
queries, and worker-thread offloading. Same posture as with the earlier documents: engaged
with as a scaling proposal to weigh against the current single-operator deployment context,
not executed as an unconditional checklist. What actually shipped, and why, per item:

### 5.1. Disk-backed secondary/blind indexes -> persisted index snapshots (not a B-tree)
The directive's real underlying complaint was boot time (`O(live records)` decrypt cost on
every open), which does not actually require a persistent B-tree/LSM to fix. Implemented
instead: the binary `index.snapshot` now also persists the secondary and blind index tables
(not just the primary id->location index), with the same snapshot+tail-replay recovery
discipline already used for the primary index. Measured on 3000-4000 records with 2 indexed
fields: **4-11x faster reopen** than the full decrypt-based rebuild (varies by run; see
`examples/index-snapshot-demo.js`, which asserts the snapshot path beats the full-rebuild
path rather than just asserting a hardcoded number). A hand-rolled on-disk B-tree was
deliberately NOT built in this pass: correctness bugs in page-splitting/WAL-interaction are
exactly the subtle, hard-to-catch-by-casual-testing kind of bug (this session already found
and fixed two real ones -- the FD leak and the rollback gap -- through careful review, which
is evidence rushing a much harder data structure is risky, not a reason to avoid the review).
A real disk-backed structure was still built, just one iteration later -- see §6.

### 5.2. Connection multiplexing + SCAN/cursor
Implemented for real: `direct-protocol.js` v2 adds a `requestId` to both frames (a breaking,
clean replacement of v1 -- nothing had shipped against v1 yet), `direct-server.js` keeps a
connection open across many requests (idle-timeout bounded) instead of one-shot-per-socket,
and a `SCAN` opcode paginates a collection via an id-based cursor (Snowflake ids are roughly
time-ordered, so "id > cursor" gives stable pagination without a separate sorted structure).
`examples/direct-access-demo.js` fires 30 concurrent requests over one connection and
verifies every response is matched back to its request by `requestId` regardless of
completion order, plus a full multi-page SCAN.

### 5.3. Row-level access control -> row-*filtered capability tokens (not general ACL)
Implemented the narrow, precise version: `CapabilityTokenService.issue()` accepts an
optional `rowFilter: {field, value}`; `direct-server.js` enforces it against the decrypted
record for GET/FIND_ONE/SCAN (hides non-matching records as if they didn't exist) and PUT
(refuses to write a record that doesn't satisfy the filter). This is an authorization check
on already-decrypted plaintext -- the same trust tier as the rest of the direct-access path,
**not** a blind/searchable-encryption-level guarantee that the enforcing party never sees
what it's filtering on. True row-level ACL enforced *without* the enforcer seeing plaintext
is an attribute-based-encryption-class problem; general `allowedMembers` arrays and
multi-member predicates were not built since no concrete need for them exists yet in a
single-operator deployment -- `rowFilter.value` naturally generalizes to
`allowedMembers.includes(...)` if/when it does.

### 5.4. Worker-thread CPU offloading -> measured, then scoped narrowly (not general)
Benchmarked before writing any integration code (see the numbers in `crypto-worker-pool.js`
and this session's history): for fitdb's realistic record sizes, dispatching AES-256-GCM to
`node:worker_threads` is **slower**, not faster -- 1KB payloads: ~7x slower; 20000x200B
records batched up to 1000-per-message: still ~3.4-3.7x slower. Message-passing/structured-
clone overhead dominates at these sizes regardless of batching strategy. The crossover to a
real win only appears around **~100-128KB single payloads under real concurrent load**
(a pool of workers each handling a different large payload, not one worker processing many
small ones sequentially). fitdb records are small structured rows; large blobs already have
a dedicated path in the existing S3-like ObjectStoreService, not this engine. Built
accordingly: `CryptoWorkerPool` is opt-in and size-gated (default 128KB threshold) via
`CollectionStorage`'s `cryptoOffload` option; below the threshold, behavior is byte-for-byte
identical to no pool at all (verified in `examples/crypto-offload-demo.js`, which confirms
zero pool invocations for small records and correct round-tripping for a 200KB one). No
general-purpose worker pool was wired into the default put/get path, because the measurements
say that would be a regression for the common case, not an optimization.

### 5.5. Range queries -> bucketized/coarsened blind indexing (explicitly not OPE)
A schema field can set `rangeBucket: { width }`; the stored index entry is a blind-indexed
*bucket* (`floor(value/width)`), not the value itself. `Collection.findRange(field, min,
max)` enumerates the buckets overlapping `[min,max]`, gathers candidates, decrypts, and
applies an exact filter. This is deliberately **not** Order-Preserving Encryption: a real OPE
scheme is a research-grade primitive (subtle security properties, easy to implement
incorrectly in a way that looks fine but leaks far more than intended), and hand-rolling one
here would be worse than being upfront about not attempting it. Bucketing's leakage is
explicit and tunable: the server learns which bucket a record falls into (e.g. "which day"
for a day-width bucket), not its exact value or its relative order versus other records
outside shared buckets -- narrower leakage than OPE by construction, at the cost of
imprecise buckets needing a post-decrypt filter. Verified in `examples/range-query-demo.js`
for boundary correctness (single-bucket-width windows, multi-bucket windows, empty ranges)
and persistence across a reopen.

## 6. Real disk-backed indexes (bounded memory, not just persisted)

§5.1 shipped persisted-but-fully-RAM-resident secondary/blind/range indexes. This section is
the actual disk-backed structure: mark a field `diskBacked: true` (alongside `index`,
`blindIndex`, or `rangeBucket`) and its index moves to `SecondaryIndexStore`
(`secondary-index-store.js`), backed by `SortedIndexSegment` (`sorted-index-segment.js`) --
an SSTable-style file (sorted data blocks + a sparse in-memory index, one entry per ~128
keys, in the spirit of LevelDB/RocksDB). Writes land in a small bounded memtable; once it
exceeds `flushThreshold` (default 2000) it is merge-sorted against the existing on-disk
segment and rewritten as a fresh immutable file (old one discarded) -- the same
never-mutate-in-place, always-write-new-and-swap discipline used everywhere else in fitdb.

Measured on 5000 records with a 300-entry flush threshold: **only ~200 entries ever sit in
the memtable and only ~38 sparse-index blocks are RAM-resident** for the whole field, versus
5000 if it were a plain Map (`examples/disk-backed-index-demo.js` asserts this directly, not
just prints it). Also new: `findRangePlain(field, min, max)` for a plain (non-blind, non-
bucketed) `diskBacked` numeric field, doing a genuine ordered range scan on disk via the
segment's sorted blocks -- the confidentiality trade-off is explicit: unlike `rangeBucket`,
this field's real value order is visible to the server, so only use it where that's fine.

Deliberately simplified relative to a full multi-level LSM: exactly one on-disk segment at a
time, fully rewritten on every flush (O(total entries) I/O per flush, not O(memtable size)).
That trades some flush-time I/O for a much smaller, more auditable correctness surface --
worth it at this project's scale; revisit with leveled compaction only if flush cost is ever
actually measured to matter.

## 7. Object store: S3-bucket logic integrated with fitdb (`object-store.js`)

`FitObjectStore` wraps a fitdb `Database`: object *metadata* (owner, visibility, filename,
size, content-type, timestamps) is a normal fitdb collection (reusing RBAC, Snowflake ids,
and the indexes from §7 directly); object *bytes* live on disk, split by visibility exactly
as requested:

- **Public** (`putPublicObject`): bytes stored **plaintext**, served by a real, tested HTTP
  server (`object-http-server.js`) at `GET /objects/public/<slug>` -- genuine S3-style
  unauthenticated URL access. Encrypting public bytes would only relocate the exposure point
  to wherever the key gets handed out (which would have to be "anyone", since that's what
  public means), for zero actual gain.
- **Private** (`putPrivateObject`): bytes are **chunked-AEAD-encrypted** (`encrypted-blob.js`)
  -- each fixed-size chunk is its own independent AES-256-GCM frame (AAD-bound to
  objectId+chunkIndex), the same reasoning already applied to every database record: a
  single whole-file AEAD tag would force buffering the entire file to encrypt or verify,
  which doesn't scale. This lets both writing and reading stream at O(chunkSize) memory
  regardless of object size (verified with a multi-chunk, non-block-aligned object; tamper
  and truncation are both independently caught, per `examples/object-store-demo.js`).
  Private bytes are reachable **only** through `direct-server.js`'s new `OBJECT_DOWNLOAD`
  opcode, capability-token-gated exactly like every other direct-access operation (owner-only
  by default via the token's `sub`, or cross-owner with an `ADMIN`-scoped token) -- this is
  the "already gRPC-based, security completed" private path from the request: no alternate
  route to private bytes exists anywhere in this module.

### 8.1. Collection titles
`defineCollection(name, { title, description, fields })` persists a human-readable
title/description in the manifest (`Database.listCollectionInfo()` reads them back) -- e.g.
`FitObjectStore.defineObjectsCollection` sets title `"Objects"`. Purely a display/UI
convenience; has no effect on storage or indexing.

### 8.2. Blind search cannot enumerate -- and this store never tries to make it
A blind index answers exactly one question: "does a record with this *exact, already-known*
value exist" -- structurally, not as an implementation gap, it cannot answer "list
everything", because doing so would mean testing every possible value against the index,
which is precisely the plaintext-searchable structure blind indexing exists to avoid handing
the server. `object-store.js`'s schema reflects this on purpose: `ownerId` is a **plain**
index (the server already has to know ownership to do RBAC at all, so this isn't a new
disclosure) and is what `listOwned(ownerId)` is built on; `originalFileName`/`publicSlug`
stay blind-indexed and are used **only** for exact-match lookups (`findByExactName`,
`findPublicBySlug`), never for browsing. `examples/object-store-demo.js` exercises both
paths side by side so the distinction is concrete, not just asserted in a comment.

## 8. A recurring gotcha worth flagging explicitly: `_id` is BigInt, most other "id" values are strings
A decoded record's `_id` (and any `int64`/`uint64` field) is a **BigInt** -- necessary since
JS `Number` silently loses precision above 2^53 and Snowflake ids exceed that. But
`Collection.insert()` returns a **string**, as do `dbId`, capability-token `sub`, and most
function parameters named `id`. `bigintValue === stringValue` is always `false` in JS (no
implicit coercion under `===`), so comparing an id fresh out of a decoded record against one
of those string-typed values needs an explicit `String(...)` (or `BigInt(...)`) on one side.
This bit the test suite itself three separate times while building this project -- worth
naming plainly here rather than leaving it as a silent trap, since a real caller is exactly
as likely to hit it.

## 9. Known limitations / good next steps
- `SecondaryIndexStore` keeps exactly one on-disk segment (§7); a flush costs O(total field
  entries), not O(memtable size) -- fine unless a field's total entry count gets very large
  *and* writes are frequent enough for flush cost to show up, at which point leveled
  compaction (multiple segments, lazily merged) is the natural next step.
- `direct-server.js`'s SCAN still sorts the full remaining candidate set per page call
  (O(n log n)); a collection that outgrows this should move its ordering field to a
  `diskBacked` plain index and paginate via `findRangePlain`-style disk-backed ordering
  instead of the generic id-cursor SCAN.
- No hardware-enclave-backed key caching; would require native bindings (SGX/TPM), out of
  scope for a pure Node-built-ins implementation.
- The direct-access object-download protocol is JSON+base64 framed (~33% overhead on wire),
  consistent with this channel's existing "control-plane simplicity over wire efficiency"
  tradeoff (see direct-protocol.js) -- real binary framing is a contained follow-up if object
  transfer volume ever makes that overhead matter.
