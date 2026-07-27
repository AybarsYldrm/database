# @fitfak/database

An encrypted, binary-storage database engine for Node.js, plus an mTLS gRPC server and client
for reaching it across a network. The engine itself uses only Node built-ins; the transport
layer uses `@fitfak/grpc`, which does too.

Three layers, each usable on its own:

```
src/                    the engine — encrypted append-only storage, indexes, object store
src/grpc/               DatabaseService: server and client, mTLS-authenticated
src/provisioning/       how a service with no certificate gets one
```

`require('@fitfak/database')` in a CLI tool does not drag in an HTTP/2 server — the transport
and provisioning modules load on first use.

```
src/
  snowflake.js            Snowflake ID generator (db ids, record ids, capability jti)
  rbac.js                 Bitmask permissions + per-database AccessControlList
  async-queue.js          Serializes writes per collection
  crypto-core.js          HKDF / AES-256-GCM / blind-index primitives
  key-provider.js         Pluggable KEK sources: ClientSecret, MLS export secret
  crypto-worker-pool.js   Size-gated worker_threads AES-GCM offload (measured, off by default)
  binary-codec.js         Schema-driven TLV codec — the "smaller than JSON" layer
  cache.js                Segmented LRU record cache
  sorted-index-segment.js SSTable-style on-disk sorted index
  secondary-index-store.js Bounded-memory memtable + tombstones over that segment
  storage-engine.js       Encrypted segments, primary/secondary/blind/range indexes, compaction
  change-stream.js        Ordered change events with gap detection — the alternative to polling
  schema-migration.js     Schema diffing: what may change, what must be rebuilt, what is refused
  version-watermark.js    Client-side rollback/replay detection
  database.js             Collection/Database, per-collection subkeys, watch(), snapshot()
  database-manager.js     create/open/close, manifest, session cache, O(1) key rewrap
  capability-token.js     kid+HMAC scoped, single-use, row-filterable tokens
  direct-protocol.js      Multiplexed wire framing for capability-token direct access
  direct-server.js        TCP/TLS listener authenticated purely by capability token
  encrypted-blob.js       Chunked AEAD for large object bytes (true streaming)
  object-store.js         S3-bucket-style file storage integrated with the engine
  object-http-server.js   HTTP server for public objects
  secret-store.js         Certificates, keys and tokens — versioned, expiry-queryable
  dns-store.js            Authoritative DNS zones + an always-current in-memory ZoneCache
  grpc/
    schemas.js            Wire schemas for DatabaseService
    server.js             DatabaseServer — every method mTLS-gated
    client.js             connectDatabase, RemoteCollection, WatchedCollection
    identity.js           client certificate → principal → per-database ACL
    record-codec.js       JSON/TLV payloads, int64-safe
  provisioning/
    enrollment-service.js Registration Authority: bootstrap and renewal endpoints
    enrollment-client.js  enrol → upgrade to mTLS → auto-renew
    attestor.js           who may enrol as what (pluggable per service)
    ca-backend.js         where certificates come from (@fitfak/ssl, ACME, custom)
    csr-provider.js       key generation and CSR construction
```

`npm test` runs thirteen suites; every file under `test/` is an executable self-check.

### Installing

The engine has **no dependencies** — `npm run test:engine` (ten suites) runs from a bare
checkout. The gRPC layer needs `@fitfak/grpc`, which is a sibling package in this stack rather
than a third-party one; vendoring a second copy of it here would be worse than depending on
it. Until it is published:

```sh
npm run link:grpc                     # side-by-side checkout at ../grpc
node scripts/link-grpc.js /path/to/grpc
```

`@fitfak/ssl` is an **optional** peer dependency, needed only by the `@fitfak/ssl` CA and CSR
adapters. A deployment using ACME, or one whose certificates are managed entirely outside this
process, never loads it.

---

## 1. Getting a client connected

The central question this package answers is not "how do I query the database" but "how does a
service that has never run before get permission to". The data plane is mTLS-only, so a
service needs a client certificate — and it cannot have one until something has vouched for
it.

```
  1. bootstrap TLS      server proves who it is; client proves nothing yet
  2. fetch anchors      the CA bundle, so the client can verify the server from now on
  3. enrol              prove entitlement, submit a CSR, receive a certificate
  4. upgrade            same client object, now mutually authenticated
  5. steady state       everything else, mTLS only
  6. renew              over mTLS, well before expiry — no bootstrap credential involved
```

That is RFC 7030 (EST) semantics carried over gRPC. In this stack the CA is central (the ACME
authority at `trust.fitfak.net`), and **this server is a Registration Authority, never a CA**:
it authenticates the bootstrapping peer and decides what identity it may hold, then delegates
the signature. It holds no signing key.

### Client side

```js
const { enroll, connectDatabase, createFitfakSslCsrProvider } = require('@fitfak/database');

const identity = await enroll({
  target: 'https://db.internal.fitfak.net:8443',
  serviceName: 'idp-service',
  csrProvider: createFitfakSslCsrProvider(),
  trust: { pinnedFingerprints: [process.env.DB_CA_FINGERPRINT] },
  bootstrap: { secret: Buffer.from(process.env.ENROLMENT_SECRET, 'base64') },
  altNames: ['idp.internal.fitfak.net'],
});

identity.startAutoRenewal();          // renews at ~2/3 of the certificate's lifetime
const handle = await connectDatabase({ target, identity });
```

`identity.client` is already upgraded to mTLS. Renewal generates a **fresh key pair** rather
than re-certifying the old one: renewing onto the same key would carry any past exposure
forward for another full lifetime.

### Server side

```js
const { createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
        createCompositeAttestor, createAcmeCaBackend } = require('@fitfak/database');

const server = createDatabaseServer({
  baseDir: '/var/lib/fitdb',
  principals: {
    'idp-service':  { roles: ['admin'] },
    'dns-resolver': { roles: ['reader'] },
  },
  enrollment: {
    caBackend: createAcmeCaBackend({ acme, trustAnchorsPem: [caPem] }),
    attestor: createCompositeAttestor([
      createSharedSecretAttestor({ enrolments: { 'idp-service': { secret, roles: ['admin'] } } }),
      createRenewalAttestor(),
    ]),
  },
});

server.listen(8443, { tls: { key, cert, ca, requestCert: true, rejectUnauthorized: false } });
```

`requestCert: true, rejectUnauthorized: false` is what lets one port serve both channels: every
client is asked for a certificate, a client without one still completes the handshake, and the
per-method security level does the rest. Enrolment declares `minSecurityLevel: 'tls'`; every
`DatabaseService` method declares `'mtls'`. The transport enforces this **before** the handler
runs, so it cannot be forgotten in a handler.

### The three ways to trust the server on first contact

Until a peer has a certificate it cannot authenticate itself, but it must still authenticate
the server it is about to hand an enrolment credential to. `enroll()` refuses to proceed
without one of:

| `trust` | What it means |
|---|---|
| `{ caPem }` | The CA bundle was delivered out of band. Verified during the handshake. Preferred. |
| `{ pinnedFingerprints }` | Verified immediately after connect, against the leaf **or** a trust anchor. Pinning the CA survives a legitimate server-certificate rotation; pinning the leaf does not. |
| `{ trustOnFirstUse: true }` | Explicitly accepting an unverified first connection. Logged loudly. |

Trust anchors are fetched before verification completes — they are public data and the request
carries no credential. **Nothing secret is sent until verification has settled.**

### What the enrolment proof binds to

```
HMAC(secret, "fitdb-enroll-v1" ‖ serviceName ‖ nonce ‖ timestamp ‖ channelBinding ‖ SHA256(csr))
```

Each element closes a specific hole:

- **`channelBinding`** — the RFC 9266 `tls-exporter` value. Without it, anyone who can observe
  the bootstrap exchange, including a proxy that terminates TLS, can replay the proof on their
  own connection. The test suite demonstrates the relay being rejected.
- **`SHA256(csr)`** — without it, an interceptor can keep a valid proof and substitute a CSR
  over a key they control, and the CA will certify the attacker's key under the victim's name.
- **`nonce`** — burned unconditionally, whether or not the enrolment succeeds.
- **`timestamp`** — bounds how long a captured proof stays useful.

A bootstrap credential is **single-use by default**; renewal goes through the mTLS path, which
needs no secret at all. A use is spent only once a certificate has actually been issued — an
authenticated request rejected downstream (wrong CN, CA unreachable) leaves the credential
usable, so a recoverable mistake does not become a re-provisioning job.

The CSR is checked against the grant on **both** CN and SAN. Checking only the CN would leave
the field most TLS stacks actually match on unchecked.

### Other services, other mechanisms

`createSharedSecretAttestor` is the bootstrap case. Once an IdP exists, `createTokenAttestor`
delegates the decision to it; a device might present a TPM attestation; a workload might
present a platform token. `createCompositeAttestor` runs several, so one endpoint serves a
bootstrapping IdP, an IdP-issued workload token and an ordinary renewal.

---

## 2. Using the database

The remote API mirrors the embedded one, so code moves between them by changing how the handle
is obtained and nothing else.

```js
const db = await handle.openDatabase({ dbId, clientSecret });

await db.defineCollection('kullanicilar', {
  fields: [
    { no: 2, name: 'email',    type: 'string', blindIndex: true, required: true },
    { no: 3, name: 'tenant',   type: 'string', index: true },
    { no: 4, name: 'createdAt', type: 'int64', rangeBucket: { width: 86400000 }, diskBacked: true },
  ],
});

const users = db.collection('kullanicilar');
const id = await users.insert({ email: 'a@fitfak.net', tenant: 'core', createdAt: Date.now() });
await users.findOne('email', 'a@fitfak.net');
await users.findRange('createdAt', weekAgo, now);
for await (const record of users.scan()) { /* pages transparently */ }
```

`clientSecret` is returned by `CreateDatabase` exactly once and is never persisted
server-side. Losing it means losing the data.

**int64 and ids.** JSON has no int64, and every Snowflake id is above 2^53, so `JSON.parse`
would silently round them — insert a record, read it back, get a *different id*. Ids and int64
fields therefore cross the wire as strings and are coerced back by schema type. A JSON number
that has already lost precision is rejected rather than stored corrupted.

**Optimistic concurrency.** `update(id, patch, { expectedVersion })` returns `ABORTED` if the
record moved. Without it, two concurrent read-modify-write callers silently lose one write.

### Schema evolution

Redefining a collection with an extra field is a **migration**, not a no-op. (It used to be a
no-op: the new field was absent from the in-memory schema, so the encoder had no tag for it,
every value written to it was discarded, `get()` never returned it and `find()` threw "no such
field" — with no error anywhere. Adding a field and redeploying is ordinary, so it has to work
or fail loudly.)

```js
await db.defineCollection('certificates', {
  fields: [...existing, { no: 14, name: 'skidHex', type: 'string', index: true }],
});
// → { migrated: true, indexesRebuilt: true, schemaVersion: 2, changes: [{ kind: 'add-field', ... }] }
```

Field **number** is identity — it is what is written to disk; the name only exists in the
schema. So the rules follow from the wire format:

| Change | Result |
|---|---|
| new field number | applied. Older records simply lack it, as in protobuf |
| index added/changed/removed | applied, index rebuilt from the stored records |
| field renamed (same number) | applied — matching is by number, so this is a rename, not a drop plus an add |
| **type changed** | **refused.** Every stored record carries bytes under that tag and would decode as the new type |
| **field removed** | **refused** unless named in `dropFields`; its number is then reserved forever |
| **reserved number reused** | **refused.** Records written while it was live still carry bytes under that tag |

The last one is the trap that arrives months late: a field is dropped, and someone later picks
a number that looks free. The manifest records `reserved` per collection, so it is caught at
definition time rather than surfacing as corrupted reads.

Whole registries — the shape a project's `schemas.js` already has — go through in one call,
and are **all-or-nothing**: every collection is checked first, and one refusal blocks the set.
A half-applied migration leaves the application facing a schema that is half old and half new.

```js
await db.applySchemaRegistry(require('./schemas'));                 // embedded
await remoteDb.applySchemaRegistry(require('./schemas'));           // over gRPC
db.inspectMigration('certificates', fields);                        // dry run, no writes
await remoteDb.defineCollection('certificates', { fields, dryRun: true });
```

`inspectMigration` / `dryRun` exist for a deploy-time check: a refused migration is far better
found by a pipeline than by the first write after a rollout.

**Binary payloads.** After `describe()`, a client can send `payloadBin` — the collection's own
TLV encoding — instead of `payloadJson`: same method, roughly 2.5x less on the wire.

### Existing clients

`DatabaseService` is wire-compatible with the hand-written schema map already deployed in the
IdP's `grpc-db-adapter`: `OpenDatabase`, `InsertRecord`, `UpdateRecord`, `DeleteRecord` and
`FindRecord` keep their field numbers, and the fields added since (`collections`,
`sessionExpiresAt`, `payloadBin`, `expectedVersion`) sit at numbers that adapter does not
declare, so proto3 skips them. `find('_id', id)` and `find('*', '')` are special-cased so the
adapter's `get()` and `scan()` work unchanged. `test/adapter-compat-demo.js` pins this by
running that adapter's exact schema map against the server.

The one change an existing adapter does need is transport-level: the data plane is mTLS-only,
so `{ rejectUnauthorized: false }` with no client certificate is no longer sufficient. Pass
real credentials, or enrol for them.

---

## 3. Not polling

Two workloads motivated the change stream, and both are unworkable with per-read decryption:

- **DNS**, answered at query rate. Every answer would be a round trip plus a decrypt, for data
  that changed hours ago.
- **Certificates and keys**, where a stale cache means a service is still presenting a
  certificate that was rotated away.

```js
const view = users.watch();
await view.ready();

view.get(id);     // map lookup, no network, no decrypt
view.all();
view.fresh;       // false when the stream reported a gap
```

Correctness rests on two things the server provides. Every event carries a **per-collection**
sequence number as well as a global one — a watcher following one collection must check
contiguity on the per-collection counter, because writes to *other* collections consume global
numbers and would look like gaps. And when the server can no longer prove continuity it sends
an explicit **RESET** rather than a stream with a hole in it.

`Database#snapshot()` reads its sequence counters **before** scanning, not after. Reading after
would let a write that landed mid-scan be both missed by the scan and covered by the returned
counter — the watcher would discard its event as already-applied and serve a view missing that
record forever. Reading first can only cause the harmless opposite: a re-applied change.

Reconnection uses full jitter. A fixed retry interval turns a server restart into a
synchronised stampede from every watcher at once.

---

## 4. Secrets: certificates and keys

```js
const vault = await SecretStore.open(db);

await vault.putCertificate({ name: 'api.fitfak.net', certPem, privateKeyPem, chainPem });
const pair = await vault.getCertificatePair('api.fitfak.net');   // ready for a TLS context

await vault.listExpiring(30 * 86400000);   // what needs renewing
```

A private key written into a collection is encrypted at rest with the same construction as
every other record — a copy of the data directory is useless without the root secret. A PEM
file in `/etc` is not. **This is not an HSM**: material is decrypted into process memory
whenever it is read, exactly like every other record. If the threat model includes a memory
dump of a live process, the answer is a TPM/HSM-backed signer that never releases the key,
not a different database.

Expiry and fingerprint are read out of the certificate rather than taken from the caller — an
expiry sweep that depends on a caller remembering to pass `notAfter` is a sweep that misses
things.

**Rotation is a transition, not a cutover.** Versions are never overwritten. A new version can
be staged as `PENDING` and promoted later; the superseded version is `RETIRED`, not deleted, so
a consumer that has not yet reloaded still has something real to verify against.
`markCompromised()` marks and records a reason but does **not** erase — incident response needs
to know what was exposed — and it is the local half of a revocation only; revoking at the CA
is the CA's job.

Browsing goes through `kind` (a plain index), never through `name` (blind-indexed). That
asymmetry is deliberate: the set of secret *kinds* in use is not sensitive, the set of secret
*names* is.

---

## 5. DNS

```js
const dns = await DnsStore.open(db);
await dns.put({ zone: 'internal.fitfak.net', name: 'db.internal.fitfak.net',
                type: 'A', ttl: 300, rdata: { address: '10.0.0.10' } });

const cache = await dns.zoneCache('internal.fitfak.net');
cache.query('anything.apps.internal.fitfak.net', 'A');
// → { status: 'NOERROR', records: [...], chain: [] }
```

`resolve()` does an exact `(name, type)` lookup through the blind index — correct, but one
decrypt per call. `zoneCache()` is the intended way to serve traffic: one snapshot, then the
change stream.

Everything a resolver needs that a blind index *cannot* provide happens against the decrypted
zone, because all of it requires knowing what is **absent**, and an index that cannot enumerate
can never establish absence:

- **NODATA vs NXDOMAIN.** A missing type at an existing name is `NOERROR` with no records.
  Answering `NXDOMAIN` there tells the world the name does not exist and breaks every other
  type at it.
- **Wildcards**, per RFC 4592 §3.3.1 via the closest encloser. `*.apps.example.com` answers for
  `a.b.apps.example.com` — at any depth, not just one label — *unless* something between them
  exists as a node. Given a real `sub.apps.example.com`, a query for `x.sub.apps.example.com`
  is `NXDOMAIN`, not the wildcard's address. The naive "walk up trying `*.<suffix>`" version
  gets this wrong, and getting it wrong means a wildcard silently capturing traffic meant for a
  real subtree. Empty non-terminals are tracked for exactly this reason.
- **CNAME chains**, including referrals out of the zone.

`putRRset()` replaces a record set wholesale, which is the only way to avoid leaving a stale
member in a round-robin A set. A record outside its zone is refused rather than stored: it
would be present in the database, absent from DNS, and very hard to notice.

`cache.fresh` is load-bearing. When the change stream reports a gap the cache stops claiming to
be authoritative, and a resolver should answer SERVFAIL rather than serve a set it can no
longer vouch for.

---

## 6. Identity and authorization

The client certificate **is** the identity. `createPrincipalResolver` maps it to a principal;
the per-database ACL decides what that principal may do. Certificates and grants are separate
on purpose — adding a service should not require re-issuing anyone's certificate.

```js
createPrincipalResolver({
  subjectField: 'CN',
  principals: { 'idp-service': { roles: ['admin'] } },   // also the allow-list
  pinnedIssuers: ['fitfak Issuing CA'],
})
```

**Verified vs. presented certificates.** On a listener that accepts unauthenticated clients, a
peer can present a certificate signed by any CA — including its own — and Node returns it from
`getPeerCertificate()` exactly as it returns a valid one. `call.peer.certificate` is populated
**only** when the chain validated, so a handler reading `commonName` from it can never get an
attacker-chosen string. The unverified form is available as `peer.presentedCertificate`, under
a name that cannot be mistaken for a trusted one.

**Revocation at this layer is the allow-list.** Removing a principal locks that certificate out
on its next connection however long it stays cryptographically valid. That is a real mechanism
for a closed set of known services and an inadequate one for anything larger, where the CA's
own CRL/OCSP infrastructure is what you want in front of this.

Capability tokens still work for the direct-access path and may only ever **narrow** authority:
a token wider than the issuer's own grant is refused, so `ISSUE_CAPABILITY` is a delegation
primitive rather than an escalation one.

---

## 7. Key hierarchy

```
root secret                         (clientSecret, OR an MLS group's exportSecret())
  --KeyProvider.deriveKek()-->      KEK
    --HKDF(KEK, 'fitdb-manifest')-> manifestKey    (decrypts manifest.bin: schema + ACL + wrappedDDK)
    --AES-256-GCM unwrap(KEK)-->    DDK             (Database Data Key, 32 random bytes)
      --HKDF(DDK, 'collection:X')-> per-collection key
        --HKDF(DDK,'blind:field')-> per-field blind-index key (HMAC only, never encrypts)
```

The server persists **only** `wrappedDDK`. KEK derivation is delegated entirely to a
`KeyProvider` the storage layer never sees the internals of, which is what lets key management
evolve without touching storage: `ClientSecretKeyProvider` for a single credential-holder,
`MlsExportSecretKeyProvider` for an RFC 9420 group. `rewrapDatabaseKey()` gives O(1) rotation —
re-wrap the same DDK under a new KEK, zero record I/O.

**Honest caveat.** "The server cannot decrypt" is true of data *at rest*: a copy of the disk is
useless without the root secret. During a live session the DDK necessarily sits in RAM so the
engine can encode, decode and index. That is inherent to any queryable encrypted store, not
specific to this design — a memory dump of a live process is a different threat from disk
theft, and this system does not claim to defend against the former.

---

## 8. Storage format

Records are TLV-encoded (`binary-codec.js`, protobuf-style field-number tags and varints) before
encryption — roughly 2.5x smaller than the equivalent JSON, and unknown field numbers are
skipped rather than erroring, so schemas can gain fields without invalidating stored records.

```
[op:1][flags:1][id:8 BE][version:4 BE][payloadLen:4 BE][payload = iv(12)+tag(16)+ciphertext]
```

`payload` is AES-256-GCM over the (optionally deflated) record with `AAD = id ‖ op ‖ flags ‖
version`. Binding `version` into the AAD is what makes the monotonic per-id counter
tamper-evident: a storage node cannot serve an older but perfectly authentic frame without a
client tracking watermarks (`version-watermark.js`) detecting the regression. AEAD proves a
record is genuine, not that it is the latest.

Recovery: a binary `index.snapshot` means a clean reopen replays nothing; an unclean shutdown
replays only the tail past the snapshot. Compaction copies live frames byte-for-byte — no
decrypt/re-encrypt, since the AAD binds nothing that relocation changes.

---

## 9. Indexes, and what each one leaks

| Kind | Query | What the server learns |
|---|---|---|
| `index: true` | equality, enumerable | the plaintext value |
| `blindIndex: true` | equality with an **already-known** value | which records share a value |
| `rangeBucket: { width }` | range | which bucket (e.g. which day), not the value or cross-bucket order |
| `diskBacked: true` + `index` | ordered range scan | the real order of every indexed value |

A blind index answers exactly one question: "does a record with this exact value exist". It
**cannot** enumerate — doing so would mean testing every possible value, which is precisely the
plaintext-searchable structure blind indexing exists to avoid. Anything meant to be *browsable*
belongs on a plain index or a scan. Both `object-store.js` and `secret-store.js` are shaped
around this: `ownerId`/`kind` are plain, `originalFileName`/`name` are blind.

Range queries are bucketed blind indexing, explicitly **not** order-preserving encryption. OPE
is a research-grade primitive that is easy to implement in a way that looks fine and leaks far
more than intended; bucketing's leakage is explicit and tunable by width.

`diskBacked: true` moves an index into an SSTable-style segment with a bounded memtable —
measured at ~200 resident entries and ~38 sparse-index blocks for a 5000-record field, versus
5000 for a plain Map. Deliberately one on-disk segment, fully rewritten per flush: a much
smaller correctness surface than leveled compaction, at the cost of O(total) flush I/O.

---

## 10. Known limitations

- `SecondaryIndexStore` keeps one on-disk segment; a flush costs O(total field entries).
  Leveled compaction is the natural next step if that ever measures.
- `SCAN` sorts the full remaining candidate set per page; a collection that outgrows this
  should move its ordering field to a `diskBacked` plain index.
- No CRL or OCSP client. Revocation at this layer is the principal allow-list.
- The direct-access object protocol is JSON+base64 framed (~33% overhead), consistent with that
  channel's control-plane-simplicity tradeoff.
- No hardware-enclave key custody; that needs native bindings, out of scope for a pure Node
  implementation.
- `_id` is a **BigInt** in a decoded record, while `insert()` returns a **string**, as do
  `dbId` and capability-token `sub`. `bigintValue === stringValue` is always false in JS —
  compare with an explicit `String(...)` on one side. This bit the test suite three times
  while the engine was being built.
