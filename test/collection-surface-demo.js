'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const fsp = require('node:fs/promises');

const { DatabaseManager } = require('../src');
const { toJson, recordToJsonObject } = require('../src/grpc/record-codec');

// WHAT A CALLER ACTUALLY GETS BACK, EMBEDDED VS REMOTE.
//
// The README has said, since the gRPC layer landed, that "the remote API mirrors the embedded
// one, so code moves between them by changing how the handle is obtained and nothing else."
// The method names do mirror. The values they hand back do not, and none of the differences
// raises an error:
//
//   int64       embedded: BigInt                         remote: decimal STRING
//   bytes       embedded: Buffer                         remote: base64 STRING
//   update()    embedded: the record                     remote: a version number
//   count()     embedded: sync number                    remote: Promise<number>
//   find()      embedded: no limit option                remote: takes { limit }
//   generateId  embedded: present                        remote: absent
//
// `scan()` agrees -- both are async generators over records -- but it reads as though it does
// not: `Collection#scan()` is `{ return this.storage.scan(); }`, a plain non-async method
// returning what looks like an iterator. It is an async generator, so `for (const x of
// scan())` throws "not iterable" on both. `scanPage(afterId, limit)` is the surface to write
// against: identical signature on both classes, `{ records, nextCursor }` on both, and
// paginated, which the remote side needs anyway.
//
// The int64 row is the expensive one. Every counter a caller keeps -- a byte total, a
// timestamp, a version -- gets arithmetic done to it:
//
//   embedded:  1024n + 512   -> TypeError                loud, found in a minute
//   remote:   "1024" + 512   -> "1024512"                silent, found in production
//
// The second one throws nothing, logs nothing and passes every test written against the
// embedded engine. @fitfak/workspace hit exactly this: quota accounting that was correct on
// `local` and doubled a user's used bytes on `stack`.
//
// This file pins the real behaviour so the difference is a documented property rather than a
// discovery. It does NOT assert that the two should agree -- changing what RemoteCollection
// returns would break every deployed client that already compensates, the IdP's
// grpc-db-adapter among them. It asserts what each side does, so a caller can be told.
//
// WHY THERE IS NO SERVER HERE: the embedded half runs for real. The remote half needs
// @fitfak/grpc, which many checkouts do not have (`npm run link:grpc`), and booting a server
// would mean this test usually does not run at all. Instead the remote half is exercised
// where its types are actually decided -- the encoder in src/grpc/record-codec.js, which has
// no transport dependency -- and the one client line that consumes it is read from source.

let checks = 0;
function check(name, condition) {
  if (!condition) throw new Error(`FAILED: ${name}`);
  checks += 1;
  console.log(`  ok ${name}`);
}

const FIELDS = [
  { no: 1, name: '_id', type: 'uint64' },
  { no: 2, name: 'tenant', type: 'string', index: true },
  { no: 3, name: 'usedBytes', type: 'int64' },
  { no: 4, name: 'createdAt', type: 'uint64' },
  { no: 5, name: 'blob', type: 'bytes' },
];

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-collection-surface');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir, sessionTtlMs: 60000 });
  const { db } = await manager.createDatabase({ ownerId: 'u1', name: 'surface' });

  const rows = await db.defineCollectionAsync('rows', {
    fields: FIELDS.filter((f) => f.name !== '_id'),
  });

  /* ── 1. embedded: what comes back and in what type ─────────── */

  const id = await rows.insert({
    tenant: 'core', usedBytes: 1024, createdAt: Date.now(), blob: Buffer.from('merhaba'),
  });
  check('insert() returns an id string, not the record', typeof id === 'string');

  const record = await rows.get(id);
  check('embedded identity field is _id', record._id !== undefined && record.id === undefined);
  check('embedded int64 decodes to BigInt', typeof record.usedBytes === 'bigint');
  check('embedded uint64 decodes to BigInt', typeof record.createdAt === 'bigint');
  check('embedded bytes decodes to Buffer', Buffer.isBuffer(record.blob));

  // The failure mode, demonstrated rather than described: this is what a caller who moved
  // arithmetic over from the file-backed prototype writes, and this is what it does.
  let mixed = null;
  try { void (record.usedBytes + 512); } catch (err) { mixed = err; }
  check('BigInt + Number throws, so the embedded mistake is loud',
    mixed instanceof TypeError);

  const updated = await rows.update(id, { usedBytes: 2048 });
  check('embedded update() returns the record', updated && updated._id !== undefined);

  check('embedded count() is synchronous', typeof rows.count() === 'number');
  check('embedded generateId() exists', typeof rows.generateId() === 'string');

  // scan() is declared without `async`, so it reads like a sync iterator. It is not.
  const iterator = rows.scan();
  check('scan() returns an ASYNC iterator despite the sync-looking declaration',
    typeof iterator[Symbol.asyncIterator] === 'function'
    && iterator[Symbol.iterator] === undefined);

  let notIterable = null;
  try { [...rows.scan()]; } catch (err) { notIterable = err; }
  check('spreading scan() throws -- the shape is easy to misread',
    notIterable instanceof TypeError);

  const scanned = [];
  for await (const row of rows.scan()) scanned.push(row);
  check('scan() yields records once awaited properly',
    scanned.length === 1 && scanned[0]._id !== undefined);

  /* ── 2. the one surface both halves share ──────────────────── */

  // scanPage(afterId, limit) -> { records, nextCursor } is identical on both classes, and it
  // yields records on both. Anything that has to work over either handle should iterate with
  // this rather than scan().
  await rows.insert({ tenant: 'core', usedBytes: 1, createdAt: Date.now() });
  await rows.insert({ tenant: 'core', usedBytes: 2, createdAt: Date.now() });

  const firstPage = await rows.scanPage(null, 2);
  check('scanPage(null, n) starts from the beginning', firstPage.records.length === 2);
  check('scanPage yields RECORDS on the embedded side',
    firstPage.records[0]._id !== undefined);
  check('scanPage hands back a cursor when more remain', firstPage.nextCursor !== null);

  const secondPage = await rows.scanPage(firstPage.nextCursor, 2);
  check('the cursor advances', secondPage.records.length === 1);
  check('the last page has no cursor', secondPage.nextCursor === null);

  /* ── 3. remote: the same record, as the wire delivers it ───── */

  // Server side, verbatim from writePayload(): the record is JSON-shaped and stringified.
  const wire = toJson(recordToJsonObject(FIELDS, {
    _id: 1234567890123456789n,
    tenant: 'core',
    usedBytes: 1024n,
    createdAt: 1700000000000n,
    blob: Buffer.from('merhaba'),
  }));

  // Client side, verbatim from RemoteCollection#get(): a bare JSON.parse. No coercion runs
  // here -- client.js imports toJson from the codec and nothing else.
  const received = JSON.parse(wire);

  check('remote int64 arrives as a STRING, not BigInt',
    typeof received.usedBytes === 'string' && received.usedBytes === '1024');
  check('remote uint64 arrives as a string', typeof received.createdAt === 'string');
  check('remote bytes arrives as base64, not Buffer',
    typeof received.blob === 'string'
    && Buffer.from(received.blob, 'base64').toString() === 'merhaba');
  check('remote _id survives above 2^53 because it is a string',
    received._id === '1234567890123456789');

  // And this is the bug, reproduced: no throw, no log, wrong number.
  check('string + Number concatenates silently -- the remote mistake is QUIET',
    received.usedBytes + 512 === '1024512');

  /* ── 4. the client really does decode this way ─────────────── */

  // Section 3 is only honest if the client's read path is still a bare JSON.parse. If someone
  // adds coerceRecord() to it, these checks fail and this file needs rewriting -- which is the
  // point of having them.
  const clientSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'grpc', 'client.js'), 'utf8');
  check('client get() parses without coercing',
    /return res\.found \? JSON\.parse\(res\.payloadJson\) : null;/.test(clientSource));
  check('client does not import coerceRecord',
    !/coerceRecord/.test(clientSource));
  check('remote scan() is an async generator too',
    /async\* scan\(/.test(clientSource));
  check('remote scanPage has the same signature as the embedded one',
    /async scanPage\(afterId = null, limit = 100\)/.test(clientSource));
  check('remote update() returns a version, not a record',
    /async update\([\s\S]{0,400}?return res\.version;/.test(clientSource));
  check('remote collection has no generateId',
    !/^ {2}generateId\(/m.test(clientSource));
  check('remote find() takes a limit the embedded one does not',
    /async find\(field, value, \{ limit = 0 \} = \{\}\)/.test(clientSource));

  await db.close?.();
  await fsp.rm(baseDir, { recursive: true, force: true });

  console.log(`\n${checks} checks passed.`);
  console.log(
    '\nFor callers that must run over either handle: iterate with scanPage(), and normalise\n'
    + 'int64 and bytes at the boundary. @fitfak/workspace does this in one adapter\n'
    + '(EngineCollection) rather than at each call site -- see README section 2.');
}

main().catch((err) => { console.error(err); process.exit(1); });
