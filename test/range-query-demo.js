'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const { DatabaseManager, ClientSecretKeyProvider } = require('../src');

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-range-query-demo');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'u1', name: 'x' });
  // day-width buckets (86400000 ms) over a synthetic "createdAt" timestamp field
  const DAY = 86400000;
  const events = await db.defineCollectionAsync('events', {
    fields: [
      { no: 2, name: 'label', type: 'string' },
      { no: 3, name: 'createdAt', type: 'int64', rangeBucket: { width: DAY } },
    ],
  });

  const base = 1_700_000_000_000; // fixed epoch ms so the test is deterministic
  const N = 500;
  const timestamps = [];
  for (let i = 0; i < N; i++) {
    // spread records across ~50 days, several per day, with some jitter within the day
    const ts = base + Math.floor(i / 10) * DAY + (i % 10) * 3600000;
    timestamps.push(ts);
    await events.insert({ label: `evt_${i}`, createdAt: BigInt(ts) });
  }

  // query a 5-day window landing mid-way through the dataset, crossing several bucket edges
  const rangeStart = base + 20 * DAY;
  const rangeEnd = base + 25 * DAY - 1; // end just before day 25 starts
  const t0 = Date.now();
  const results = await events.findRange('createdAt', BigInt(rangeStart), BigInt(rangeEnd));
  const queryMs = Date.now() - t0;

  const expectedCount = timestamps.filter((ts) => ts >= rangeStart && ts <= rangeEnd).length;
  assert.strictEqual(results.length, expectedCount, `range query should return exactly the records inside [${rangeStart}, ${rangeEnd}]`);
  for (const r of results) {
    assert.ok(r.createdAt >= BigInt(rangeStart) && r.createdAt <= BigInt(rangeEnd), 'every returned record must satisfy the exact bound, not just bucket membership');
  }
  console.log(`range query over ${N} records (5-day window, ${DAY / 3600000}h buckets) returned ${results.length}/${expectedCount} expected records in ${queryMs}ms`);

  // boundary check: a window of exactly one bucket width, aligned to a bucket edge
  const oneDay = await events.findRange('createdAt', BigInt(base + 10 * DAY), BigInt(base + 11 * DAY - 1));
  const expectedOneDay = timestamps.filter((ts) => ts >= base + 10 * DAY && ts < base + 11 * DAY).length;
  assert.strictEqual(oneDay.length, expectedOneDay);
  console.log(`single-bucket-width window returned exactly ${oneDay.length} records as expected`);

  // empty range (no data) must return zero results, not throw
  const empty = await events.findRange('createdAt', BigInt(base - 100 * DAY), BigInt(base - 99 * DAY));
  assert.strictEqual(empty.length, 0);
  console.log('empty range correctly returns zero results');

  // persistence: close and reopen, confirm the range index survived via the snapshot
  await manager.closeDatabase(dbId);
  const manager2 = new DatabaseManager({ baseDir });
  const db2 = await manager2.openDatabase({ ownerId: 'u1', dbId, requesterId: 'u1', keyProvider: new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64')) });
  const events2 = db2.collection('events');
  const afterReopen = await events2.findRange('createdAt', BigInt(rangeStart), BigInt(rangeEnd));
  assert.strictEqual(afterReopen.length, expectedCount);
  console.log('range index correctly persisted and reloaded across a clean close/reopen');

  // ── An open-ended range must not cost anything proportional to the range ───────────────
  //
  // This is the regression that took the whole database down. `findRange(field, 0, now)` --
  // the natural spelling of "everything due by now" -- used to walk one bucket at a time from
  // the epoch to the present, hashing each bucket number. On a minute-width field that is
  // ~30 million synchronous HMACs, roughly two minutes with the event loop held the entire
  // time, so no other client of the database was served either. A single row was enough to
  // trigger it; an EMPTY collection was fast, which is why deleting the data appeared to fix
  // it and why it came straight back on the next insert.
  //
  // Both properties are asserted: the answer is still exact, and it arrives quickly.
  const MINUTE = 60_000;
  const queue = await db2.defineCollectionAsync('due_queue', {
    fields: [
      { no: 2, name: 'queueId', type: 'string', index: true },
      { no: 3, name: 'nextAttemptAt', type: 'uint64', rangeBucket: { width: MINUTE } },
    ],
  });

  const now = Date.now();
  await queue.insert({ queueId: 'due-now', nextAttemptAt: now - 1000 });
  await queue.insert({ queueId: 'due-earlier', nextAttemptAt: now - 90 * MINUTE });
  await queue.insert({ queueId: 'not-due-yet', nextAttemptAt: now + 60 * MINUTE });

  const openEndedStart = Date.now();
  const due = await queue.findRange('nextAttemptAt', 0, now);
  const openEndedMs = Date.now() - openEndedStart;

  assert.strictEqual(due.length, 2, 'an open-ended range must still return exactly the due rows');
  assert.ok(
    due.every((r) => Number(r.nextAttemptAt) <= now),
    'the exact filter still applies, even though candidates came from a whole-field sweep',
  );
  assert.ok(
    openEndedMs < 5000,
    `findRange(0, now) took ${openEndedMs}ms; it must not scale with the width of the range `
    + '(before the bucket-probe budget existed this was ~120000ms and blocked the event loop throughout)',
  );
  console.log(`open-ended range (${Math.floor(now / MINUTE).toLocaleString()} buckets wide) answered in ${openEndedMs}ms with ${due.length} exact matches`);

  // The limit stops the decrypt loop early rather than being applied to a fully built result.
  const limited = await queue.findRange('nextAttemptAt', 0, now, { limit: 1 });
  assert.strictEqual(limited.length, 1, 'limit must cap the number of records returned');
  console.log('limit is honoured on an open-ended range');

  // A non-numeric bound used to produce NaN buckets and silently return nothing, which reads
  // exactly like "no matching rows" at the call site.
  await assert.rejects(
    () => queue.findRange('nextAttemptAt', undefined, now),
    /numeric bounds/,
    'a non-numeric bound must be reported, not silently answered with an empty set',
  );
  console.log('non-numeric bounds are rejected instead of silently returning nothing');

  await manager2.closeDatabase(dbId);
  console.log('\nALL RANGE-QUERY CHECKS PASSED');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
