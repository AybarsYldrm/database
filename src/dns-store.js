'use strict';

// DNS zones and resource records held in an encrypted fitdb collection.
//
// This exists because of a specific tension. DNS is answered at query rate -- thousands of
// lookups a second, each needing an answer in single-digit milliseconds -- and an encrypted
// store cannot serve that per query: every answer would mean a round trip plus a decrypt, for
// data that changed hours ago. Caching the plaintext without knowing when it goes stale is
// worse: a resolver serving a deleted record is worse than one that is slow.
//
// The resolution is the change stream. A resolver loads the zone once, keeps it in memory, and
// the database tells it when something changed (see change-stream.js). Query-time cost is a
// map lookup; the encrypted store is on the write path only. `ZoneCache` below is that
// pattern, and it is the intended way to use this module -- `resolve()` exists for
// administrative lookups and for warming the cache, not for serving traffic.
//
// One property to be explicit about: `lookupKey` is blind-indexed, so the server can answer
// "is there a record for exactly this name and type" without holding a plaintext-searchable
// table of every hostname. It structurally cannot enumerate. That is why a wildcard match, an
// NXDOMAIN determination, or a zone transfer all go through the in-memory zone rather than
// through the index -- the index can confirm a name you already know, and nothing else.

const DNS_RECORD_TYPES = Object.freeze({
  A: 'A', AAAA: 'AAAA', CNAME: 'CNAME', MX: 'MX', NS: 'NS', PTR: 'PTR',
  SOA: 'SOA', SRV: 'SRV', TXT: 'TXT', CAA: 'CAA', DNSKEY: 'DNSKEY', DS: 'DS', TLSA: 'TLSA',
});

const DNS_RECORDS_SCHEMA_FIELDS = [
  // Plain index: a zone name is not the secret here (the resolver is authoritative for it,
  // and it is public in any delegation), and browsing a zone has to be possible.
  { no: 2, name: 'zone', type: 'string', index: true, required: true },
  // Blind: the full set of hostnames inside a zone often IS sensitive (internal service
  // topology), so it gets an index that confirms rather than enumerates.
  { no: 3, name: 'name', type: 'string', blindIndex: true, required: true },
  { no: 4, name: 'lookupKey', type: 'string', blindIndex: true }, // `${name}|${type}`, the query shape
  { no: 5, name: 'type', type: 'string', index: true, required: true },
  { no: 6, name: 'ttl', type: 'int32' },
  // RDATA varies per type (A is an address, MX is a preference plus an exchange, SOA is seven
  // fields), so it is carried as JSON rather than forced into one column shape.
  { no: 7, name: 'rdataJson', type: 'string', required: true },
  { no: 8, name: 'createdAt', type: 'int64' },
  { no: 9, name: 'updatedAt', type: 'int64', rangeBucket: { width: 3600000 } },
  { no: 10, name: 'disabled', type: 'bool' },
  { no: 11, name: 'comment', type: 'string' },
];

const DEFAULT_TTL = 300;

/** Trailing-dot-insensitive, case-insensitive: DNS names compare that way (RFC 4343). */
function normalizeName(name) {
  return String(name || '').trim().toLowerCase().replace(/\.$/, '');
}

function lookupKeyFor(name, type) {
  return `${normalizeName(name)}|${String(type).toUpperCase()}`;
}

/** True when `name` is inside `zone` (or is the zone apex). */
function isInZone(name, zone) {
  const n = normalizeName(name);
  const z = normalizeName(zone);
  return n === z || n.endsWith(`.${z}`);
}

class DnsStore {
  constructor({ database, collection = 'dns_records' }) {
    this.database = database;
    this.collectionName = collection;
    this.records = database.collection(collection);
  }

  static async defineCollection(database, { collection = 'dns_records', ...opts } = {}) {
    return database.defineCollectionAsync(collection, {
      title: 'DNS Records',
      description: 'Authoritative DNS resource records, encrypted at rest',
      fields: DNS_RECORDS_SCHEMA_FIELDS,
      ...opts,
    });
  }

  static async open(database, options = {}) {
    await DnsStore.defineCollection(database, options);
    return new DnsStore({ database, ...options });
  }

  // ---- writing --------------------------------------------------------------------------------

  /**
   * @param {object} record
   * @param {string} record.zone
   * @param {string} record.name  fully qualified; must be inside `zone`
   * @param {string} record.type  see DNS_RECORD_TYPES
   * @param {object|string|Array} record.rdata  shape depends on type
   */
  async put({ zone, name, type, rdata, ttl = DEFAULT_TTL, comment = '', disabled = false }) {
    const normalizedZone = normalizeName(zone);
    const normalizedName = normalizeName(name);
    const recordType = String(type).toUpperCase();

    if (!isInZone(normalizedName, normalizedZone)) {
      // Silently accepting this would produce a record no resolver for either zone ever
      // returns -- present in the database, absent from DNS, and very hard to notice.
      throw new Error(`fitdb dns: '${normalizedName}' is not inside zone '${normalizedZone}'`);
    }
    if (!rdata) throw new Error('fitdb dns: rdata is required');

    const now = Date.now();
    const id = await this.records.insert({
      zone: normalizedZone,
      name: normalizedName,
      lookupKey: lookupKeyFor(normalizedName, recordType),
      type: recordType,
      ttl: Number(ttl) || DEFAULT_TTL,
      rdataJson: typeof rdata === 'string' ? rdata : JSON.stringify(rdata),
      createdAt: BigInt(now),
      updatedAt: BigInt(now),
      disabled: !!disabled,
      comment,
    });
    return id;
  }

  /**
   * Replaces every record at (name, type) with `rdatas` -- the RRset semantics DNS actually
   * has. Updating one record of a multi-record RRset in isolation is how a round-robin A set
   * ends up with a stale member still being handed out.
   */
  async putRRset({ zone, name, type, rdatas, ttl = DEFAULT_TTL, comment = '' }) {
    const existing = await this.resolve(name, type, { includeDisabled: true });
    for (const record of existing) await this.records.delete(record._id);
    const ids = [];
    for (const rdata of rdatas) ids.push(await this.put({ zone, name, type, rdata, ttl, comment }));
    return ids;
  }

  async update(recordId, patch) {
    const existing = await this.records.get(recordId);
    if (!existing) throw new Error(`fitdb dns: no record '${recordId}'`);
    const next = { ...existing, ...patch, updatedAt: BigInt(Date.now()) };
    if (patch.rdata !== undefined) {
      next.rdataJson = typeof patch.rdata === 'string' ? patch.rdata : JSON.stringify(patch.rdata);
      delete next.rdata;
    }
    // The blind index is built over lookupKey; letting name/type drift without recomputing it
    // would leave a record that exists but can never be looked up.
    if (patch.name !== undefined || patch.type !== undefined) {
      next.name = normalizeName(next.name);
      next.type = String(next.type).toUpperCase();
      next.lookupKey = lookupKeyFor(next.name, next.type);
    }
    await this.records.update(recordId, next);
    return next;
  }

  async delete(recordId) { return this.records.delete(recordId); }

  async deleteRRset(name, type) {
    const existing = await this.resolve(name, type, { includeDisabled: true });
    for (const record of existing) await this.records.delete(record._id);
    return existing.length;
  }

  // ---- reading ----------------------------------------------------------------------------------

  /**
   * Exact (name, type) lookup through the blind index. Correct, but one decrypt per call --
   * fine for administration, wrong for serving queries. Use `zoneCache()` for that.
   */
  async resolve(name, type, { includeDisabled = false } = {}) {
    const records = await this.records.find('lookupKey', lookupKeyFor(name, type));
    return includeDisabled ? records : records.filter((r) => !r.disabled);
  }

  /** Every type at a name. Needs the record set for the name, so it goes through `name`. */
  async resolveAny(name, { includeDisabled = false } = {}) {
    const records = await this.records.find('name', normalizeName(name));
    return includeDisabled ? records : records.filter((r) => !r.disabled);
  }

  /** Everything in a zone, via the plain `zone` index -- this is what a zone transfer reads. */
  async listZone(zone, { includeDisabled = false } = {}) {
    const records = await this.records.find('zone', normalizeName(zone));
    const visible = includeDisabled ? records : records.filter((r) => !r.disabled);
    return visible.sort((a, b) => a.name.localeCompare(b.name) || a.type.localeCompare(b.type));
  }

  /**
   * An in-memory, always-current copy of a zone: the intended way to serve queries. One
   * snapshot plus a change subscription replaces one decrypt per query.
   */
  async zoneCache(zone, options = {}) {
    const cache = new ZoneCache(this, normalizeName(zone), options);
    await cache.start();
    return cache;
  }
}

/**
 * The query-serving side.
 *
 * Everything a resolver needs that a blind index cannot provide -- wildcard matching, CNAME
 * following, deciding NXDOMAIN versus NODATA -- happens here, against the decrypted zone,
 * because all three require knowing what is *absent*, and an index that cannot enumerate can
 * never establish absence.
 *
 * `fresh` is load-bearing. When the change stream reports a gap the cache stops claiming to be
 * authoritative, and a resolver should answer SERVFAIL rather than serve a set it can no
 * longer vouch for -- a resolver confidently returning stale records is worse than one that
 * admits it is broken.
 */
class ZoneCache {
  constructor(store, zone, { onChange = null, autoReload = true } = {}) {
    this.store = store;
    this.zone = zone;
    this.onChange = onChange;
    this.autoReload = autoReload;
    this.byLookupKey = new Map(); // 'name|TYPE' -> [record]
    this.names = new Set();       // names that actually carry records
    this.nodes = new Set();       // names + every ancestor: DNS's "existing node" set
    this.fresh = false;
    this.lastLoadedAt = 0;
    this._unsubscribe = null;
    this._reloading = null;
  }

  async start() {
    // Subscribe BEFORE loading. The other order drops every change that lands during the
    // load, and nothing downstream can detect that it happened.
    if (this.autoReload) {
      this._unsubscribe = this.store.database.watch(this.store.collectionName, (event) => this._onEvent(event));
    }
    await this.reload();
    return this;
  }

  async reload() {
    if (this._reloading) return this._reloading;
    this._reloading = (async () => {
      const records = await this.store.listZone(this.zone);
      const byKey = new Map();
      const names = new Set();
      const nodes = new Set([this.zone]);
      for (const record of records) {
        const key = lookupKeyFor(record.name, record.type);
        if (!byKey.has(key)) byKey.set(key, []);
        byKey.get(key).push(decodeRecord(record));
        names.add(record.name);
        // A node exists if it has records OR if anything below it does -- the "empty
        // non-terminal" of RFC 4592 §2.2.2. Leaving these out breaks closest-encloser
        // matching: an empty non-terminal is what stops a wildcard higher up from swallowing
        // names under a branch that genuinely exists.
        for (const ancestor of ancestorsOf(record.name, this.zone)) nodes.add(ancestor);
      }
      this.byLookupKey = byKey;
      this.names = names;
      this.nodes = nodes;
      this.fresh = true;
      this.lastLoadedAt = Date.now();
    })();
    try { await this._reloading; } finally { this._reloading = null; }
    return this;
  }

  _onEvent(event) {
    // A record moving between zones arrives as a put whose zone is this one, or as a delete
    // carrying no record at all -- in both cases the cheap, always-correct response is to
    // reload. Zones are small; the alternative is incremental logic whose edge cases are
    // exactly the ones that produce a silently wrong answer.
    const affectsUs = !event.record || event.record.zone === this.zone;
    if (!affectsUs) return;
    this.fresh = false;
    this.reload().then(
      () => this.onChange?.(event),
      () => { this.fresh = false; },
    );
  }

  stop() {
    if (this._unsubscribe) { this._unsubscribe(); this._unsubscribe = null; }
    return this;
  }

  /**
   * Resolves a query the way an authoritative server would.
   *
   * @returns {{ status: 'NOERROR'|'NXDOMAIN', records: [], chain: [] }}
   *   NOERROR with an empty `records` is NODATA: the name exists, this type does not. That
   *   distinction is not cosmetic -- a resolver that returns NXDOMAIN for NODATA tells the
   *   world the name does not exist, which breaks every other type at that name.
   */
  query(name, type, { followCname = true, maxChain = 8 } = {}) {
    const normalized = normalizeName(name);
    const recordType = String(type).toUpperCase();
    const chain = [];

    let current = normalized;
    for (let depth = 0; depth <= maxChain; depth++) {
      if (!isInZone(current, this.zone)) return { status: 'NOERROR', records: [], chain, referral: current };

      const exact = this.byLookupKey.get(lookupKeyFor(current, recordType));
      if (exact && exact.length) return { status: 'NOERROR', records: exact, chain };

      if (followCname && recordType !== 'CNAME') {
        const cname = this.byLookupKey.get(lookupKeyFor(current, 'CNAME'));
        if (cname && cname.length) {
          chain.push(cname[0]);
          const target = normalizeName(cname[0].rdata.target || cname[0].rdata);
          // A CNAME pointing outside this zone is a legitimate referral, not an error: the
          // answer continues at whoever is authoritative there.
          if (!isInZone(target, this.zone)) return { status: 'NOERROR', records: [], chain, referral: target };
          current = target;
          continue;
        }
      }

      // The name itself exists with other types: NODATA, not NXDOMAIN. A wildcard must not be
      // consulted here -- RFC 4592 §2.2.1, an existing node blocks wildcard synthesis at it.
      if (this.names.has(current)) return { status: 'NOERROR', records: [], chain };

      const synthesized = this._synthesizeWildcard(current, recordType);
      if (synthesized) return { ...synthesized, chain };
      return { status: 'NXDOMAIN', records: [], chain };
    }
    return { status: 'NOERROR', records: [], chain, truncated: true };
  }

  /**
   * Wildcard synthesis per RFC 4592 §3.3.1, via the closest encloser.
   *
   * The naive version -- walk up the name trying `*.<suffix>` until something matches -- gets
   * one important case wrong. Given `*.apps.example.com` and a real `sub.apps.example.com`, a
   * query for `x.sub.apps.example.com` must NOT be answered from the wildcard: the closest
   * existing ancestor is `sub.apps.example.com`, so the only wildcard that may apply is
   * `*.sub.apps.example.com`, and if that does not exist the answer is NXDOMAIN. Walking up
   * blindly would hand back `*.apps`'s address for a name under a branch that genuinely
   * exists, which is how a wildcard silently captures traffic meant for a real subtree.
   *
   * Note also that the wildcard matches at any depth below its parent, not just one label --
   * `*.apps.example.com` does answer for `a.b.apps.example.com`, provided nothing between
   * them exists as a node.
   */
  _synthesizeWildcard(qname, type) {
    const closestEncloser = this._closestEncloser(qname);
    if (closestEncloser === null) return null;
    if (closestEncloser === qname) return null; // handled by the NODATA branch above

    const sourceOfSynthesis = `*.${closestEncloser}`;
    const match = this.byLookupKey.get(lookupKeyFor(sourceOfSynthesis, type));
    if (match && match.length) {
      return {
        status: 'NOERROR',
        records: match.map((record) => ({ ...record, name: qname, wildcardFrom: sourceOfSynthesis })),
      };
    }
    // The wildcard node exists but carries no record of this type: NODATA, not NXDOMAIN.
    if (this.names.has(sourceOfSynthesis)) return { status: 'NOERROR', records: [] };
    return null;
  }

  /** Longest ancestor of `qname` (or `qname` itself) that exists as a node in this zone. */
  _closestEncloser(qname) {
    if (!isInZone(qname, this.zone)) return null;
    let candidate = qname;
    for (;;) {
      if (this.nodes.has(candidate)) return candidate;
      if (candidate === this.zone) return this.zone;
      const dot = candidate.indexOf('.');
      if (dot === -1) return null;
      candidate = candidate.slice(dot + 1);
    }
  }

  get size() {
    let total = 0;
    for (const records of this.byLookupKey.values()) total += records.length;
    return total;
  }

  /** Every record, for a zone transfer or an export. */
  all() {
    const out = [];
    for (const records of this.byLookupKey.values()) out.push(...records);
    return out;
  }
}

/** Every name between `name` and `zone` inclusive -- the nodes DNS considers to exist. */
function ancestorsOf(name, zone) {
  const out = [];
  let current = normalizeName(name);
  const apex = normalizeName(zone);
  while (isInZone(current, apex)) {
    out.push(current);
    if (current === apex) break;
    const dot = current.indexOf('.');
    if (dot === -1) break;
    current = current.slice(dot + 1);
  }
  return out;
}

function decodeRecord(record) {
  let rdata;
  try { rdata = JSON.parse(record.rdataJson); }
  catch (_) { rdata = record.rdataJson; }
  return {
    id: String(record._id),
    zone: record.zone,
    name: record.name,
    type: record.type,
    ttl: record.ttl,
    rdata,
    comment: record.comment || '',
  };
}

module.exports = {
  DnsStore, ZoneCache, DNS_RECORDS_SCHEMA_FIELDS, DNS_RECORD_TYPES,
  normalizeName, lookupKeyFor, isInZone, DEFAULT_TTL,
};
