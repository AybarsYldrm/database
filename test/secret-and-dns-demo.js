'use strict';

const assert = require('node:assert');
const path = require('node:path');
const fsp = require('node:fs/promises');
const crypto = require('node:crypto');

const { DatabaseManager, SecretStore, DnsStore, SECRET_KINDS, SECRET_STATES } = require('../src');
const { createTestCaBackend, generateKeyPair } = require('./helpers/test-pki');

// The two workloads that motivated the change stream: material that must not sit in plaintext
// on disk (certificates, keys) and data that is read far more often than it is written (DNS).
// Both are unworkable with per-read decryption and unsafe with an unmanaged cache; the point
// of these checks is that the managed cache stays correct, and says so when it cannot.

let checks = 0;
function check(name, condition) {
  if (!condition) throw new Error(`FAILED: ${name}`);
  checks++;
  console.log(`  ok ${name}`);
}

async function waitFor(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('timed out waiting for a condition');
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-secret-dns');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir, sessionTtlMs: 60000 });
  const { db, dbId, clientSecret } = await manager.createDatabase({ ownerId: 'ops', name: 'infra' });

  // ============================ SECRET STORE ============================
  console.log('\n[1] Certificates and keys, encrypted at rest');
  const vault = await SecretStore.open(db);
  const ca = createTestCaBackend();
  const leafKey = generateKeyPair();
  const leaf = ca.issueDirect({
    subject: { CN: 'api.fitfak.net', O: 'fitfak' }, keyPair: leafKey,
    altNames: ['api.fitfak.net'], eku: ['serverAuth'], validityDays: 30,
  });

  {
    const stored = await vault.putCertificate({
      name: 'api.fitfak.net',
      certPem: leaf.certPem,
      privateKeyPem: leaf.privateKeyPem,
      chainPem: [ca.ca.certPem],
    });
    check('a certificate and its key are stored together', stored.certificate.version === 1 && stored.key.version === 1);

    const pair = await vault.getCertificatePair('api.fitfak.net');
    check('the pair comes back ready for a TLS context', pair.certPem === leaf.certPem && pair.privateKeyPem === leaf.privateKeyPem);
    check('the chain is preserved', pair.chainPem[0] === ca.ca.certPem);
    // Derived from the certificate rather than taken from the caller: an expiry sweep that
    // relies on a caller remembering to pass notAfter is a sweep that misses things.
    check('expiry is read out of the certificate itself', Math.abs(pair.notAfter - new Date(leaf.notAfter).getTime()) < 1000);
    check('and so is the fingerprint', pair.fingerprint === leaf.fingerprint256);
  }

  console.log('\n[2] Nothing readable is left on disk');
  {
    const collectionDir = path.join(db.dir, 'collections', 'secrets');
    const files = await fsp.readdir(collectionDir);
    const segment = files.find((f) => /^seg-\d+\.log$/.test(f));
    const raw = await fsp.readFile(path.join(collectionDir, segment));
    // The strongest available check that the record really is encrypted: a PEM body is
    // extremely distinctive, so finding none of it in the segment file means the plaintext
    // never reached disk.
    check('the private key does not appear in the segment file',
      !raw.includes(Buffer.from('BEGIN PRIVATE KEY')) && !raw.includes(Buffer.from('BEGIN CERTIFICATE')));
    check('nor does the secret name', !raw.includes(Buffer.from('api.fitfak.net')));
  }

  console.log('\n[3] Rotation is a transition, not a cutover');
  {
    const renewedKey = generateKeyPair();
    const renewed = ca.issueDirect({
      subject: { CN: 'api.fitfak.net', O: 'fitfak' }, keyPair: renewedKey,
      altNames: ['api.fitfak.net'], eku: ['serverAuth'], validityDays: 397,
    });

    // Staged: issued but not yet promoted, so a consumer that reloads right now still gets
    // the certificate its peers are currently pinned to.
    await vault.putCertificate({ name: 'api.fitfak.net', certPem: renewed.certPem, privateKeyPem: renewed.privateKeyPem, activate: false });
    const stillOld = await vault.getCertificatePair('api.fitfak.net');
    check('a staged version does not displace the active one', stillOld.certPem === leaf.certPem);

    await vault.activate('api.fitfak.net', 2);
    await vault.activate('api.fitfak.net.key', 2);
    const now = await vault.getCertificatePair('api.fitfak.net');
    check('promoting swaps the active version', now.certPem === renewed.certPem);

    const versions = await vault.listVersions('api.fitfak.net');
    check('both versions are retained', versions.length === 2);
    // The superseded version is retired, not deleted: an in-flight consumer that has not
    // reloaded yet still has something real to verify against.
    check('the superseded one is retired rather than destroyed',
      versions[0].state === SECRET_STATES.RETIRED && versions[1].state === SECRET_STATES.ACTIVE);
  }

  console.log('\n[4] Finding what needs renewing');
  {
    const soonKey = generateKeyPair();
    const soon = ca.issueDirect({ subject: { CN: 'expiring.fitfak.net' }, keyPair: soonKey, eku: ['serverAuth'], validityDays: 5 });
    await vault.putCertificate({ name: 'expiring.fitfak.net', certPem: soon.certPem, privateKeyPem: soon.privateKeyPem });

    const expiring = await vault.listExpiring(7 * 86400000);
    const names = expiring.map((r) => r.name);
    check('a certificate expiring inside the window is found', names.includes('expiring.fitfak.net'));
    // The bucketed range index means the server learns which day-bucket a secret expires in,
    // not the exact timestamp; the exact bound is applied after decryption.
    check('one expiring outside it is not', !names.includes('api.fitfak.net'));
    check('results are ordered by urgency',
      expiring.every((r, i) => i === 0 || Number(expiring[i - 1].notAfter) <= Number(r.notAfter)));
  }

  console.log('\n[5] Browsing goes through kind, never through name');
  {
    const byKind = await vault.listByKind(SECRET_KINDS.CERTIFICATE);
    check('active certificates are enumerable by kind', byKind.length === 2);

    await vault.put({ name: 'session-signing-key', material: crypto.randomBytes(32), kind: SECRET_KINDS.SYMMETRIC_KEY });
    check('a symmetric key round trips', (await vault.getMaterial('session-signing-key')).length === 32);
    check('and does not show up under certificates', (await vault.listByKind(SECRET_KINDS.CERTIFICATE)).length === 2);

    // The asymmetry is the point: `kind` is a plain index because the set of kinds in use is
    // not sensitive, while `name` is blind-indexed because the set of secret names is.
    const nameField = (await vault.secrets.describe?.()) || null;
    check('an unknown name simply resolves to nothing', (await vault.getActive('no-such-secret')) === null);
  }

  console.log('\n[6] Compromise marks, it does not erase');
  {
    await vault.put({ name: 'leaked-token', material: Buffer.from('hunter2'), kind: SECRET_KINDS.API_TOKEN });
    const marked = await vault.markCompromised('leaked-token', { reason: 'found in a build log' });
    check('every version is marked', marked === 1);
    check('it is no longer served as active', (await vault.getActive('leaked-token')) === null);
    // Incident response needs to know what was exposed, so the material stays.
    const versions = await vault.listVersions('leaked-token');
    check('but the material is retained for the investigation', versions[0].material.toString() === 'hunter2');
    check('with the reason recorded', JSON.parse(versions[0].metadataJson).reason === 'found in a build log');
  }

  // ============================ DNS STORE ============================
  console.log('\n[7] An authoritative zone held encrypted');
  const dns = await DnsStore.open(db);
  {
    await dns.put({ zone: 'internal.fitfak.net', name: 'internal.fitfak.net', type: 'SOA', ttl: 3600, rdata: { mname: 'ns1.internal.fitfak.net', rname: 'ops.fitfak.net', serial: 1, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300 } });
    await dns.put({ zone: 'internal.fitfak.net', name: 'db.internal.fitfak.net', type: 'A', ttl: 300, rdata: { address: '10.0.0.10' } });
    await dns.put({ zone: 'internal.fitfak.net', name: 'idp.internal.fitfak.net', type: 'A', ttl: 300, rdata: { address: '10.0.0.20' } });
    await dns.put({ zone: 'internal.fitfak.net', name: 'idp.internal.fitfak.net', type: 'AAAA', ttl: 300, rdata: { address: 'fd00::20' } });
    await dns.put({ zone: 'internal.fitfak.net', name: 'auth.internal.fitfak.net', type: 'CNAME', ttl: 300, rdata: { target: 'idp.internal.fitfak.net' } });
    await dns.put({ zone: 'internal.fitfak.net', name: '*.apps.internal.fitfak.net', type: 'A', ttl: 60, rdata: { address: '10.0.1.1' } });

    const resolved = await dns.resolve('db.internal.fitfak.net', 'A');
    check('exact lookup works through the blind index', JSON.parse(resolved[0].rdataJson).address === '10.0.0.10');
    check('names are matched case- and trailing-dot-insensitively',
      (await dns.resolve('DB.Internal.Fitfak.Net.', 'a')).length === 1);

    await assert.rejects(
      () => dns.put({ zone: 'internal.fitfak.net', name: 'elsewhere.example.com', type: 'A', rdata: { address: '1.1.1.1' } }),
      // Accepting this would create a record present in the database and absent from DNS.
      (err) => /is not inside zone/.test(err.message),
    );
    check('a record outside its zone is refused', true);

    const zone = await dns.listZone('internal.fitfak.net');
    check('the whole zone is enumerable through the plain zone index', zone.length === 6);
  }

  console.log('\n[8] The zone cache: one decrypt, then map lookups');
  const cache = await dns.zoneCache('internal.fitfak.net');
  {
    check('the cache loads the zone', cache.size === 6 && cache.fresh);

    const a = cache.query('db.internal.fitfak.net', 'A');
    check('a direct hit answers NOERROR', a.status === 'NOERROR' && a.records[0].rdata.address === '10.0.0.10');

    const cname = cache.query('auth.internal.fitfak.net', 'A');
    check('a CNAME is followed to its target', cname.records[0].rdata.address === '10.0.0.20');
    check('and the chain is reported', cname.chain[0].type === 'CNAME');

    const wildcard = cache.query('anything.apps.internal.fitfak.net', 'A');
    check('a wildcard answers for a name below it', wildcard.records[0].rdata.address === '10.0.1.1');
    check('and reports which wildcard synthesised it', wildcard.records[0].wildcardFrom === '*.apps.internal.fitfak.net');
    // RFC 4592 §3.3.1: the wildcard applies at any depth below its parent, so long as nothing
    // between them exists as a node.
    check('at any depth, when nothing between exists',
      cache.query('a.b.apps.internal.fitfak.net', 'A').records[0].rdata.address === '10.0.1.1');

    // ...but an existing node between them blocks it. This is the case a naive
    // "walk up trying *.<suffix>" implementation gets wrong, and getting it wrong means the
    // wildcard silently captures traffic meant for a real subtree.
    await dns.put({ zone: 'internal.fitfak.net', name: 'real.apps.internal.fitfak.net', type: 'A', ttl: 60, rdata: { address: '10.0.1.50' } });
    // The wildcard already answers this name, so waiting on "one record" would pass before
    // the write landed; wait on the value that actually distinguishes the two.
    await waitFor(() => cache.query('real.apps.internal.fitfak.net', 'A').records[0]?.rdata.address === '10.0.1.50');
    check('an exact record beats the wildcard', true);
    check('and a closer encloser blocks wildcard synthesis below it',
      cache.query('deep.real.apps.internal.fitfak.net', 'A').status === 'NXDOMAIN');
    check('the zone apex is never wildcard-matched',
      cache.query('internal.fitfak.net', 'A').status === 'NOERROR' && cache.query('internal.fitfak.net', 'A').records.length === 0);

    const nodata = cache.query('db.internal.fitfak.net', 'MX');
    // NODATA, not NXDOMAIN: the name exists, this type does not. Answering NXDOMAIN here
    // tells the world the name does not exist and breaks every other type at it.
    check('a missing type at an existing name is NODATA, not NXDOMAIN',
      nodata.status === 'NOERROR' && nodata.records.length === 0);
    check('a genuinely absent name is NXDOMAIN', cache.query('nope.internal.fitfak.net', 'A').status === 'NXDOMAIN');
  }

  console.log('\n[9] The cache follows writes without being asked');
  {
    await dns.put({ zone: 'internal.fitfak.net', name: 'new.internal.fitfak.net', type: 'A', ttl: 300, rdata: { address: '10.0.0.99' } });
    await waitFor(() => cache.query('new.internal.fitfak.net', 'A').records.length === 1);
    check('a new record appears without a reload call', cache.query('new.internal.fitfak.net', 'A').records[0].rdata.address === '10.0.0.99');

    const [record] = await dns.resolve('db.internal.fitfak.net', 'A');
    await dns.update(record._id, { rdata: { address: '10.0.0.11' } });
    await waitFor(() => cache.query('db.internal.fitfak.net', 'A').records[0].rdata.address === '10.0.0.11');
    check('an update is reflected', true);

    await dns.deleteRRset('new.internal.fitfak.net', 'A');
    await waitFor(() => cache.query('new.internal.fitfak.net', 'A').status === 'NXDOMAIN');
    check('a delete makes the name vanish again', true);
  }

  console.log('\n[10] RRset semantics');
  {
    await dns.putRRset({
      zone: 'internal.fitfak.net', name: 'pool.internal.fitfak.net', type: 'A', ttl: 60,
      rdatas: [{ address: '10.0.2.1' }, { address: '10.0.2.2' }, { address: '10.0.2.3' }],
    });
    await waitFor(() => cache.query('pool.internal.fitfak.net', 'A').records.length === 3);
    check('a multi-record RRset resolves as a set', cache.query('pool.internal.fitfak.net', 'A').records.length === 3);

    // Replacing the set wholesale is the only way to avoid leaving a stale member behind.
    await dns.putRRset({
      zone: 'internal.fitfak.net', name: 'pool.internal.fitfak.net', type: 'A', ttl: 60,
      rdatas: [{ address: '10.0.2.9' }],
    });
    await waitFor(() => cache.query('pool.internal.fitfak.net', 'A').records.length === 1);
    check('replacing the set leaves no stale members',
      cache.query('pool.internal.fitfak.net', 'A').records[0].rdata.address === '10.0.2.9');
  }

  console.log('\n[11] Everything survives a close and reopen');
  {
    cache.stop();
    await manager.closeDatabase(dbId);

    const { ClientSecretKeyProvider } = require('../src');
    const reopened = await manager.openDatabase({
      ownerId: 'ops', dbId, requesterId: 'ops',
      keyProvider: new ClientSecretKeyProvider(Buffer.from(clientSecret, 'base64')),
    });

    const vault2 = new SecretStore({ database: reopened });
    const pair = await vault2.getCertificatePair('api.fitfak.net');
    check('the active certificate version survives a reopen', pair.version === 2);

    const dns2 = new DnsStore({ database: reopened });
    const resolved = await dns2.resolve('idp.internal.fitfak.net', 'AAAA');
    check('DNS records survive a reopen', JSON.parse(resolved[0].rdataJson).address === 'fd00::20');

    const cache2 = await dns2.zoneCache('internal.fitfak.net');
    check('and the cache rebuilds from them', cache2.query('auth.internal.fitfak.net', 'A').records[0].rdata.address === '10.0.0.20');
    cache2.stop();
    await manager.closeDatabase(dbId);
  }

  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - secrets and DNS: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
