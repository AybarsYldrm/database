'use strict';

const path = require('node:path');
const fsp = require('node:fs/promises');

const { DatabaseManager, ClientSecretKeyProvider, PkiVault } = require('../src');
const { PURPOSES, AUTHORITY_ROLES } = require('../src/pki-vault');
const { makeStubSsl } = require('./helpers/stub-ssl');

// Certificate authorities living in the encrypted store instead of in files.
//
// The thing being replaced is a directory of PEMs whose only protection is `chmod 600`. What is
// checked here is not that encryption happens -- the storage engine's own suite covers that --
// but the properties the vault adds on top of it:
//
//   - a root cannot be created twice, because a second root is a second trust anchor and not a
//     rotation of the first
//   - each purpose has exactly one issuer, so issuance is deterministic and a revocation covers
//     the whole population it is supposed to
//   - a compromised authority stops being able to sign, including from the warm signer cache
//   - existing on-disk material can be imported without regenerating the trust anchor
//
// @fitfak/ssl is not installable in this checkout, so a stub stands in for the PKI primitives
// (see helpers/stub-ssl.js). Everything under test here is the vault's bookkeeping; the real
// package produces real DER for the same calls.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

async function rejects(label, fn) {
  let threw = false;
  try { await fn(); } catch (_) { threw = true; }
  check(label, threw);
}

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-pki-vault');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const manager = new DatabaseManager({ baseDir });
  const keyProvider = new ClientSecretKeyProvider(Buffer.alloc(32, 7));
  const { db } = await manager.createDatabase({ ownerId: 'test', name: 'pki', keyProvider });

  const ssl = makeStubSsl();
  const vault = await PkiVault.open(db, { ssl });

  console.log('\n1. The root');

  const root = await vault.createRoot({ commonName: 'FITFAK Root CA G1', trustDomain: 'fitfak.net' });
  check('a root is created', root.role === AUTHORITY_ROLES.ROOT);
  check('it has no parent', root.parent === null);
  check('its trust domain is recorded', root.trustDomain === 'fitfak.net');

  await rejects('a second root is refused, because it would be a second trust anchor',
    () => vault.createRoot({ commonName: 'FITFAK Root CA G1' }));

  console.log('\n2. Intermediates, one per purpose');

  await vault.createIntermediate({
    name: 'workload-ca',
    commonName: 'FITFAK Workload Issuing CA G1',
    purposes: [PURPOSES.WORKLOAD, PURPOSES.TLS_CLIENT],
  });
  await vault.createIntermediate({
    name: 'tls-ca',
    commonName: 'FITFAK TLS Issuing CA G1',
    purposes: [PURPOSES.TLS_SERVER],
  });

  const authorities = await vault.listAuthorities();
  check('all three authorities are listed', authorities.length === 3);
  check('the root sorts first', authorities[0].role === AUTHORITY_ROLES.ROOT);

  const workloadIssuer = await vault.findIssuerForPurpose(PURPOSES.WORKLOAD);
  check('a purpose resolves to its designated issuer', workloadIssuer.name === 'workload-ca');
  check('a second purpose on the same issuer also resolves',
    (await vault.findIssuerForPurpose(PURPOSES.TLS_CLIENT)).name === 'workload-ca');
  check('a different purpose resolves elsewhere',
    (await vault.findIssuerForPurpose(PURPOSES.TLS_SERVER)).name === 'tls-ca');

  await rejects('a purpose with no designated issuer is an error, not a fallback',
    () => vault.findIssuerForPurpose(PURPOSES.EMAIL));

  await rejects('an unknown purpose is refused at creation, not silently stored',
    () => vault.createIntermediate({ name: 'typo-ca', commonName: 'x', purposes: ['tls-serverr'] }));

  await vault.createIntermediate({
    name: 'workload-ca-2', commonName: 'Second workload CA', purposes: [PURPOSES.WORKLOAD],
  });
  await rejects('two issuers for one purpose is refused at lookup, not resolved arbitrarily',
    () => vault.findIssuerForPurpose(PURPOSES.WORKLOAD));

  console.log('\n3. Signing material');

  const signer = await vault.loadSigner('tls-ca');
  check('a signer carries the private key', !!signer.privateKey);
  check('and the issuer DN comes from its own certificate', !!signer.name);
  check('the signer is cached for the connection rates short-lived certificates imply',
    (await vault.loadSigner('tls-ca')) === signer);

  const chain = await vault.getChainPem('tls-ca');
  check('the chain runs intermediate then root', chain.length === 2);
  check('it ends at the root', chain[1] === root.certPem);

  const anchors = await vault.getTrustAnchorsPem();
  check('the trust anchors are the roots alone', anchors.length === 1 && anchors[0] === root.certPem);

  console.log('\n4. Compromise');

  await vault.markCompromised('tls-ca', { reason: 'key exposed in a backup' });
  await rejects('a compromised authority cannot sign', () => vault.loadSigner('tls-ca'));
  await rejects('and it is no longer selectable for its purpose',
    () => vault.findIssuerForPurpose(PURPOSES.TLS_SERVER));
  check('the other authorities are untouched',
    (await vault.findIssuerForPurpose(PURPOSES.TLS_CLIENT)).name === 'workload-ca');

  console.log('\n5. Importing what is already on disk');

  const existing = ssl.generateEcRootCA({ commonName: 'Legacy Root' });
  const imported = await vault.importAuthority({
    name: 'legacy-root',
    certPem: existing.certPem,
    privateKeyPem: ssl.ecPrivToPem(existing),
    role: AUTHORITY_ROLES.ROOT,
  });
  check('on-disk material is importable', imported.imported === true);
  check('and re-importing is a no-op rather than a second version',
    (await vault.importAuthority({
      name: 'legacy-root', certPem: existing.certPem, privateKeyPem: ssl.ecPrivToPem(existing),
    })).imported === false);
  check('the imported authority can sign', !!(await vault.loadSigner('legacy-root')).privateKey);

  console.log('\n6. The material is a record, not a file');

  const raw = await db.collection('secrets').findOne('name', 'pki/root.key');
  check('the private key is stored as a secrets record', !!raw);
  check('it is marked as a private key', raw.kind === 'private-key');
  check('and it expires with its certificate', Number(raw.notAfter) > Date.now());

  await db.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - PKI vault: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
