'use strict';

const path = require('node:path');
const fsp = require('node:fs/promises');
const { X509Certificate } = require('node:crypto');

const { createFitfakSslCaBackend } = require('../src/provisioning/ca-backend');
const { assertIdentityMatchesGrant } = require('../src/provisioning/enrollment-service');

// What identity an enrolling peer actually ends up holding.
//
// This suite exists because of a real escalation, not a hypothetical one. The enrolment
// service compares the CSR's subject against the grant the attestor produced:
//
//     const requestedCn = parsedCsr.subject?.CN;
//     const grantedCn   = grant.subject?.CN;
//     if (grantedCn && requestedCn && requestedCn !== grantedCn) throw ...
//
// @fitfak/ssl's parseCSR returned `subjectNameDer` (raw DER) and no decoded `subject`, so
// through the @fitfak/ssl CA backend `requestedCn` was always `undefined`, the `&&` chain
// short-circuited, and the comparison never ran. issueCertificateFromCSR then copied the
// CSR's own subject into the certificate verbatim. A peer holding a bootstrap credential for
// 'idp-service' could therefore submit a CSR naming any other principal and be certified as
// it -- and since createPrincipalResolver maps CN to principal to roles, that is a direct
// route to any entry in the allow-list.
//
// The existing suites did not catch it because test/helpers/test-pki.js decodes the subject
// properly. The test double was safer than the real backend, which is the specific way this
// class of bug survives a green build.
//
// Two independent fixes are asserted here, because either alone would leave the boundary
// resting on a single comparison:
//
//   1. the check fails CLOSED when the subject cannot be read, instead of skipping;
//   2. the subject is IMPOSED from the grant at issuance, so the CSR's own name cannot reach
//      the certificate even if a check is bypassed.

let ssl;
try {
  ssl = require('@fitfak/ssl');
} catch (_) {
  console.log('SKIP - enrolment identity binding: @fitfak/ssl is not installed');
  process.exit(0);
}

let checks = 0;
function check(name, condition) {
  checks += 1;
  if (!condition) throw new Error(`check failed: ${name}`);
  console.log(`  ok ${name}`);
}

function makeCsr(dnPairs, sans = []) {
  const key = ssl.generateEcKeyPair('P-256');
  return ssl.generateCSR({ keyType: 'ec', curveName: key.curve, ...key }, dnPairs, sans);
}

const CN = ssl.oid.OIDs.commonName;
const O = ssl.oid.OIDs.orgName;

async function main() {
  const baseDir = path.join(__dirname, '..', '.tmp-identity-binding');
  await fsp.rm(baseDir, { recursive: true, force: true });

  const ca = ssl.CertificateAuthority.create({
    useIntermediate: true, organization: 'FITFAK', country: 'TR',
  });
  const backend = createFitfakSslCaBackend({ ca, ssl });

  // What the attestor authorised. Everything below is measured against this.
  const grant = {
    principal: 'idp-service',
    subject: { CN: 'idp-service' },
    altNames: ['idp.internal.fitfak.net'],
  };

  console.log('\n[1] The CA backend decodes a subject at all');
  const plain = makeCsr([[ssl.oid.OIDs.country, 'TR'], [O, 'FITFAK'], [CN, 'idp-service']]);
  const parsedPlain = await backend.parseCsr(plain);
  check('parseCsr reports a decoded subject', parsedPlain.subject && parsedPlain.subject.CN === 'idp-service');
  check('and the other DN components', parsedPlain.subject.O === 'FITFAK' && parsedPlain.subject.C === 'TR');
  check('proof of possession still verifies', parsedPlain.verified === true);

  console.log('\n[2] The original escalation is refused');
  // No SAN at all: the SAN half of the check has nothing to catch, so this isolates the CN path.
  const impostor = makeCsr([[CN, 'db-admin-service']], []);
  const parsedImpostor = await backend.parseCsr(impostor);
  check('the impostor CN is visible to the check', parsedImpostor.subject.CN === 'db-admin-service');
  let refused = false;
  try { assertIdentityMatchesGrant(parsedImpostor, grant); } catch (_) { refused = true; }
  check('a CSR naming another principal is refused', refused);

  console.log('\n[3] A missing subject fails closed rather than skipping the check');
  // This is the shape the @fitfak/ssl backend used to return. It must never be treated as
  // "nothing to compare, therefore fine".
  let failedClosed = false;
  try { assertIdentityMatchesGrant({ subject: {}, altNames: [] }, grant); }
  catch (_) { failedClosed = true; }
  check('an undecodable subject refuses issuance', failedClosed);

  console.log('\n[4] A second common name cannot hide behind the first');
  const twoCn = makeCsr([[CN, 'idp-service'], [CN, 'db-admin-service']], []);
  const parsedTwoCn = await backend.parseCsr(twoCn);
  check('both common names are reported', parsedTwoCn.commonNames.length === 2);
  let multiRefused = false;
  try { assertIdentityMatchesGrant(parsedTwoCn, grant); } catch (_) { multiRefused = true; }
  check('a CSR with two common names is refused', multiRefused);

  console.log('\n[5] SAN escalation stays refused');
  const evilSan = makeCsr([[CN, 'idp-service']], [{ type: 'dns', value: 'evil.internal.fitfak.net' }]);
  let sanRefused = false;
  try { assertIdentityMatchesGrant(await backend.parseCsr(evilSan), grant); } catch (_) { sanRefused = true; }
  check('an unauthorised subjectAltName is refused', sanRefused);

  console.log('\n[6] The legitimate enrolment still succeeds');
  const good = makeCsr([[CN, 'idp-service']], [{ type: 'dns', value: 'idp.internal.fitfak.net' }]);
  const parsedGood = await backend.parseCsr(good);
  assertIdentityMatchesGrant(parsedGood, grant);
  const issued = await backend.issue({ csrPem: good, subject: grant.subject, altNames: grant.altNames });
  const cert = new X509Certificate(issued.certPem);
  check('a certificate is issued', !!issued.certPem);
  check('with the granted common name', /CN=idp-service/.test(cert.subject));
  check('and only the requested subjectAltName', cert.subjectAltName === 'DNS:idp.internal.fitfak.net');

  console.log('\n[7] The subject is imposed, not copied from the request');
  // Defence in depth: even reaching issue() with a CSR that names someone else -- a bypassed
  // check, a future backend that forgets to compare -- must not produce that name.
  const imposed = await backend.issue({ csrPem: impostor, subject: grant.subject, altNames: grant.altNames });
  const imposedCert = new X509Certificate(imposed.certPem);
  check('the CSR asked for db-admin-service', parsedImpostor.subject.CN === 'db-admin-service');
  check('the certificate says idp-service', /CN=idp-service/.test(imposedCert.subject));
  check('and carries no trace of the requested name', !/db-admin-service/.test(imposedCert.subject));

  console.log('\n[8] The same key cannot be certified twice, even under a race');
  // "One person can produce several certificates from the same CSR" is the same class of
  // problem one layer down: whatever decides a key is fresh has to decide it atomically.
  // The natural spelling -- findOne, then insert -- is two separate trips through the write
  // queue, so concurrent callers all observe "absent" and all insert.
  const { DatabaseManager, ClientSecretKeyProvider, SnowflakeGenerator, randomClientSecret } = require('../src');
  const mgr = new DatabaseManager({ baseDir, snowflake: new SnowflakeGenerator({ workerId: 1 }) });
  const { db } = await mgr.createDatabase({
    ownerId: 'ra', name: 'ra', keyProvider: new ClientSecretKeyProvider(randomClientSecret()),
  });
  await db.defineCollectionAsync('certificates', {
    fields: [
      { no: 2, name: 'skidHex', type: 'string', index: true, required: true },
      { no: 3, name: 'serialNumberHex', type: 'string' },
    ],
  });
  const certs = db.collection('certificates');

  const skid = 'deadbeefcafe';
  const race = await Promise.allSettled(Array.from({ length: 20 }, (_, i) => (
    certs.insertUnique({ skidHex: skid, serialNumberHex: `s${i}` }, { unique: ['skidHex'] })
  )));
  const accepted = race.filter((r) => r.status === 'fulfilled').length;
  const duplicates = race.filter((r) => r.status === 'rejected' && r.reason.code === 'UNIQUE_CONSTRAINT').length;
  check('exactly one of 20 concurrent issuances is accepted', accepted === 1);
  check('the other 19 are refused as duplicates', duplicates === 19);
  check('and only one record exists for that key', (await certs.find('skidHex', skid)).length === 1);

  // Deleting the record must free the key again, or revoking a certificate would silently
  // brick that key forever with nothing to point at as the cause.
  const [existing] = await certs.find('skidHex', skid);
  await certs.delete(existing._id);
  const reissued = await certs.insertUnique({ skidHex: skid, serialNumberHex: 'after-delete' }, { unique: ['skidHex'] });
  check('a deleted record frees the value again', !!reissued);

  await db.close();
  await fsp.rm(baseDir, { recursive: true, force: true });
  console.log(`\nOK - enrolment identity binding: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err); process.exit(1); },
);
