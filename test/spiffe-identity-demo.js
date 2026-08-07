'use strict';

const spiffe = require('../src/provisioning/spiffe');
const { assertSpiffeMatchesGrant } = require('../src/provisioning/identity-binding');

// SPIFFE identity: the grammar, and the grant check built on it.
//
// The parser is strict on purpose, and each rejection below corresponds to a way two
// implementations could read the same certificate as two different identities. Percent-encoding
// and dot-segments are the classic pair: `spiffe://fitfak.net/service/%2e%2e/admin` and
// `spiffe://fitfak.net/admin` are the same URI after normalisation and different strings before
// it, so a verifier that compares strings and an issuer that normalises disagree about who the
// holder is. Refusing to parse either form removes the disagreement rather than picking a side.
//
// The second half is the check the enrolment service runs. Its interesting case is not "the CSR
// asked for someone else's ID" -- that one is obvious -- but "the CSR asked for no ID at all"
// while the grant carried one. The SAN loop in assertIdentityMatchesGrant cannot see that,
// because a missing name is not a name outside the allow-list, and the resulting certificate is
// a valid credential with the authorisation-carrying field quietly removed.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

function rejects(label, fn) {
  let threw = false;
  try { fn(); } catch (_) { threw = true; }
  check(label, threw);
}

function main() {
  console.log('\n1. Parsing');

  const id = spiffe.parse('spiffe://fitfak.net/service/idp');
  check('trust domain is separated from the path', id.trustDomain === 'fitfak.net' && id.path === '/service/idp');
  check('segments are exposed individually', id.segments.join(',') === 'service,idp');
  check('kind is the first segment', id.kind === 'service');
  check('the round trip is byte-identical', id.uri === 'spiffe://fitfak.net/service/idp');
  check('a trust-domain-only ID is legal', spiffe.parse('spiffe://fitfak.net').path === '');

  rejects('a non-spiffe scheme is refused', () => spiffe.parse('https://fitfak.net/service/idp'));
  rejects('an uppercase trust domain is refused', () => spiffe.parse('spiffe://FITFAK.net/service/idp'));
  rejects('userinfo is refused', () => spiffe.parse('spiffe://user@fitfak.net/service/idp'));
  rejects('a port is refused', () => spiffe.parse('spiffe://fitfak.net:8443/service/idp'));
  rejects('a query string is refused', () => spiffe.parse('spiffe://fitfak.net/service/idp?role=admin'));
  rejects('a fragment is refused', () => spiffe.parse('spiffe://fitfak.net/service/idp#admin'));
  rejects('a trailing slash is refused', () => spiffe.parse('spiffe://fitfak.net/service/idp/'));
  rejects('an empty segment is refused', () => spiffe.parse('spiffe://fitfak.net/service//idp'));
  rejects('a dot segment is refused', () => spiffe.parse('spiffe://fitfak.net/service/../admin'));
  rejects('a percent-encoded dot segment is refused', () => spiffe.parse('spiffe://fitfak.net/service/%2e%2e/admin'));
  rejects('a missing trust domain is refused', () => spiffe.parse('spiffe:///service/idp'));

  console.log('\n2. Prefix comparison is segment-wise, not string-wise');

  const dns = spiffe.parse('spiffe://fitfak.net/service/dns');
  const dnsEvil = spiffe.parse('spiffe://fitfak.net/service/dns-evil');
  check('a real descendant matches', dns.isUnder('spiffe://fitfak.net/service'));
  check('a string-prefix impostor does NOT match', !dnsEvil.isUnder('spiffe://fitfak.net/service/dns'));
  check('a different trust domain never matches', !spiffe.parse('spiffe://other.example/service/dns').isUnder('spiffe://fitfak.net/service'));
  check('an ID is under itself', dns.isUnder(dns));

  console.log('\n3. Reading an ID out of a certificate');

  const certLike = { altNames: ['DNS:idp.fitfak.net', 'URI:spiffe://fitfak.net/service/idp'] };
  check('the URI SAN is found among other SAN types', spiffe.fromCertificate(certLike).uri === 'spiffe://fitfak.net/service/idp');
  check("Node's comma-joined subjectAltName string is accepted too",
    spiffe.fromCertificate({ subjectAltName: 'DNS:idp.fitfak.net, URI:spiffe://fitfak.net/service/idp' }).uri
      === 'spiffe://fitfak.net/service/idp');
  check('a certificate with no URI SAN reads as null', spiffe.fromCertificate({ altNames: ['DNS:idp.fitfak.net'] }) === null);

  // Two SPIFFE IDs is the case where "take the first" would be an authorisation bug: the
  // issuer's view of who this is and the verifier's view differ by which one each one reads.
  rejects('two SPIFFE IDs in one certificate is an error, not a choice', () => spiffe.fromCertificate({
    altNames: ['URI:spiffe://fitfak.net/service/idp', 'URI:spiffe://fitfak.net/service/admin'],
  }));

  console.log('\n4. Building IDs from untrusted components');

  check('the naming convention is applied', spiffe.forDevice('fitfak.net', 'abc-123').uri === 'spiffe://fitfak.net/device/abc-123');
  // A device id arriving from a request is exactly how a slash gets into a path segment.
  rejects('a segment containing a separator cannot deepen the path',
    () => spiffe.forDevice('fitfak.net', 'abc/../service/idp'));
  rejects('a segment containing a space is refused', () => spiffe.forUser('fitfak.net', 'user id'));

  console.log('\n5. The grant check the enrolment service runs');

  const grant = { spiffeId: 'spiffe://fitfak.net/service/dns' };

  assertSpiffeMatchesGrant({ altNames: ['URI:spiffe://fitfak.net/service/dns'] }, grant);
  check('a CSR asking for exactly the granted ID is accepted', true);

  rejects('a CSR asking for a different ID is refused',
    () => assertSpiffeMatchesGrant({ altNames: ['URI:spiffe://fitfak.net/service/idp'] }, grant));

  // The one the SAN allow-list loop structurally cannot catch.
  rejects('a CSR that OMITS the granted ID is refused',
    () => assertSpiffeMatchesGrant({ altNames: ['DNS:dns.fitfak.net'] }, grant));

  rejects('a CSR asking for two IDs is refused',
    () => assertSpiffeMatchesGrant({
      altNames: ['URI:spiffe://fitfak.net/service/dns', 'URI:spiffe://fitfak.net/service/idp'],
    }, grant));

  rejects('a malformed SPIFFE URI is refused rather than ignored',
    () => assertSpiffeMatchesGrant({ altNames: ['URI:spiffe://FITFAK.net/service/dns'] }, grant));

  // No grant means the applicant may not name itself.
  rejects('a CSR asking for an ID with no SPIFFE grant is refused',
    () => assertSpiffeMatchesGrant({ altNames: ['URI:spiffe://fitfak.net/service/dns'] }, { subject: { CN: 'dns' } }));

  assertSpiffeMatchesGrant({ altNames: ['DNS:dns.fitfak.net'] }, { subject: { CN: 'dns' } });
  check('a CSR with no ID and no SPIFFE grant is unaffected', true);

  console.log('\n6. The relying-party verifier');

  const verify = spiffe.createVerifier({
    trustDomain: 'fitfak.net',
    allowed: ['spiffe://fitfak.net/service', 'spiffe://fitfak.net/device'],
  });
  check('an allowed prefix passes', verify(certLike).uri === 'spiffe://fitfak.net/service/idp');
  rejects('an ID outside every allowed prefix is refused',
    () => verify({ altNames: ['URI:spiffe://fitfak.net/user/abc'] }));
  rejects('an ID from another trust domain is refused even under an allowed prefix',
    () => verify({ altNames: ['URI:spiffe://other.example/service/idp'] }));
  rejects('a peer with no SPIFFE ID at all is refused', () => verify({ altNames: ['DNS:idp.fitfak.net'] }));

  console.log(`\nOK - SPIFFE identity: ${checks} checks passed.`);
}

try { main(); }
catch (err) { console.error('\nFAILED:', err.message); process.exit(1); }
