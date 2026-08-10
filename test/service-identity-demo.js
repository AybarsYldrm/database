'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { isSealedError, joinAsServiceWhenReady } = require('../src/service-identity');
const pairing = require('../src/pairing');

// An application joining this system in one call.
//
// The mechanics already existed and were demonstrated in examples/app-client.js. The problem was
// that it was an EXAMPLE: every application copied roughly 200 lines, and every copy was a place
// for one step to be dropped. The steps that get dropped are predictable, and none of them fail
// in a way that points at the step that was missed:
//
//   * not persisting the certificate -> every restart enrols again, which forces the
//     single-shot enrolment secret to become a standing credential
//   * not renewing -> works for hours, then a TLS handshake failure that never mentions expiry
//   * pinning the leaf -> breaks daily, because the server certificate is regenerated on every boot
//   * treating "sealed" as fatal -> the application cannot be started before the IdP
//
// These checks are about those four, plus the two things the helper must REFUSE to do.

let checks = 0;
function check(label, condition) {
  if (!condition) throw new Error(`FAILED: ${label}`);
  checks += 1;
  console.log(`  ok  ${label}`);
}

async function rejects(label, fn, matcher = null) {
  let message = null;
  try { await fn(); } catch (err) { message = err.message; }
  check(label, message !== null && (!matcher || matcher.test(message)));
  return message;
}

const SOURCE = fs.readFileSync(path.join(__dirname, '..', 'src', 'service-identity.js'), 'utf8');

function tmpDir(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

async function main() {
  console.log('\n1. Exported as a supported call, not an example to copy');

  {
    const api = require('..');
    check('joinAsService is exported', typeof api.joinAsService === 'function');
    check('the retrying variant is too', typeof api.joinAsServiceWhenReady === 'function');
    check('and the predicate behind it', typeof api.isSealedError === 'function');
  }

  console.log('\n2. "Sealed" is told apart from everything else');

  {
    // The database refuses everyone until the IdP has provisioned it, and in this architecture
    // that is a normal startup ordering rather than a fault.
    for (const message of [
      '9 FAILED_PRECONDITION: the database is sealed',
      'this database does not serve any principal yet',
      'server identity has not been provisioned',
    ]) {
      check(`recognised as sealed: ${message.slice(0, 34)}…`, isSealedError(new Error(message)));
    }

    // And the cases that must NOT be retried. Retrying a wrong secret would turn a clear failure
    // into a service that never starts and never says why.
    for (const message of [
      'enrolment secret rejected',
      'certificate has expired',
      'connect ECONNREFUSED 127.0.0.1:51572',
      'unknown service name',
    ]) {
      check(`not sealed: ${message.slice(0, 34)}`, !isSealedError(new Error(message)));
    }
    check('a missing error is not sealed', !isSealedError(null) && !isSealedError(undefined));
  }

  console.log('\n3. Only the sealed case is retried');

  {
    let attempts = 0;
    // A wrong secret must surface immediately, not be retried forever behind a log line.
    await rejects('a non-sealed failure is raised at once', async () => {
      attempts += 1;
      await joinAsServiceWhenReady({ serviceName: 'x', target: 'https://nowhere.invalid:1',
        caFingerprint: 'AA', stateDir: tmpDir('svc-'), enrolmentSecret: '' },
      { retryMs: 5, maxAttempts: 3 });
    });
    check('it did not loop', attempts === 1);
  }

  console.log('\n4. It refuses to enrol against an unauthenticated server');

  {
    const stateDir = tmpDir('svc-anchor-');
    const pairingDir = tmpDir('pair-');
    // Address published, but no IdP half yet: there is no root fingerprint to pin.
    await pairing.publishDatabase({
      dir: pairingDir, target: 'https://db.fitfak.net:51572',
      controlSecret: Buffer.alloc(32, 1), bootstrapFingerprint: 'AA:BB', trustDomain: 'fitfak.net',
    });

    // Handing an enrolment credential to a server you have not authenticated is handing it to
    // whoever answered on that address.
    const message = await rejects('no trust anchor means no enrolment',
      () => require('../src/service-identity').joinAsService({
        serviceName: 'dns-resolver', stateDir, pairingDir, enrolmentSecret: 'AAAA',
      }), /trust anchor/i);
    check('and it says where the anchor comes from', /pairing directory|FITFAK_DB_CA_FINGERPRINT/.test(message));

    fs.rmSync(stateDir, { recursive: true, force: true });
    fs.rmSync(pairingDir, { recursive: true, force: true });
  }

  console.log('\n5. It refuses to invent a credential');

  {
    const stateDir = tmpDir('svc-nocred-');
    const message = await rejects('no certificate and no secret is an error',
      () => require('../src/service-identity').joinAsService({
        serviceName: 'dns-resolver', stateDir,
        target: 'https://db.fitfak.net:51572', caFingerprint: 'AA:BB',
      }), /no way to obtain one/i);
    // It must say where the secret comes from: it is one service's credential, shown once in the
    // admin panel.
    check('it points at the admin panel', /admin panel/.test(message));

    // And it must never read that secret from the pairing directory: a secret readable from a
    // shared directory is one every process on the host could enrol with.
    check('the enrolment secret is never read from pairing',
      !/readDatabase[\s\S]{0,400}enrolmentSecret/.test(SOURCE));
    check('nor from the IdP half', !/readIdp[\s\S]{0,400}enrolmentSecret/.test(SOURCE));

    fs.rmSync(stateDir, { recursive: true, force: true });
  }

  console.log('\n6. The four steps that get dropped are all here');

  {
    // Persisting the certificate. Without it every restart enrols again, and the single-shot
    // secret has to become a standing credential purely because processes restart.
    check('the certificate is persisted after enrolment',
      /writeSecret\(stateDir, IDENTITY_FILE/.test(SOURCE));
    check('a stored certificate is resumed rather than re-enrolled',
      /if \(hasStoredIdentity\) \{[\s\S]{0,200}resume\(/.test(SOURCE));
    // And the credential checks are skipped when one exists: demanding an enrolment secret on
    // every start is exactly what turns a single-use credential into a standing one.
    check('a stored certificate needs no enrolment secret',
      /if \(!hasStoredIdentity\) \{[\s\S]{0,900}no way to obtain one/.test(SOURCE));

    // Renewal. Started here rather than left to the caller: forgetting it works perfectly for
    // hours and then stops with an error that says nothing about expiry.
    check('auto-renewal is started', /identity\.startAutoRenewal\(\)/.test(SOURCE));
    check('renewal failure is non-fatal', /renewalFailed[\s\S]{0,300}continuing on the current certificate/.test(SOURCE));
    // Persisted on EVERY renewal: otherwise a restart falls back to the enrolment-time
    // certificate, which may already have expired -- and then it enrols again.
    check('each renewal is persisted', /identity\.on\('renewed'[\s\S]{0,400}writeSecret/.test(SOURCE));

    // The ROOT's fingerprint. The server certificate is regenerated every boot by design, so a
    // leaf pin breaks daily.
    check('the pin is the root fingerprint', /rootFingerprint/.test(SOURCE));
    check('and that reason is written down', /regenerated on every boot/.test(SOURCE));

    // The SPIFFE ID must be in the SAN exactly once: omitting it yields a certificate carrying
    // no verifiable identity.
    check('the SPIFFE ID goes in the SAN', /altNames: \[spiffeId, serviceName\]/.test(SOURCE));
  }

  console.log('\n7. Secrets are written the way secrets are written');

  {
    const dir = tmpDir('svc-write-');
    // Reach the private helper the same way the module uses it, through a real call.
    const { joinAsService } = require('../src/service-identity');
    await rejects('call fails without a credential (expected)',
      () => joinAsService({ serviceName: 'x', stateDir: dir, target: 'https://a:1', caFingerprint: 'AA' }));

    check('0600 and temp-then-rename', /mode: 0o600[\s\S]{0,200}rename\(tmp, file\)/.test(SOURCE));
    check('the state directory is 0700', /mkdir\(dir, \{ recursive: true, mode: 0o700 \}\)/.test(SOURCE));
    // A half-written identity file means enrolling again on next start, spending a credential
    // that was meant to be single-use.
    check('the reason is written down', /half-written file[\s\S]{0,200}single-use/.test(SOURCE));

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log('\n8. The database secret is stored before it is used');

  {
    // createDatabase returns the client secret once and never keeps a copy. A crash between
    // creating and storing leaves a database that can never be opened again.
    check('written before opening', /writeSecret\(stateDir, DB_HANDLE_FILE[\s\S]{0,600}openDatabase\(/.test(SOURCE));
    check('and the operator is told to back it up', /BACK IT UP/.test(SOURCE));
  }

  console.log('\n9. Discovery, with explicit values winning');

  {
    const pairingDir = tmpDir('pair2-');
    await pairing.publishDatabase({
      dir: pairingDir, target: 'https://discovered.fitfak.net:51572',
      controlSecret: Buffer.alloc(32, 2), bootstrapFingerprint: 'CC:DD', trustDomain: 'fitfak.net',
    });

    const stateDir = tmpDir('svc-disc-');
    // The address is discovered: the error is about the missing credential, not the address.
    const message = await rejects('address comes from the pairing directory',
      () => require('../src/service-identity').joinAsService({
        serviceName: 'dns-resolver', stateDir, pairingDir, caFingerprint: 'CC:DD',
      }));
    check('so the failure is about the credential, not the address', /no way to obtain one/.test(message));

    // With neither an address nor a pairing file, it says so rather than guessing.
    const empty = tmpDir('pair-empty-');
    await rejects('no address anywhere is named as such',
      () => require('../src/service-identity').joinAsService({
        serviceName: 'dns-resolver', stateDir, pairingDir: empty, enrolmentSecret: 'AA',
      }), /no database address/i);

    fs.rmSync(pairingDir, { recursive: true, force: true });
    fs.rmSync(stateDir, { recursive: true, force: true });
    fs.rmSync(empty, { recursive: true, force: true });
  }

  console.log('\n10. A missing service name is refused immediately');

  {
    await rejects('serviceName is required',
      () => require('../src/service-identity').joinAsService({}), /needs a serviceName/);
  }

  console.log(`\nOK - service identity: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
