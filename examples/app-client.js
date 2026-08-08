'use strict';

// How an ordinary application connects to fitdb.
//
//   node examples/app-client.js
//
// "Ordinary" means: not the identity provider. The IdP is the one service that bootstraps the
// database, and it does so through a control plane nothing else can reach (examples/idp-bootstrap.js).
// Everything after it — an SMTP relay, a DNS resolver, a job runner — goes through the path in
// this file, and that path has not changed: enrol once, upgrade to mTLS, renew before expiry.
//
// Two things ARE different, and both are visible below:
//
//   1. Connecting before the IdP is up now fails with FAILED_PRECONDITION and a message that
//      says why. Previously it would have succeeded against a database that had no way to know
//      who you were.
//
//   2. The identity you ask for is a SPIFFE ID in the certificate's URI SAN, and it must match
//      what the attestor granted exactly — you cannot omit it, and you cannot ask for another.
//
// The rest is the same three calls it always was.

const {
  enroll, resume, connectDatabase, createFitfakSslCsrProvider, spiffe,
} = require('..');

const fsp = require('node:fs/promises');
const path = require('node:path');

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

const TARGET = process.env.FITFAK_DB_TARGET || 'https://localhost:51572';
const TRUST_DOMAIN = process.env.FITFAK_TRUST_DOMAIN || 'fitfak.net';
const SERVICE_NAME = process.env.FITFAK_SERVICE_NAME || 'smtp-service';

// Where this service keeps its certificate between restarts.
//
// Persisting it is what makes the enrolment secret genuinely single-use: without it, every
// restart would have to enrol again, which forces the secret to be multi-use and long-lived —
// a permanent backdoor next to the identity system, purely because processes get restarted.
const STATE_DIR = process.env.FITFAK_SERVICE_STATE_DIR || path.join(__dirname, '.app-state');
const IDENTITY_FILE = path.join(STATE_DIR, 'identity.json');

// The identity this service will hold. It goes in the URI SAN, not the CN.
const SPIFFE_ID = spiffe.forService(TRUST_DOMAIN, SERVICE_NAME.replace(/-service$/, '')).uri;

// One of these is required. The CA fingerprint is the better one to carry: it survives a
// legitimate rotation of the database's server certificate, which a leaf pin does not.
const CA_FINGERPRINT = process.env.FITFAK_DB_CA_FINGERPRINT || '';
const ENROLMENT_SECRET = process.env.FITFAK_ENROLMENT_SECRET || '';
// Once the IdP is up, this is the better path: the service presents a token it already holds
// rather than a secret pasted into its environment. Same endpoint, different era — see the
// composite attestor in examples/db-server.js.
const ACCESS_TOKEN = process.env.FITFAK_ACCESS_TOKEN || '';

// ---------------------------------------------------------------------------------------------

async function loadStoredIdentity() {
  try {
    const stored = JSON.parse(await fsp.readFile(IDENTITY_FILE, 'utf8'));
    return stored.certPem && stored.privateKeyPem ? stored : null;
  } catch (_) {
    return null;
  }
}

async function storeIdentity(identity) {
  await fsp.mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${IDENTITY_FILE}.tmp`;
  // 0600, temp-then-rename. Writing in place leaves a half-written file if the process dies
  // mid-write, and the next start finds it "present but corrupt".
  await fsp.writeFile(tmp, JSON.stringify(identity, null, 2), { mode: 0o600 });
  await fsp.rename(tmp, IDENTITY_FILE);
}

async function obtainIdentity() {
  const csrProvider = createFitfakSslCsrProvider();

  // ---- restart: reuse the certificate we already hold -----------------------------------
  const stored = await loadStoredIdentity();
  if (stored) {
    console.log('[app] stored certificate found — resuming, no enrolment credential spent');
    return resume({
      target: TARGET,
      certPem: stored.certPem,
      privateKeyPem: stored.privateKeyPem,
      chainPem: stored.chainPem,
      principal: stored.principal,
      roles: stored.roles,
      notAfter: stored.notAfter,
      renewAfter: stored.renewAfter,
      csrProvider,
      subject: { CN: SERVICE_NAME },
      altNames: [SPIFFE_ID, SERVICE_NAME],
      logger: console,
    });
  }

  // ---- first run: enrol -------------------------------------------------------------------
  if (!CA_FINGERPRINT) {
    // Sending an enrolment credential to a server you have not authenticated is sending it to
    // whoever answered on that address.
    throw new Error(
      'FITFAK_DB_CA_FINGERPRINT is required on first run. Without it there is no way to '
      + 'authenticate the database before handing it an enrolment credential.',
    );
  }
  if (!ENROLMENT_SECRET && !ACCESS_TOKEN) {
    throw new Error(
      'Either FITFAK_ENROLMENT_SECRET (first provisioning) or FITFAK_ACCESS_TOKEN (once the '
      + 'identity provider is up) is required.',
    );
  }

  console.log(`[app] no stored certificate — enrolling as ${SPIFFE_ID}`);

  const identity = await enroll({
    target: TARGET,
    serviceName: SERVICE_NAME,
    csrProvider,
    // Pinning the CA rather than shipping the bundle: enough to authenticate the server on
    // first contact, and it survives a legitimate server-certificate rotation.
    trust: { pinnedFingerprints: [CA_FINGERPRINT] },
    bootstrap: ACCESS_TOKEN
      ? { token: ACCESS_TOKEN }
      : { secret: Buffer.from(ENROLMENT_SECRET, 'base64') },
    subject: { CN: SERVICE_NAME },
    // The SPIFFE ID must be here. The enrolment service requires the granted ID to be present
    // exactly once — omitting it would produce a certificate with no verifiable identity, and
    // asking for a different one is refused outright.
    altNames: [SPIFFE_ID, SERVICE_NAME],
    logger: console,
  });

  await storeIdentity({
    certPem: identity.certPem,
    privateKeyPem: identity.privateKeyPem,
    chainPem: identity.chainPem,
    principal: identity.principal,
    roles: identity.roles,
    notAfter: identity.notAfter,
    renewAfter: identity.renewAfter,
  });

  console.log('[app] enrolled. The enrolment credential is SPENT — remove it from this');
  console.log('      environment. Renewal goes over mTLS from here and never touches it again.');
  return identity;
}

async function main() {
  let identity;
  try {
    identity = await obtainIdentity();
  } catch (err) {
    // The one failure worth naming, because it is not a bug and not transient: the database is
    // refusing everyone until the identity provider has connected.
    if (/sealed|provisioned|does not serve any principal/i.test(err.message)) {
      console.error(
        `\n[app] The database is not open yet.\n\n  ${err.message}\n\n`
        + '  This is the intended behaviour, not a fault. Every service here takes its\n'
        + '  authority from the identity provider, so the database refuses everyone until\n'
        + '  the IdP has connected. Start the IdP and try again.\n',
      );
      process.exit(1);
    }
    throw err;
  }

  // Renews at the server-advertised renewAfter — two thirds of the lifetime for a service
  // certificate, half for anything short-lived. A fresh key pair is generated each time: if
  // the previous key was ever exposed, renewing onto it carries the exposure forward.
  identity.startAutoRenewal();
  identity.on('renewed', async (event) => {
    await storeIdentity({
      certPem: identity.certPem,
      privateKeyPem: identity.privateKeyPem,
      chainPem: identity.chainPem,
      principal: identity.principal,
      roles: identity.roles,
      notAfter: event.notAfter,
      renewAfter: event.renewAfter,
    });
    console.log(`[app] certificate renewed until ${new Date(event.notAfter).toISOString()}`);
  });
  identity.on('renewalFailed', (err) => {
    // Non-destructive: the current certificate keeps working until it actually expires, so a
    // transient CA outage is a warning rather than an outage of this service.
    console.warn(`[app] renewal failed, continuing on the current certificate: ${err.message}`);
  });

  console.log(`[app] principal ${identity.principal}, roles ${identity.roles.join(', ') || '(none)'}`);
  console.log(`[app] certificate expires ${new Date(identity.notAfter).toISOString()}`);

  // ---- the data plane ---------------------------------------------------------------------
  const handle = await connectDatabase({ target: TARGET, identity });

  const who = await handle.whoAmI();
  console.log(`[app] the server sees: ${who.principal} (${who.securityLevel})`);
  if (who.spiffeId) console.log(`[app] workload identity: ${who.spiffeId}`);

  // A database this service owns. `clientSecret` is returned exactly once and is never stored
  // server-side: losing it means losing the data, so it belongs wherever this service keeps
  // its other secrets.
  const dbHandleFile = path.join(STATE_DIR, 'database.json');
  let dbHandle;
  try {
    dbHandle = JSON.parse(await fsp.readFile(dbHandleFile, 'utf8'));
  } catch (_) {
    const created = await handle.createDatabase(SERVICE_NAME);
    // Stored BEFORE use: a crash in between would leave a database nobody can open again.
    await fsp.writeFile(dbHandleFile, JSON.stringify(created, null, 2), { mode: 0o600 });
    dbHandle = created;
    console.log(`[app] created database ${created.dbId} — back up ${dbHandleFile}`);
  }

  const db = await handle.openDatabase(dbHandle);
  await db.defineCollection('outbox', {
    fields: [
      { no: 2, name: 'recipient', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'subject', type: 'string' },
      { no: 4, name: 'queuedAt', type: 'int64', rangeBucket: { width: 3600000 }, diskBacked: true },
      { no: 5, name: 'state', type: 'string', index: true },
    ],
  });

  const outbox = db.collection('outbox');
  const id = await outbox.insert({
    recipient: 'aybars@fitfak.net', subject: 'hoş geldin', queuedAt: Date.now(), state: 'queued',
  });
  console.log(`[app] queued ${id}`);
  console.log(`[app] pending: ${(await outbox.find('state', 'queued')).length}`);

  // A live view instead of polling: the decrypt happens once and the database says when the
  // copy goes stale.
  const view = outbox.watch();
  await view.ready();
  view.on('put', (event) => console.log(`[app] outbox ${event.op} ${event.id}`));
  console.log(`[app] watching ${view.size} record(s)`);

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      view.stop();
      handle.close();
      identity.close();
      process.exit(0);
    });
  }
}

main().catch((err) => { console.error('\n[app] FAILED:', err.message); process.exit(1); });
