'use strict';

const fsp = require('node:fs/promises');
const path = require('node:path');

const pairing = require('./pairing');

// An application joining this system, in one call.
//
//     const identity = await joinAsService({ serviceName: 'dns-resolver' });
//     const users = identity.db.collection('users');
//
// Everything below that line already existed and was demonstrated in examples/app-client.js.
// The problem was that it was an EXAMPLE: every application had to copy roughly 200 lines of
// discovery, enrol-or-resume, persistence, renewal and connection handling, and every copy was
// a place for one of those steps to be dropped.
//
// The steps that get dropped are predictable, and each one fails in a way that is not obviously
// about the step:
//
//   NOT PERSISTING THE CERTIFICATE. Every restart enrols again, which forces the enrolment
//   secret to be multi-use and long-lived -- a permanent credential sitting next to the identity
//   system, purely because processes restart. Nothing looks wrong until someone asks why a
//   single-shot secret has been used forty times.
//
//   NOT RENEWING. Certificates here are short-lived by design. An application that connects once
//   and never renews works perfectly for hours and then stops, and the error is a TLS handshake
//   failure rather than anything mentioning expiry.
//
//   PINNING THE LEAF. The database's server certificate is regenerated on every boot -- that is
//   the whole point of the sealed bootstrap. An application pinning it breaks daily; the root's
//   fingerprint is the thing that survives.
//
//   ENROLLING BEFORE THE DATABASE IS OPEN. The database refuses everyone until the IdP has
//   provisioned it, which in this architecture is a normal startup ordering rather than a fault.
//   An application that treats FAILED_PRECONDITION as fatal cannot be started first.
//
// This file does all of them, once, in a place where they can be fixed once.
//
//
// WHAT IT DELIBERATELY DOES NOT DO
//
// It does not invent an enrolment secret, and it does not read one from the pairing directory.
// That secret is ONE service's credential, issued from the admin panel and shown once. A secret
// readable from a shared directory would be a secret every process on the host could enrol with,
// and the whole identity model would reduce to "can you read /var/lib/fitfak".

const IDENTITY_FILE = 'identity.json';
const DB_HANDLE_FILE = 'database.json';

/**
 * @param {object}   opts
 * @param {string}   opts.serviceName        must match the name registered in the admin panel
 * @param {string}  [opts.stateDir]          where the certificate is kept between restarts
 * @param {string}  [opts.enrolmentSecret]   first run only; base64. Defaults to FITFAK_ENROLMENT_SECRET
 * @param {string}  [opts.accessToken]       alternative to the secret, once the IdP is up
 * @param {string}  [opts.target]            overrides pairing discovery
 * @param {string}  [opts.caFingerprint]     overrides pairing discovery
 * @param {string}  [opts.pairingDir]
 * @param {string}  [opts.trustDomain]
 * @param {string[]}[opts.roles]
 * @param {boolean} [opts.openDatabase=true] also open (or create) this service's database
 * @param {string}  [opts.databaseName]
 * @param {object}  [opts.logger]
 * @returns {{ identity, handle, db, spiffeId, principal, close }}
 */
async function joinAsService({
  serviceName,
  stateDir = process.env.FITFAK_SERVICE_STATE_DIR || path.join(process.cwd(), '.service-state'),
  enrolmentSecret = process.env.FITFAK_ENROLMENT_SECRET || '',
  accessToken = process.env.FITFAK_ACCESS_TOKEN || '',
  target = process.env.FITFAK_DB_TARGET || null,
  caFingerprint = process.env.FITFAK_DB_CA_FINGERPRINT || null,
  pairingDir = process.env.FITFAK_PAIRING_DIR || null,
  trustDomain = process.env.FITFAK_TRUST_DOMAIN || 'fitfak.net',
  roles = [],
  openDatabase = true,
  databaseName = 'main',
  logger = null,
} = {}) {
  if (!serviceName) throw new Error('fitdb: joinAsService needs a serviceName');

  // ---- everything that can be decided WITHOUT the transport, first ----------------------------
  //
  // Configuration is validated before @fitfak/grpc and @fitfak/ssl are loaded, and the ordering
  // is deliberate. Loading first means a service with a missing trust anchor reports a
  // module-resolution error instead of the thing that is actually wrong, and the operator goes
  // looking at their dependency tree rather than at their configuration.
  const discovery = await resolveEndpoint({ target, caFingerprint, pairingDir, logger });
  const stored = await readJson(path.join(stateDir, IDENTITY_FILE));
  const hasStoredIdentity = !!(stored && stored.certPem && stored.privateKeyPem);

  if (!hasStoredIdentity) {
    if (!discovery.fingerprint) {
      // Sending an enrolment credential to a server you have not authenticated is sending it to
      // whoever answered on that address.
      throw new Error(
        'fitdb: no trust anchor, so the database cannot be authenticated before the enrolment '
        + 'credential is handed to it. The identity provider publishes the root fingerprint to '
        + `the pairing directory (${pairing.pairingDir(pairingDir)}) once it has provisioned the `
        + 'database; until then pass FITFAK_DB_CA_FINGERPRINT.',
      );
    }
    if (!enrolmentSecret && !accessToken) {
      throw new Error(
        `fitdb: '${serviceName}' has no certificate yet and no way to obtain one. Register the `
        + 'application in the admin panel and pass the enrolment secret it shows once, as '
        + 'FITFAK_ENROLMENT_SECRET.',
      );
    }
  }

  // eslint-disable-next-line global-require
  const { enroll, resume, connectDatabase, createFitfakSslCsrProvider, spiffe } = require('..');

  const spiffeId = spiffe.forService(trustDomain, serviceName.replace(/-service$/, '')).uri;
  const csrProvider = createFitfakSslCsrProvider();

  // ---- the certificate: reuse it, or enrol once -----------------------------------------------
  let identity;

  if (hasStoredIdentity) {
    logger?.info?.({ service: serviceName, msg: 'stored certificate found — resuming, no credential spent' });
    identity = await resume({
      target: discovery.target,
      certPem: stored.certPem,
      privateKeyPem: stored.privateKeyPem,
      chainPem: stored.chainPem,
      principal: stored.principal,
      roles: stored.roles,
      notAfter: stored.notAfter,
      renewAfter: stored.renewAfter,
      csrProvider,
      subject: { CN: serviceName },
      altNames: [spiffeId, serviceName],
      logger,
    });
  } else {
    logger?.info?.({ service: serviceName, spiffeId, msg: 'no stored certificate — enrolling' });
    identity = await enroll({
      target: discovery.target,
      serviceName,
      csrProvider,
      // The ROOT's fingerprint, not the leaf's. The database's server certificate is regenerated
      // on every boot by design, so a leaf pin would break daily.
      trust: { pinnedFingerprints: [discovery.fingerprint] },
      bootstrap: accessToken ? { token: accessToken } : { secret: Buffer.from(enrolmentSecret, 'base64') },
      subject: { CN: serviceName },
      // The enrolment service requires the granted SPIFFE ID to be present exactly once:
      // omitting it produces a certificate carrying no verifiable identity, and asking for a
      // different one is refused outright.
      altNames: [spiffeId, serviceName],
      roles,
      logger,
    });

    await writeSecret(stateDir, IDENTITY_FILE, {
      certPem: identity.certPem,
      privateKeyPem: identity.privateKeyPem,
      chainPem: identity.chainPem,
      principal: identity.principal,
      roles: identity.roles,
      notAfter: identity.notAfter,
      renewAfter: identity.renewAfter,
    });
    logger?.warn?.({
      service: serviceName,
      msg: 'enrolled — the enrolment credential is SPENT, remove it from this environment',
    });
  }

  // ---- renewal --------------------------------------------------------------------------------
  //
  // Started here rather than left to the caller. A caller who forgets works perfectly for hours
  // and then stops with a TLS handshake failure that says nothing about expiry.
  identity.startAutoRenewal();
  identity.on('renewed', async (event) => {
    // Persisted on every renewal: without this a restart falls back to the certificate from the
    // last enrolment, which may already have expired -- and then the service enrols again,
    // spending a credential that was meant to be single-use.
    await writeSecret(stateDir, IDENTITY_FILE, {
      certPem: event.certPem || identity.certPem,
      privateKeyPem: event.privateKeyPem || identity.privateKeyPem,
      chainPem: event.chainPem || identity.chainPem,
      principal: identity.principal,
      roles: identity.roles,
      notAfter: event.notAfter || identity.notAfter,
      renewAfter: event.renewAfter || identity.renewAfter,
    }).catch((err) => logger?.warn?.({ error: err.message, msg: 'renewed certificate could not be persisted' }));
    logger?.info?.({ service: serviceName, notAfter: new Date(identity.notAfter).toISOString(), msg: 'certificate renewed' });
  });
  identity.on('renewalFailed', (err) => {
    // Non-destructive: the current certificate keeps working until it actually expires, so a
    // transient CA outage is a warning rather than an outage of this service.
    logger?.warn?.({ error: err.message, msg: 'renewal failed — continuing on the current certificate' });
  });

  // ---- the data plane ---------------------------------------------------------------------------
  const handle = await connectDatabase({ target: discovery.target, identity });

  let db = null;
  if (openDatabase) db = await openServiceDatabase({ handle, stateDir, databaseName, logger });

  return {
    identity,
    handle,
    db,
    spiffeId,
    principal: identity.principal,
    roles: identity.roles,
    target: discovery.target,
    async close() {
      try { identity.stopAutoRenewal?.(); } catch (_) { /* closing */ }
      try { await handle.close?.(); } catch (_) { /* closing */ }
    },
  };
}

/**
 * Where the database is and what authenticates it.
 *
 * Discovered when the processes share a host: the database publishes its address, the IdP
 * publishes the root everything descends from. Explicit values win, for the deployment where
 * they do not share a host and these have to travel some other way.
 */
async function resolveEndpoint({ target, caFingerprint, pairingDir, logger }) {
  if (target && caFingerprint) return { target, fingerprint: caFingerprint, discovered: false };

  const database = await pairing.readDatabase({ dir: pairingDir, logger }).catch(() => null);
  const idp = await pairing.readIdp({ dir: pairingDir, logger }).catch(() => null);

  const resolvedTarget = target || database?.target;
  if (!resolvedTarget) {
    throw new Error(
      'fitdb: no database address. Set FITFAK_DB_TARGET, or run this where the database writes '
      + `its pairing file (${pairing.pairingDir(pairingDir)}).`,
    );
  }
  return {
    target: resolvedTarget,
    fingerprint: caFingerprint || idp?.rootFingerprint || null,
    discovered: !target,
  };
}

/**
 * This service's own database, opened or created.
 *
 * `createDatabase` returns the client secret ONCE and never stores it server-side. Losing it
 * loses the data, so it is written before it is used: a crash between the two would leave a
 * database that can never be opened again.
 */
async function openServiceDatabase({ handle, stateDir, databaseName, logger }) {
  const stored = await readJson(path.join(stateDir, DB_HANDLE_FILE));
  if (stored && stored.dbId && stored.clientSecret) {
    return handle.openDatabase({ dbId: stored.dbId, clientSecret: stored.clientSecret });
  }

  const created = await handle.createDatabase(databaseName);
  await writeSecret(stateDir, DB_HANDLE_FILE, { dbId: created.dbId, clientSecret: created.clientSecret });
  logger?.warn?.({
    dbId: created.dbId,
    msg: 'new database created — its access secret is in the state directory. BACK IT UP; the '
      + 'server does not keep a copy and the data is unreachable without it',
  });
  return handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
}

async function readJson(file) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); } catch (_) { return null; }
}

async function writeSecret(dir, name, payload) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, name);
  const tmp = `${file}.tmp`;
  // 0600, temp-then-rename. Writing in place leaves a half-written file if the process dies
  // mid-write, and the next start finds it "present but corrupt" -- which for the identity file
  // means enrolling again and spending a single-use credential.
  await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
  await fsp.chmod(tmp, 0o600).catch(() => {});
  await fsp.rename(tmp, file);
}

/**
 * True when an error means "the database is sealed", rather than something being wrong.
 *
 * The database refuses everyone until the identity provider has provisioned it, and in this
 * architecture that is a normal startup ordering. An application that treats it as fatal cannot
 * be started before the IdP; one that retries starts in any order.
 */
function isSealedError(err) {
  return /sealed|provisioned|FAILED_PRECONDITION|does not serve any principal/i.test(err?.message || '');
}

/**
 * `joinAsService`, retrying while the database is still sealed.
 *
 * Separate rather than built in, because the two mean different things: an application that
 * should exit when misconfigured wants the plain call, and a long-running service that should
 * survive being started first wants this one.
 */
async function joinAsServiceWhenReady(options = {}, { retryMs = 5000, maxAttempts = 0, logger = null } = {}) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop
      return await joinAsService({ ...options, logger });
    } catch (err) {
      // Only the sealed case is retried. Retrying a wrong secret or a missing anchor would turn
      // a clear failure into a service that never starts and never says why.
      if (!isSealedError(err)) throw err;
      if (maxAttempts && attempt >= maxAttempts) throw err;
      logger?.info?.({
        attempt,
        msg: 'the database is sealed — the identity provider has not provisioned it yet; retrying',
      });
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => { const t = setTimeout(resolve, retryMs); t.unref?.(); });
    }
  }
}

module.exports = { joinAsService, joinAsServiceWhenReady, isSealedError };
