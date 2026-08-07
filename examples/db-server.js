'use strict';

// A production-shaped fitdb server for the fitfak stack: an IdP, an SMTP relay, and whatever
// comes after them, all sharing one database process.
//
//   node examples/db-server.js
//
// The thing that makes this file different from a conventional database server is what it does
// NOT do at startup:
//
//   it does not generate a certificate authority
//   it does not write a private key to disk
//   it does not decide who any principal is
//   it does not serve a single request
//
// It starts SEALED. It has an ephemeral self-signed certificate, generated in memory and never
// written anywhere, and exactly one thing is reachable on it: the control plane the identity
// provider uses to hand over a real server certificate, the matching key, and the trust anchors
// this database will validate every client against.
//
// Only once the IdP has done that AND come back on a mutually authenticated connection does the
// database open to anyone else. Until then every other service -- including one holding a
// perfectly valid certificate -- is refused with FAILED_PRECONDITION.
//
// The reason is not ceremony. Every service in this stack takes its authority from the IdP, so a
// database reachable before the IdP is up is a database answering authorisation questions that
// nobody can yet ask. That gap is exactly where a database grows a second identity system: a
// local user table, a static password, an allow-list maintained by hand. Two sources of truth
// about identity is the thing Zero Trust exists to remove (NIST SP 800-207 §2.1).
//
// What still lives on disk: the enrolment secrets and the data itself. What no longer does: the
// CA key pair, the CA certificate, the server key and the server certificate. Those come from
// the IdP over the control plane on every boot. Losing this container loses nothing that has to
// be recovered from a backup.

const fs = require('node:fs');
const path = require('node:path');

const {
  createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
  createCompositeAttestor, createIdpTokenAttestor, generateEnrolmentSecret,
  createEphemeralBootstrapIdentity, createIdpCaBackend, createLogger, spiffe,
} = require('..');

const log = createLogger('db');

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

const STATE_DIR = process.env.FITFAK_DB_STATE_DIR || path.join(__dirname, '.db-state');
const DATA_DIR = process.env.FITFAK_DB_DATA_DIR || path.join(__dirname, 'fitdb');
const PORT = Number(process.env.FITFAK_DB_PORT || 51572);
const HOST = process.env.FITFAK_DB_HOST || '127.0.0.1';
const TRUST_DOMAIN = process.env.FITFAK_TRUST_DOMAIN || 'fitfak.net';

const list = (value, fallback) => (value || fallback).split(',').map((s) => s.trim()).filter(Boolean);
const SERVER_DNS = list(process.env.FITFAK_DB_DNS, 'localhost, db.fitfak.net');
const SERVER_IPS = list(process.env.FITFAK_DB_IPS, '127.0.0.1');

// The one principal that may reach anything while this database is sealed.
//
// Both halves are checked: the name, which is policy and lives here, and the SPIFFE ID, which is
// a cryptographic claim and lives in the certificate. Requiring both means someone who can edit
// this file still cannot become the IdP, and someone who can mint a certificate still has to be
// named here.
const CONTROL_PRINCIPAL = process.env.FITFAK_DB_CONTROL_PRINCIPAL || 'idp-service';
const CONTROL_SPIFFE_ID = process.env.FITFAK_DB_CONTROL_SPIFFE_ID
  || spiffe.forService(TRUST_DOMAIN, 'idp').uri;

// How long a provisioned-but-uncommitted server identity survives. If the IdP installs a
// certificate and then never completes its mTLS connection, the material is dropped and the
// database re-seals -- because that is either a deployment that failed halfway or a single
// message an attacker got through, and both want the door shut again.
const ADMISSION_HOLD_MS = Number(process.env.FITFAK_DB_ADMISSION_HOLD_MS || 120_000);

// Which services may enrol, what identity each may hold, and what it may do once enrolled.
//
// `maxUses: 1` is right and does not need raising for restarts: a service that already holds a
// certificate reconnects with resume(), and renews over mTLS with reenroll(). The secret is
// needed exactly once, at first provisioning, and can be removed from the service's environment
// afterwards.
//
// The roles here are server-wide (what the principal may ask this server to do at all).
// Authority over a particular database is separate and lives in that database's ACL, so a
// service being 'admin' here does not give it access to another service's data.
const SERVICES = {
  'idp-service': {
    roles: ['admin'],
    maxUses: 1,
    spiffeId: spiffe.forService(TRUST_DOMAIN, 'idp').uri,
    altNames: ['idp-service', 'session.fitfak.net', 'localhost'],
  },
  'smtp-service': {
    roles: ['admin'],
    maxUses: 1,
    spiffeId: spiffe.forService(TRUST_DOMAIN, 'smtp').uri,
    altNames: ['smtp-service', 'mail.fitfak.net', 'localhost'],
  },
};

fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
const statePath = (name) => path.join(STATE_DIR, name);

// ---------------------------------------------------------------------------------------------
// The bootstrap identity: generated in memory, thrown away on provisioning
// ---------------------------------------------------------------------------------------------
//
// This certificate authenticates nobody and is not meant to. The bootstrap exchange is
// authenticated by the pre-shared secret below, confirmed in BOTH directions and bound to the
// TLS exporter (RFC 9266) -- see src/provisioning/control-plane-service.js. The certificate's
// only job is to get a TLS session established so that an exporter value exists to bind to.
//
// Its fingerprint is printed at startup, and the IdP may pin it as defence in depth. It changes
// on every boot, which is the point.

const bootstrapIdentity = createEphemeralBootstrapIdentity({
  ssl: require('@fitfak/ssl'),
  commonName: SERVER_DNS[0] || 'localhost',
  dnsNames: SERVER_DNS,
  ips: SERVER_IPS,
});

// ---------------------------------------------------------------------------------------------
// Secrets: the bootstrap secret and the per-service enrolment secrets
// ---------------------------------------------------------------------------------------------

const SECRETS_FILE = statePath('enrolment-secrets.json');
const LEGACY_IDP_SECRET_FILE = statePath('idp-enrolment-secret');

let savedSecrets = {};
let secretsChanged = false;

if (fs.existsSync(SECRETS_FILE)) {
  try {
    savedSecrets = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8'));
  } catch (err) {
    // Overwriting an unreadable secrets file would silently re-provision every service. Stop
    // and let an operator look at it.
    throw new Error(`[db] ${SECRETS_FILE} exists but could not be parsed (${err.message}). Refusing to overwrite it.`);
  }
}

// Older layout: one bare file holding the IdP's secret.
if (fs.existsSync(LEGACY_IDP_SECRET_FILE) && !savedSecrets['idp-service']) {
  savedSecrets['idp-service'] = fs.readFileSync(LEGACY_IDP_SECRET_FILE, 'utf8').trim();
  secretsChanged = true;
}

// The control-plane secret is separate from every enrolment secret on purpose. It authorises one
// thing -- installing this server's TLS identity -- and an enrolment secret authorises another --
// obtaining a client certificate for one named service. Sharing one value between them would
// mean a service's provisioning credential could re-key the database it connects to.
if (!savedSecrets['__control-plane']) {
  savedSecrets['__control-plane'] = generateEnrolmentSecret().toString('base64');
  secretsChanged = true;
}
const bootstrapSecret = Buffer.from(savedSecrets['__control-plane'], 'base64');

const enrolments = {};
const principals = {};

for (const [serviceName, config] of Object.entries(SERVICES)) {
  if (!savedSecrets[serviceName]) {
    savedSecrets[serviceName] = generateEnrolmentSecret().toString('base64');
    secretsChanged = true;
  }
  enrolments[serviceName] = {
    secret: Buffer.from(savedSecrets[serviceName], 'base64'),
    subject: { CN: serviceName },
    spiffeId: config.spiffeId,
    altNames: config.altNames || [serviceName],
    roles: config.roles,
    maxUses: config.maxUses ?? 1,
  };
  // The allow-list pins each principal's workload identity as well as its name, so a CN
  // collision -- from a second CA, or from a service legitimately renamed -- cannot become an
  // impersonation.
  principals[serviceName] = { roles: config.roles, spiffeId: config.spiffeId };
}

if (secretsChanged) fs.writeFileSync(SECRETS_FILE, JSON.stringify(savedSecrets, null, 2), { mode: 0o600 });

console.log('\n  Client configuration (stable across restarts):\n');
console.log(`    ${'control plane'.padEnd(16)} secret: '${savedSecrets['__control-plane']}',   <- the identity provider only`);
for (const serviceName of Object.keys(SERVICES)) {
  console.log(`    ${serviceName.padEnd(16)} secret: '${savedSecrets[serviceName]}',`);
}
console.log(`\n    bootstrap certificate fingerprint (changes every boot, optional to pin):`);
console.log(`      ${bootstrapIdentity.fingerprint256}`);
console.log('');

// ---------------------------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------------------------

const server = createDatabaseServer({
  baseDir: DATA_DIR,
  principals,
  logger: log,

  // Identity comes from the URI SAN, not the Common Name. RFC 6125 §6.4.4 deprecated
  // CN-as-identity a decade ago, and every workload-identity implementation worth
  // interoperating with -- SPIRE, Istio -- reads the SAN. Keying principals by CN here while
  // certificates carry a SPIFFE ID would mean authorising on the one field nothing validates.
  trustDomain: TRUST_DOMAIN,
  requireSpiffeId: true,

  admission: {
    controlPrincipal: CONTROL_PRINCIPAL,
    controlSpiffeId: CONTROL_SPIFFE_ID,
    bootstrapSecret,
    bootstrapIdentity,
    holdMs: ADMISSION_HOLD_MS,
    serverName: SERVER_DNS[0] || 'localhost',
  },

  enrollment: {
    // This process holds no signing key and cannot sign anything.
    //
    // The IdP is the certificate authority for this deployment; enrolment here is the
    // Registration Authority half -- authenticate the peer, decide what identity it may hold,
    // and ask the real CA to issue it. Configuring a local CA instead would recreate exactly
    // the second identity system this whole design removes.
    //
    // The IdP is expected to independently constrain what this RA may vouch for (a SPIFFE path
    // prefix). `spiffePrefix` here is the client-side half of the same rule: a bug in either
    // end is still caught by the other.
    caBackend: createIdpCaBackend({
      issuanceUrl: process.env.FITFAK_DB_RA_ISSUANCE_URL || 'https://trust.fitfak.net/pki/ra/issue',
      clientId: process.env.FITFAK_DB_RA_CLIENT_ID || 'fitdb-registration-authority',
      clientSecret: process.env.FITFAK_DB_RA_CLIENT_SECRET || '',
      spiffePrefix: `spiffe://${TRUST_DOMAIN}/service`,
      // The anchors were installed with the server identity over the control plane, so there is
      // nothing to fetch. Late-bound because they do not exist until the IdP has provisioned
      // this process -- and until then no enrolment can succeed anyway.
      trustAnchorsProvider: () => server.clientTrustAnchors || [],
      logger: log,
    }),
    serverName: SERVER_DNS[0] || 'localhost',
    attestor: createCompositeAttestor([
      // First issuance, for a service that has an out-of-band secret and nothing else.
      createSharedSecretAttestor({ enrolments }),

      // Once the IdP is up, everything after it enrols against a token the IdP issued rather
      // than a secret pasted into its config. Only wired when the credentials are present, so
      // the server still starts before the IdP exists.
      ...(process.env.DB_OAUTH_CLIENT_ID && process.env.DB_OAUTH_CLIENT_SECRET ? [
        createIdpTokenAttestor({
          introspectionUrl: 'https://session.fitfak.net/oauth/introspect',
          clientId: process.env.DB_OAUTH_CLIENT_ID,
          clientSecret: process.env.DB_OAUTH_CLIENT_SECRET,
          services: {
            'dns-resolver': {
              requiredScope: 'service:enrol',
              subject: { CN: 'dns-resolver' },
              spiffeId: spiffe.forService(TRUST_DOMAIN, 'dns-resolver').uri,
              roles: ['reader'],
            },
          },
        }),
      ] : []),
    ]),
    // Renewal is authenticated by the certificate being renewed, never by the request, so it
    // belongs on its own attestor rather than in the list above -- Reenroll requires mTLS and
    // Enroll must not accept it.
    renewalAttestor: createRenewalAttestor({
      trustDomain: TRUST_DOMAIN,
      roleResolver: (certificate) => SERVICES[certificate.subject?.CN]?.roles || [],
    }),
  },
});

// The lines an operator actually needs when nothing can connect.
server.on('admissionOpened', (event) => log.info({
  principal: event.principal,
  msg: 'identity provider connected — the database is now open to every authorised principal',
}));
server.on('admissionSealed', (event) => log.warn({
  reason: event.reason,
  msg: 'the database is sealed and is refusing every principal until the identity provider provisions it again',
}));

// A failed client handshake -- a service with an expired certificate, a probe from elsewhere on
// the network -- must be a log line, not a dead server. These are the lines to read first when a
// client reports that it cannot connect.
server.app.on('clientError', (err) => log.warn({ error: err.message, msg: 'TLS client error' }));
server.app.on('sessionError', (err) => log.warn({ error: err.message, msg: 'HTTP/2 session error' }));
server.app.on('error', (err) => log.error({ error: err.message, stack: err.stack, msg: 'server error' }));

server.listen(PORT, {
  host: HOST,
  tls: {
    key: bootstrapIdentity.key,
    cert: bootstrapIdentity.cert,
    ca: bootstrapIdentity.ca,
    // One port serves all three channels. A peer with no certificate reaches exactly the methods
    // that declare minSecurityLevel 'tls' -- the control plane, GetTrustAnchors and Enroll -- and
    // nothing else; the transport refuses everything on the data plane before a handler runs.
    // `rejectUnauthorized` must stay false for that to be possible: with it true the handshake
    // fails first and a service that has never enrolled has no way in at all.
    requestCert: true,
    rejectUnauthorized: false,
    // TLS 1.3 only. The channel binding both the control plane and the enrolment proof depend on
    // is the RFC 9266 tls-exporter, and the replay protection it provides is only as good as the
    // exporter -- so a downgrade to 1.2 would silently weaken the one mechanism that stops a
    // TLS-terminating proxy from replaying either proof.
    minVersion: 'TLSv1.3',
  },
});

log.warn({
  state: 'sealed',
  controlPrincipal: CONTROL_PRINCIPAL,
  msg: 'this database serves nobody until the identity provider provisions it. '
    + 'Start the IdP with FITFAK_IDP_DB_CONTROL_SECRET set to the control-plane secret above.',
});
log.info({ dataDir: DATA_DIR, stateDir: STATE_DIR, msg: 'state directories' });

// Flush every open database's index snapshot before exiting. Without this the next start replays
// segments from the last snapshot instead of resuming from a clean one -- correct either way,
// but proportionally slower the more has been written since.
let shuttingDown = false;
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info({ signal, msg: 'shutting down' });
    try { await server.close({ graceMs: 5000 }); }
    catch (err) { log.error({ error: err.message, msg: 'close failed' }); }
    process.exit(0);
  });
}

// An unhandled rejection defaults to killing the process in current Node. For a database that
// several services depend on, taking the whole thing down over one bad request is worse than
// logging it and staying up.
process.on('unhandledRejection', (reason) => log.error({
  error: reason instanceof Error ? reason.message : String(reason),
  stack: reason instanceof Error ? reason.stack : undefined,
  msg: 'unhandled rejection',
}));
