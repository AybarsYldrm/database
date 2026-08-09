'use strict';

// The fitdb server for the fitfak stack: one database process serving several services, with an
// operator panel beside it.
//
//   node examples/db-server.js
//
// Two things make this different from a conventional database server.
//
// FIRST: it starts SEALED. It has no certificate authority, no server certificate anyone would
// trust, no principals, and it serves nobody. It wears an ephemeral self-signed certificate
// generated at boot and never written anywhere, and the only thing reachable on it is the
// control plane the identity provider uses to hand over the certificate it will actually serve.
//
// The reason is not ceremony. Every service here takes its authority from the IdP, so a database
// reachable before the IdP is up is a database answering authorisation questions nobody can yet
// ask — and that gap is where a database grows a second identity system: a local user table, a
// static password, an allow-list edited by hand. Two sources of truth about identity is the
// thing Zero Trust exists to remove (NIST SP 800-207 §2.1).
//
// SECOND: the list of services is not in this file. It lives in a registry the admin panel
// writes to, so registering a new application is something an operator does rather than an
// edit-and-restart. That matters more than it sounds: when adding a service means restarting the
// database, operators stop adding services one at a time and start raising `maxUses` on an
// existing credential instead — turning a single-shot bootstrap secret into a standing key.
//
//
// WHAT LIVES ON DISK
//
//   services.json          the service registry and their enrolment secrets   0600
//   admin-token            the panel's bearer token, regenerated each boot     0600
//   fitdb/                 the data itself
//
// What no longer does: the CA key pair, the CA certificate, the server key and the server
// certificate. Those come from the IdP over the control plane on every boot. Losing this
// container loses nothing that has to be restored from a backup.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
  createCompositeAttestor, createIdpTokenAttestor, createIdpCaBackend,
  createEphemeralBootstrapIdentity, createLogger, spiffe,
  ServiceRegistry, createServiceMetrics, createAdminServer,
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

// The admin panel. Same shape as the IdP's admin host: one logical service per loopback address,
// port 80, fronted by whatever terminates TLS at the edge.
//
// The bind address is the primary control — 127.0.2.1 is reachable only from this host, so "who
// can use the panel" reduces to "who can run code on this machine", and anyone who can do that
// can already read this process's memory. There is a token as well, because a local process is
// not necessarily a trusted one and a browser on this host can be steered at a loopback URL.
const ADMIN_HOST = process.env.FITFAK_DB_ADMIN_HOST || '127.0.2.1';
const ADMIN_PORT = Number(process.env.FITFAK_DB_ADMIN_PORT || 80);
const ADMIN_ENABLED = process.env.FITFAK_DB_ADMIN !== '0';

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
// database re-seals — because that is either a deployment that failed halfway or a single
// message an attacker got through, and both want the door shut again.
const ADMISSION_HOLD_MS = Number(process.env.FITFAK_DB_ADMISSION_HOLD_MS || 120_000);

fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
const statePath = (name) => path.join(STATE_DIR, name);

// ---------------------------------------------------------------------------------------------

async function main() {
  // ---- the throwaway identity this process wears until the IdP provisions it ----------------
  //
  // This certificate authenticates nobody and is not meant to. The bootstrap exchange is
  // authenticated by the pre-shared control secret, confirmed in BOTH directions and bound to
  // the TLS exporter (RFC 9266). The certificate's only job is to get a TLS session established
  // so that an exporter value exists to bind to. Its fingerprint changes every boot, which is
  // the point.
  const bootstrapIdentity = createEphemeralBootstrapIdentity({
    ssl: require('@fitfak/ssl'),
    commonName: SERVER_DNS[0] || 'localhost',
    dnsNames: SERVER_DNS,
    ips: SERVER_IPS,
  });

  // ---- secrets ------------------------------------------------------------------------------
  //
  // The control-plane secret is separate from every enrolment secret on purpose. It authorises
  // one thing — installing this server's TLS identity — and an enrolment secret authorises
  // another — obtaining a client certificate for one named service. Sharing one value between
  // them would mean a service's provisioning credential could re-key the database it connects to.
  const controlSecret = loadOrCreateSecret('control-plane-secret');

  // ---- the service registry the panel writes to ---------------------------------------------
  const registry = await ServiceRegistry.open({ stateDir: STATE_DIR, trustDomain: TRUST_DOMAIN });

  // First boot: seed the two services this stack cannot start without. Everything after them is
  // registered from the panel.
  if (registry.list().length === 0) {
    for (const seed of [
      { name: 'idp-service', roles: ['admin'], kind: 'service', description: 'Kimlik sağlayıcı', altNames: ['session.fitfak.net'] },
      { name: 'smtp-service', roles: ['admin'], kind: 'service', description: 'E-posta aktarıcı', altNames: ['mail.fitfak.net'] },
    ]) {
      const { secret } = await registry.create(seed);
      log.warn({ service: seed.name, secret, msg: 'seeded service — this secret is printed once' });
    }
  }

  const metrics = createServiceMetrics({ baseDir: DATA_DIR });

  // ---- the server ---------------------------------------------------------------------------
  const server = createDatabaseServer({
    baseDir: DATA_DIR,
    logger: log,

    // The allow-list comes from the registry, so a service registered in the panel is
    // recognised on its next connection. Read through a resolver rather than snapshotted,
    // because a snapshot taken here would be the state at boot forever.
    principalResolver: buildPrincipalResolver(registry),

    admission: {
      controlPrincipal: CONTROL_PRINCIPAL,
      controlSpiffeId: CONTROL_SPIFFE_ID,
      bootstrapSecret: controlSecret,
      bootstrapIdentity,
      holdMs: ADMISSION_HOLD_MS,
      serverName: SERVER_DNS[0] || 'localhost',
    },

    enrollment: {
      // This process holds no signing key and cannot sign anything.
      //
      // The IdP is the certificate authority; enrolment here is the Registration Authority half
      // — authenticate the peer, decide what identity it may hold, ask the real CA to issue it.
      // Configuring a local CA instead would recreate exactly the second identity system this
      // design removes.
      caBackend: createIdpCaBackend({
        issuanceUrl: process.env.FITFAK_DB_RA_ISSUANCE_URL || 'https://trust.fitfak.net/pki/ra/issue',
        clientId: process.env.FITFAK_DB_RA_CLIENT_ID || 'fitdb-registration-authority',
        clientSecret: process.env.FITFAK_DB_RA_CLIENT_SECRET || '',
        // The IdP independently constrains what this RA may vouch for. This is the client-side
        // half of the same rule, so a bug in either end is still caught by the other.
        spiffePrefix: `spiffe://${TRUST_DOMAIN}/service`,
        // The anchors arrived with the server identity over the control plane, so there is
        // nothing to fetch. Late-bound because they do not exist until the IdP has provisioned
        // this process — and until then no enrolment can succeed anyway.
        trustAnchorsProvider: () => server.clientTrustAnchors || [],
        logger: log,
      }),
      serverName: SERVER_DNS[0] || 'localhost',

      attestor: createCompositeAttestor([
        // First issuance, for a service that has an out-of-band secret and nothing else.
        // `registry.enrolments` is a LIVE Map: a service registered in the panel is enrollable
        // immediately, with nothing restarted.
        createSharedSecretAttestor({
          enrolments: registry.enrolments,
          onConsumed: ({ serviceName }) => {
            registry.recordUse(serviceName).catch((err) => log.warn({
              service: serviceName, error: err.message, msg: 'could not record credential use',
            }));
          },
        }),

        // Once the IdP is up, everything after it enrols against a token the IdP issued rather
        // than a secret pasted into its config. Only wired when the credentials are present, so
        // the server still starts before the IdP exists.
        ...(process.env.DB_OAUTH_CLIENT_ID && process.env.DB_OAUTH_CLIENT_SECRET ? [
          createIdpTokenAttestor({
            introspectionUrl: 'https://session.fitfak.net/oauth/introspect',
            clientId: process.env.DB_OAUTH_CLIENT_ID,
            clientSecret: process.env.DB_OAUTH_CLIENT_SECRET,
            services: tokenAttestorServices(registry),
            logger: log,
          }),
        ] : []),
      ]),

      // Renewal is authenticated by the certificate being renewed, never by the request, so it
      // belongs on its own attestor — Reenroll requires mTLS and Enroll must not accept it.
      renewalAttestor: createRenewalAttestor({
        trustDomain: TRUST_DOMAIN,
        roleResolver: (certificate) => registry.get(certificate.subject?.CN)?.roles || [],
      }),
    },
  });

  // ---- events an operator actually needs -----------------------------------------------------
  server.on('admissionOpened', (event) => log.info({
    principal: event.principal,
    msg: 'identity provider connected — the database is now open to every authorised principal',
  }));
  server.on('admissionSealed', (event) => log.warn({
    reason: event.reason,
    msg: 'the database is sealed and is refusing every principal until the identity provider provisions it again',
  }));
  server.on('enrolled', (event) => log.info({ principal: event.principal, method: event.method, msg: 'enrolled' }));

  // A failed client handshake — a service with an expired certificate, a probe from elsewhere on
  // the network — must be a log line, not a dead server. These are the lines to read first when
  // a client reports that it cannot connect.
  server.app.on('clientError', (err) => log.warn({ error: err.message, msg: 'TLS client error' }));
  server.app.on('sessionError', (err) => log.warn({ error: err.message, msg: 'HTTP/2 session error' }));
  server.app.on('error', (err) => log.error({ error: err.message, stack: err.stack, msg: 'server error' }));

  server.listen(PORT, {
    host: HOST,
    tls: {
      key: bootstrapIdentity.key,
      cert: bootstrapIdentity.cert,
      ca: bootstrapIdentity.ca,
      // One port serves all three channels. A peer with no certificate reaches exactly the
      // methods that declare minSecurityLevel 'tls' — the control plane, GetTrustAnchors and
      // Enroll — and nothing else; the transport refuses everything on the data plane before a
      // handler runs. `rejectUnauthorized` must stay false for that to be possible: with it true
      // the handshake fails first and a service that has never enrolled has no way in at all.
      requestCert: true,
      rejectUnauthorized: false,
      // TLS 1.3 only. The channel binding both the control plane and the enrolment proof depend
      // on is the RFC 9266 tls-exporter, and a downgrade to 1.2 would silently weaken the one
      // mechanism that stops a TLS-terminating proxy from replaying either proof.
      minVersion: 'TLSv1.3',
    },
  });

  // Attached after listen(), because the HTTP/2 server does not exist before it.
  metrics.attach(server.app.server.server);

  // ---- the admin panel ------------------------------------------------------------------------
  let admin = null;
  if (ADMIN_ENABLED) {
    admin = createAdminServer({
      server,
      metrics,
      registry,
      host: ADMIN_HOST,
      port: ADMIN_PORT,
      // Regenerated every boot. A token that survives a restart is a token that ends up in a
      // shell history and a chat message, and this one costs nothing to reissue.
      token: crypto.randomBytes(24).toString('base64url'),
      logger: log,
      info: {
        trustDomain: TRUST_DOMAIN,
        dataDir: DATA_DIR,
        stateDir: STATE_DIR,
        controlPrincipal: CONTROL_PRINCIPAL,
      },
    }).listen();

    // Written as well as printed: the log scrolls, and an operator coming back an hour later
    // should not have to restart the database to get back in.
    fs.writeFileSync(statePath('admin-token'), admin.token, { mode: 0o600 });
  }

  // ---- what an operator needs to see at startup ------------------------------------------------
  console.log('');
  console.log(`  fitdb   ${HOST}:${PORT}   SEALED`);
  console.log('');
  console.log('  This database serves nobody until the identity provider provisions it.');
  console.log('  Start the IdP with:');
  console.log('');
  console.log(`    FITFAK_IDP_DB_CONTROL_SECRET='${controlSecret.toString('base64')}'`);
  console.log(`    FITFAK_IDP_DB_TARGET='https://${SERVER_DNS[0] || HOST}:${PORT}'`);
  console.log('');
  console.log(`  bootstrap certificate fingerprint (changes every boot, optional to pin):`);
  console.log(`    ${bootstrapIdentity.fingerprint256}`);
  if (admin) {
    console.log('');
    console.log('  Admin panel:');
    console.log(`    ${admin.url()}`);
    console.log(`    (token also in ${statePath('admin-token')})`);
  }
  console.log('');

  // ---- shutdown --------------------------------------------------------------------------------
  //
  // Flush every open database's index snapshot before exiting. Without this the next start
  // replays segments from the last snapshot instead of resuming from a clean one — correct
  // either way, but proportionally slower the more has been written since.
  let shuttingDown = false;
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      if (shuttingDown) return;
      shuttingDown = true;
      log.info({ signal, msg: 'shutting down' });
      metrics.close();
      try { if (admin) await admin.close(); } catch (err) { log.error({ error: err.message, msg: 'admin close failed' }); }
      try { await server.close({ graceMs: 5000 }); } catch (err) { log.error({ error: err.message, msg: 'close failed' }); }
      process.exit(0);
    });
  }
}

// ---------------------------------------------------------------------------------------------

/**
 * A principal resolver that reads the allow-list from the registry on every request.
 *
 * `createPrincipalResolver` copies its `principals` option into a Map at construction, which is
 * right for a static list and wrong here: a service registered in the panel would not be
 * recognised until a restart, and removing one would not lock it out until a restart either.
 * Rebuilding per request costs an object allocation against a network round trip.
 */
function buildPrincipalResolver(registry) {
  const { createPrincipalResolver } = require('../src/grpc/identity');
  return (peer) => createPrincipalResolver({
    principals: registry.principals(),
    subjectField: 'CN',
    trustDomain: process.env.FITFAK_TRUST_DOMAIN || 'fitfak.net',
    // Identity comes from the URI SAN, not the Common Name. RFC 6125 §6.4.4 deprecated
    // CN-as-identity a decade ago, and every workload-identity implementation worth
    // interoperating with — SPIRE, Istio — reads the SAN.
    requireSpiffeId: true,
  })(peer);
}

/**
 * The IdP-token attestor's service map, built from the registry.
 *
 * Every registered service is eligible, but the token still has to carry the scope: an access
 * token proves the caller holds a grant, and this table decides what that grant may become. If
 * the token chose, anyone able to mint one with an arbitrary `sub` could name themselves any
 * principal in the system.
 */
function tokenAttestorServices(registry) {
  const services = {};
  for (const service of registry.list()) {
    if (!service.enabled) continue;
    services[service.name] = {
      requiredScope: 'service:enrol',
      subject: { CN: service.name },
      spiffeId: service.spiffeId,
      altNames: service.altNames,
      roles: service.roles,
    };
  }
  return services;
}

/**
 * Reads a 32-byte secret, or creates one.
 *
 * Kept out of the registry file on purpose: this one is not a service credential and must not be
 * listed, rotated or removed alongside them.
 */
function loadOrCreateSecret(name) {
  const file = statePath(name);
  if (fs.existsSync(file)) {
    const secret = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
    if (secret.length >= 32) return secret;
    throw new Error(`[db] ${file} exists but is shorter than 32 bytes. Refusing to use it; delete it to regenerate.`);
  }
  const secret = crypto.randomBytes(32);
  fs.writeFileSync(file, secret.toString('base64'), { mode: 0o600 });
  return secret;
}

// An unhandled rejection defaults to killing the process in current Node. For a database that
// several services depend on, taking the whole thing down over one bad request is worse than
// logging it and staying up.
process.on('unhandledRejection', (reason) => log.error({
  error: reason instanceof Error ? reason.message : String(reason),
  stack: reason instanceof Error ? reason.stack : undefined,
  msg: 'unhandled rejection',
}));

main().catch((err) => { console.error('\n[db] FAILED TO START:', err.message, '\n', err.stack); process.exit(1); });
