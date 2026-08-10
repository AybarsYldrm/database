#!/usr/bin/env node
'use strict';

// The fitdb server.
//
//   npx fitdb-server            (or)   node bin/db-server.js
//
// This is the program, not an example of one. There is no application code in this file and there
// is nowhere to put any: no service names, no schemas, no seeded principals. Everything this
// database serves is registered at runtime — from the admin panel, or by the identity provider —
// and lives in state, not in source.
//
// That is a deliberate constraint rather than tidiness. A server file that lists its services is a
// server that must be edited and restarted to gain one, and operators who have to restart a
// database to add a service stop adding services one at a time. They raise `maxUses` on an
// existing credential instead, and a single-shot bootstrap secret quietly becomes a standing key.
//
//
// TWO THINGS MAKE THIS DIFFERENT FROM A CONVENTIONAL DATABASE SERVER
//
// FIRST: it starts SEALED. It has no certificate authority, no server certificate anyone would
// trust, no principals, and it serves nobody. It wears an ephemeral self-signed certificate
// generated at boot and never written anywhere, and the only thing reachable on it is the control
// plane the identity provider uses to hand over the certificate it will actually serve.
//
// The reason is not ceremony. Every service here takes its authority from the IdP, so a database
// reachable before the IdP is up is a database answering authorisation questions nobody can yet
// ask — and that gap is where a database grows a second identity system: a local user table, a
// static password, an allow-list edited by hand. Two sources of truth about identity is the thing
// Zero Trust exists to remove (NIST SP 800-207 §2.1).
//
// SECOND: it configures itself. Connecting these two processes used to mean copying a control
// secret out of this process's stdout, inventing a registration-authority client id and secret, and
// entering five values on both sides — each one producing an unreadable TLS error when mistyped.
// Now both processes read and write one directory (src/pairing.js) and find each other.
//
//
// START ORDER DOES NOT MATTER
//
// Logically the IdP comes first: it is the certificate authority and this database cannot open
// without it. But neither process requires the other to be running when it starts. This one boots
// sealed and waits; the IdP boots, buffers its writes, and connects in the background. Whichever
// starts first waits for the other, and the system converges without anyone sequencing it.
//
//
// WHAT LIVES ON DISK
//
//   <state>/services.json          the service registry and their enrolment secrets     0600
//   <state>/control-plane-secret   the secret the IdP proves itself with                0600
//   <state>/admin-token            the panel's break-glass token, regenerated each boot 0600
//   <data>/                        the data itself
//
// What does not: the CA key pair, the CA certificate, the server key, the server certificate.
// Those come from the IdP over the control plane on every boot. Losing this container loses
// nothing that has to be restored from a backup.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
  createCompositeAttestor, createIdpCaBackend, createEphemeralBootstrapIdentity,
  createLogger, spiffe, pairing, assertSslCompatible,
  ServiceRegistry, createServiceMetrics, createAdminServer, createIdpAuth,
} = require('..');

const log = createLogger('db');

// ---------------------------------------------------------------------------------------------
// Configuration
//
// Every one of these has a working default. The only value an operator normally sets is
// FITFAK_PAIRING_DIR, and only when the two processes run as different users.
// ---------------------------------------------------------------------------------------------

const STATE_DIR = process.env.FITFAK_DB_STATE_DIR || path.join(process.cwd(), '.db-state');
const DATA_DIR = process.env.FITFAK_DB_DATA_DIR || path.join(process.cwd(), 'fitdb');
const PORT = Number(process.env.FITFAK_DB_PORT || 51572);
const HOST = process.env.FITFAK_DB_HOST || '127.0.0.1';
const TRUST_DOMAIN = process.env.FITFAK_TRUST_DOMAIN || 'fitfak.net';
const PAIRING_DIR = process.env.FITFAK_PAIRING_DIR || null;

// The admin panel. Same shape as the IdP's admin host: one logical service per loopback address,
// port 80. The bind address is the primary control — 127.0.2.1 is reachable only from this host,
// so "who can use the panel" reduces to "who can run code on this machine", and anyone who can do
// that can already read this process's memory.
const ADMIN_HOST = process.env.FITFAK_DB_ADMIN_HOST || '127.0.2.1';
const ADMIN_PORT = Number(process.env.FITFAK_DB_ADMIN_PORT || 80);
const ADMIN_ENABLED = process.env.FITFAK_DB_ADMIN !== '0';

const list = (value, fallback) => (value || fallback).split(',').map((s) => s.trim()).filter(Boolean);
const SERVER_DNS = list(process.env.FITFAK_DB_DNS, 'localhost, db.fitfak.net');
const SERVER_IPS = list(process.env.FITFAK_DB_IPS, '127.0.0.1');

// The one principal that may reach anything while this database is sealed.
//
// Both halves are checked: the name, which is policy and lives here, and the SPIFFE ID, which is a
// cryptographic claim and lives in the certificate. Requiring both means someone who can edit this
// file still cannot become the IdP, and someone who can mint a certificate still has to be named
// here.
const CONTROL_PRINCIPAL = process.env.FITFAK_DB_CONTROL_PRINCIPAL || 'idp-service';
const CONTROL_SPIFFE_ID = process.env.FITFAK_DB_CONTROL_SPIFFE_ID
  || spiffe.forService(TRUST_DOMAIN, 'idp').uri;

// How long a provisioned-but-uncommitted server identity survives. If the IdP installs a
// certificate and then never completes its mTLS connection, the material is dropped and the
// database re-seals — because that is either a deployment that failed halfway or a single message
// an attacker got through, and both want the door shut again.
const ADMISSION_HOLD_MS = Number(process.env.FITFAK_DB_ADMISSION_HOLD_MS || 120_000);

fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
const statePath = (name) => path.join(STATE_DIR, name);

// ---------------------------------------------------------------------------------------------

async function main() {
  // ---- the signing library, before anything is signed with it --------------------------------
  //
  // An old @fitfak/ssl produces certificates whose public key does not belong to the CSR's
  // private key. The certificate looks valid, its chain verifies, and it fails only in a TLS
  // handshake -- a network hop away from the code that made it, hours later, in another service.
  // Checking here turns that diagnosis into one startup message.
  const sslCheck = assertSslCompatible();
  log.info({ version: sslCheck.version, msg: '@fitfak/ssl verified' });

  // ---- the throwaway identity this process wears until the IdP provisions it ------------------
  //
  // This certificate authenticates nobody and is not meant to. The bootstrap exchange is
  // authenticated by the pre-shared control secret, confirmed in BOTH directions and bound to the
  // TLS exporter (RFC 9266). The certificate's only job is to get a TLS session established so an
  // exporter value exists to bind to. Its fingerprint changes every boot, which is the point.
  const bootstrapIdentity = createEphemeralBootstrapIdentity({
    ssl: require('@fitfak/ssl'),
    commonName: SERVER_DNS[0] || 'localhost',
    dnsNames: SERVER_DNS,
    ips: SERVER_IPS,
  });

  // ---- secrets ---------------------------------------------------------------------------------
  //
  // The control-plane secret is separate from every enrolment secret on purpose. It authorises one
  // thing — installing this server's TLS identity — and an enrolment secret authorises another —
  // obtaining a client certificate for one named service. Sharing one value between them would mean
  // a service's provisioning credential could re-key the database it connects to.
  const controlSecret = loadOrCreateSecret('control-plane-secret');

  // ---- the registry the panel writes to --------------------------------------------------------
  //
  // Opened empty on a first boot and left that way. Nothing is seeded here: the IdP is not a
  // registered service — it is admitted by the admission gate, which is a different mechanism for a
  // different reason — and every other service is something an operator adds from the panel.
  const registry = await ServiceRegistry.open({ stateDir: STATE_DIR, trustDomain: TRUST_DOMAIN });
  const metrics = createServiceMetrics({ baseDir: DATA_DIR });

  // ---- the server ------------------------------------------------------------------------------
  const server = createDatabaseServer({
    baseDir: DATA_DIR,
    logger: log,

    // The allow-list comes from the registry, so a service registered in the panel is recognised on
    // its next connection. Read through a resolver rather than snapshotted, because a snapshot
    // taken here would be the state at boot forever.
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
      // The IdP is the certificate authority; enrolment here is the Registration Authority half —
      // authenticate the peer, decide what identity it may hold, ask the real CA to issue it.
      // Configuring a local CA instead would recreate exactly the second identity system this
      // design removes.
      caBackend: createIdpCaBackend({
        // Late-bound, because these values do not exist until the IdP has provisioned this process
        // — and until then no enrolment can succeed anyway, so there is nothing to be late for.
        credentialsProvider: async () => {
          const idp = await pairing.readIdp({ dir: PAIRING_DIR, logger: log });
          if (!idp) return null;
          return {
            issuanceUrl: process.env.FITFAK_DB_RA_ISSUANCE_URL || idp.issuanceUrl,
            anchorsUrl: process.env.FITFAK_DB_RA_ANCHORS_URL || idp.anchorsUrl,
            clientId: process.env.FITFAK_DB_RA_CLIENT_ID || idp.raClientId,
            clientSecret: process.env.FITFAK_DB_RA_CLIENT_SECRET || idp.raClientSecret,
          };
        },
        // The IdP independently constrains what this RA may vouch for. This is the client-side half
        // of the same rule, so a bug in either end is still caught by the other.
        spiffePrefix: `spiffe://${TRUST_DOMAIN}/service`,
        // The anchors arrived with the server identity over the control plane, so there is nothing
        // to fetch.
        trustAnchorsProvider: () => server.clientTrustAnchors || [],
        logger: log,
      }),
      serverName: SERVER_DNS[0] || 'localhost',

      // First issuance, for a service that has an out-of-band secret and nothing else.
      // `registry.enrolments` is a LIVE Map: a service registered in the panel is enrollable
      // immediately, with nothing restarted.
      attestor: createCompositeAttestor([
        createSharedSecretAttestor({
          enrolments: registry.enrolments,
          onConsumed: ({ serviceName }) => {
            registry.recordUse(serviceName).catch((err) => log.warn({
              service: serviceName, error: err.message, msg: 'could not record credential use',
            }));
          },
        }),
      ]),

      // Renewal is authenticated by the certificate being renewed, never by the request, so it
      // belongs on its own attestor — Reenroll requires mTLS and Enroll must not accept it.
      renewalAttestor: createRenewalAttestor({
        trustDomain: TRUST_DOMAIN,
        roleResolver: (certificate) => registry.get(certificate.subject?.CN)?.roles || [],
      }),
    },
  });

  // ---- events an operator actually needs --------------------------------------------------------
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
  // the network — must be a log line, not a dead server. These are the lines to read first when a
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
      // that declare minSecurityLevel 'tls' — the control plane, GetTrustAnchors and Enroll — and
      // nothing else; the transport refuses everything on the data plane before a handler runs.
      // `rejectUnauthorized` must stay false for that to be possible: with it true the handshake
      // fails first and a service that has never enrolled has no way in at all.
      requestCert: true,
      rejectUnauthorized: false,
      // TLS 1.3 only. The channel binding both the control plane and the enrolment proof depend on
      // is the RFC 9266 tls-exporter, and a downgrade to 1.2 would silently weaken the one
      // mechanism that stops a TLS-terminating proxy from replaying either proof.
      minVersion: 'TLSv1.3',
    },
  });

  // Attached after listen(), because the HTTP/2 server does not exist before it.
  metrics.attach(server.app.server.server);

  // ---- tell the identity provider where to find us -----------------------------------------------
  //
  // Written AFTER listen(), so the address in the file is one that answers. Publishing it earlier
  // would advertise a port that is not open yet and send the IdP into a retry loop on its very
  // first attempt.
  const target = `https://${SERVER_DNS[0] || HOST}:${PORT}`;
  const pairingFile = await pairing.publishDatabase({
    dir: PAIRING_DIR,
    target,
    controlSecret,
    bootstrapFingerprint: bootstrapIdentity.fingerprint256,
    trustDomain: TRUST_DOMAIN,
    logger: log,
  });

  // ---- the admin panel ---------------------------------------------------------------------------
  let admin = null;
  if (ADMIN_ENABLED) {
    admin = createAdminServer({
      server,
      metrics,
      registry,
      host: ADMIN_HOST,
      port: ADMIN_PORT,
      // Regenerated every boot. A token that survives a restart is a token that ends up in a shell
      // history and a chat message, and this one costs nothing to reissue. It is the break-glass
      // path; the everyday one is the identity provider, installed below when it appears.
      token: crypto.randomBytes(24).toString('base64url'),
      logger: log,
      info: {
        trustDomain: TRUST_DOMAIN,
        dataDir: DATA_DIR,
        stateDir: STATE_DIR,
        controlPrincipal: CONTROL_PRINCIPAL,
        target,
      },
    }).listen();

    // Written as well as printed: the log scrolls, and an operator coming back an hour later should
    // not have to restart the database to get back in.
    fs.writeFileSync(statePath('admin-token'), admin.token, { mode: 0o600 });

    watchForIdpSignIn(admin);
  }

  banner({ target, controlSecret, bootstrapIdentity, admin, pairingFile });

  // ---- shutdown ------------------------------------------------------------------------------------
  //
  // Flush every open database's index snapshot before exiting. Without this the next start replays
  // segments from the last snapshot instead of resuming from a clean one — correct either way, but
  // proportionally slower the more has been written since.
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
 * Installs identity-provider sign-in on the panel as soon as the IdP publishes its half.
 *
 * Polled rather than watched. `fs.watch` on a directory that may not exist yet, across a rename
 * from a temp file, behaves differently on every platform — and the thing being waited for happens
 * once, at a human timescale, so a check every few seconds costs nothing measurable.
 *
 * Until this lands the panel is token-only, which is correct: before the IdP exists there is no
 * one to ask who an administrator is.
 */
function watchForIdpSignIn(admin) {
  const attempt = async () => {
    if (admin.idpAuth) return true;
    const idp = await pairing.readIdp({ dir: PAIRING_DIR, logger: log }).catch(() => null);
    if (!idp || !idp.panelClientId || !idp.panelClientSecret || !idp.issuer) return false;
    try {
      admin.idpAuth = createIdpAuth({
        issuer: idp.issuer,
        clientId: idp.panelClientId,
        clientSecret: idp.panelClientSecret,
        redirectUri: `${admin.origin}/auth/callback`,
        // The IdP issues its own TLS certificate from the root this database already trusts, and
        // that root is not in any system store. Passing it explicitly is the difference between
        // sign-in working and an UNABLE_TO_VERIFY_LEAF_SIGNATURE nobody can place.
        caPem: idp.rootCertPem || null,
        logger: log,
      });
      log.info({ issuer: idp.issuer, msg: 'admin panel sign-in is now handled by the identity provider' });
      return true;
    } catch (err) {
      log.warn({ error: err.message, msg: 'could not enable identity-provider sign-in for the panel' });
      return false;
    }
  };

  attempt().then((done) => {
    if (done) return;
    const timer = setInterval(() => {
      attempt().then((ok) => { if (ok) clearInterval(timer); }).catch(() => {});
    }, 5000);
    timer.unref?.();
  }).catch(() => {});
}

/**
 * A principal resolver that reads the allow-list from the registry on every request.
 *
 * `createPrincipalResolver` copies its `principals` option into a Map at construction, which is
 * right for a static list and wrong here: a service registered in the panel would not be recognised
 * until a restart, and removing one would not lock it out until a restart either. Rebuilding per
 * request costs an object allocation against a network round trip.
 */
function buildPrincipalResolver(registry) {
  const { createPrincipalResolver } = require('../src/grpc/identity');
  return (peer) => createPrincipalResolver({
    principals: registry.principals(),
    subjectField: 'CN',
    trustDomain: TRUST_DOMAIN,
    // Identity comes from the URI SAN, not the Common Name. RFC 6125 §6.4.4 deprecated
    // CN-as-identity a decade ago, and every workload-identity implementation worth interoperating
    // with — SPIRE, Istio — reads the SAN.
    requireSpiffeId: true,
  })(peer);
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

/**
 * What an operator needs on the screen at startup.
 *
 * Printed with console.log rather than through the logger, deliberately. These lines are a
 * one-time notice for a person, not events: routing them through a structured logger would put
 * them in a log aggregator, where the admin URL and its token do not belong.
 *
 * The control secret is NOT printed. It used to be, because it had to be copied by hand; now it is
 * in the pairing file and printing it would only add a copy to a scrollback buffer.
 */
function banner({ target, bootstrapIdentity, admin, pairingFile }) {
  console.log('');
  console.log(`  fitdb   ${HOST}:${PORT}   SEALED`);
  console.log('');
  console.log('  This database serves nobody until the identity provider provisions it.');
  console.log(`  Everything it needs to do that is in ${pairingFile}`);
  console.log('');
  console.log('  Start the identity provider. If it runs as a different user, point both at the');
  console.log('  same directory:');
  console.log('');
  console.log(`    FITFAK_PAIRING_DIR='${pairing.pairingDir(PAIRING_DIR)}'`);
  console.log('');
  console.log(`  target       ${target}`);
  console.log(`  bootstrap    ${bootstrapIdentity.fingerprint256}   (changes every boot)`);
  if (admin) {
    console.log('');
    console.log('  Admin panel');
    console.log(`    ${admin.origin}/`);
    console.log('    Sign in with the identity provider once it is up. Until then, or if it is');
    console.log('    down, the break-glass token is:');
    console.log('');
    console.log(`      ${admin.token}`);
    console.log('');
    console.log(`    (also in ${statePath('admin-token')})`);
  }
  console.log('');
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
