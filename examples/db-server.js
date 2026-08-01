'use strict';

// A production-shaped fitdb server for a stack where several services share one database
// process: an IdP, an SMTP relay, and whatever comes after them.
//
//   node examples/db-server.js
//
// Everything that has to survive a restart is written under FITFAK_DB_STATE_DIR: the CA key
// pair, the enrolment secrets, and the server's own TLS certificate. Regenerating any of those
// on every boot is what turns "restart the database" into "re-provision every client", so this
// file goes out of its way not to.
//
// Adding a service is one entry in SERVICES below plus its secret, printed once at startup.

const fs = require('node:fs');
const path = require('node:path');

const {
  createDatabaseServer, createSharedSecretAttestor, createRenewalAttestor,
  createCompositeAttestor, createIdpTokenAttestor, generateEnrolmentSecret,
  createFitfakSslCaBackend,
} = require('..');
const ssl = require('@fitfak/ssl');

// ---------------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------------

const STATE_DIR = process.env.FITFAK_DB_STATE_DIR || path.join(__dirname, '.db-state');
const DATA_DIR = process.env.FITFAK_DB_DATA_DIR || path.join(__dirname, 'fitdb');
const PORT = Number(process.env.FITFAK_DB_PORT || 51572);
const HOST = process.env.FITFAK_DB_HOST || '127.0.0.1';

const list = (value, fallback) => (value || fallback).split(',').map((s) => s.trim()).filter(Boolean);
const SERVER_DNS = list(process.env.FITFAK_DB_DNS, 'localhost, fitfak.net, *.fitfak.net');
const SERVER_IPS = list(process.env.FITFAK_DB_IPS, '127.0.0.1');

// Which services may enrol, what identity each may hold, and what it may do once enrolled.
//
// `maxUses: 1` is right and does not need raising for restarts: a service that already holds a
// certificate reconnects with resume(), and renews over mTLS with reenroll(). The secret is
// needed exactly once, at first provisioning, and can be removed from the service's environment
// afterwards. Raising it turns a one-shot credential into a standing key to the identity system.
//
// The roles here are server-wide (what the principal may ask this server to do at all).
// Authority over a particular database is separate and lives in that database's ACL, so a
// service being 'admin' here does not give it access to another service's data.
const SERVICES = {
  'idp-service': {
    roles: ['admin'],
    maxUses: 1,
    altNames: ['idp-service', 'session.fitfak.net', 'localhost'],
  },
  'smtp-service': {
    roles: ['admin'],
    maxUses: 1,
    altNames: ['smtp-service', 'mail.fitfak.net', 'localhost'],
  },
};

fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
const statePath = (name) => path.join(STATE_DIR, name);

// ---------------------------------------------------------------------------------------------
// Certificate authority, loaded from disk or created on first boot
// ---------------------------------------------------------------------------------------------

function readCaPart(keyFile, certFile) {
  const keyInfo = ssl.pemToEcPriv(fs.readFileSync(statePath(keyFile), 'utf8'));
  const certPem = fs.readFileSync(statePath(certFile), 'utf8');
  return {
    keyType: 'ec',
    curveName: keyInfo.curveName,
    hashAlg: 'sha256',
    privateKey: keyInfo.privateKey,
    publicKeyBuf: keyInfo.publicKeyBuf,
    name: ssl.certInfoFromPem(certPem).subjectNameDer,
    skid: ssl.asn1.computeEcSKID(keyInfo.publicKeyBuf),
    certPem,
  };
}

function writeCaPart(part, keyFile, certFile) {
  fs.writeFileSync(statePath(keyFile), ssl.ecPrivToPem(part), { mode: 0o600 });
  fs.writeFileSync(statePath(certFile), part.certPem, { mode: 0o644 });
}

const CA_FILES = ['root-ca.key', 'root-ca.crt', 'sub-ca.key', 'sub-ca.crt'];
let ca;

if (CA_FILES.every((f) => fs.existsSync(statePath(f)))) {
  ca = ssl.CertificateAuthority.create({
    keyAlgo: 'ec',
    root: readCaPart('root-ca.key', 'root-ca.crt'),
    intermediate: readCaPart('sub-ca.key', 'sub-ca.crt'),
  });
  console.log('[db] CA loaded from disk.');
} else {
  ca = ssl.CertificateAuthority.create({
    keyAlgo: 'ec', curveName: 'P-256',
    useIntermediate: true, organization: 'FITFAK', country: 'TR',
  });
  writeCaPart(ca.root, 'root-ca.key', 'root-ca.crt');
  writeCaPart(ca.intermediate, 'sub-ca.key', 'sub-ca.crt');
  console.log('[db] new CA generated and written to disk.');
}

// ---------------------------------------------------------------------------------------------
// The server's own TLS identity, also persisted
// ---------------------------------------------------------------------------------------------

// Regenerating this on every boot is the quiet version of the same mistake as regenerating the
// CA: it is signed by a stable CA so clients still validate it, but every restart invalidates
// every resumed TLS session and every leaf-certificate pin anyone took. Reusing it while it is
// valid, and rotating without a restart via server.rotateServerCertificate(), is cheaper.
const SERVER_KEY_FILE = 'server.key';
const SERVER_CRT_FILE = 'server.crt';

function serverCertificateIsUsable() {
  if (!fs.existsSync(statePath(SERVER_KEY_FILE)) || !fs.existsSync(statePath(SERVER_CRT_FILE))) return false;
  try {
    const info = ssl.inspectCert(fs.readFileSync(statePath(SERVER_CRT_FILE), 'utf8'));
    const notAfter = new Date(info.validTo || info.notAfter).getTime();
    // Renew a month out rather than on the day, so a failure has time to be noticed.
    return Number.isFinite(notAfter) && notAfter - Date.now() > 30 * 86400000;
  } catch (_) {
    return false;
  }
}

let serverKeyPem;
let serverChainPem;

if (serverCertificateIsUsable()) {
  serverKeyPem = fs.readFileSync(statePath(SERVER_KEY_FILE), 'utf8');
  serverChainPem = fs.readFileSync(statePath(SERVER_CRT_FILE), 'utf8');
  console.log('[db] server certificate loaded from disk.');
} else {
  const serverKey = ssl.generateEcKeyPair('P-256');
  const serverCsr = ssl.generateCSR(
    { keyType: 'ec', curveName: serverKey.curve, ...serverKey },
    [[ssl.oid.OIDs.commonName, SERVER_DNS[0] || 'localhost']],
  );
  const serverCert = ssl.issueCertificateFromCSR(serverCsr, ca.issuer, {
    profile: 'tls-server',
    sans: [
      ...SERVER_DNS.map((value) => ({ type: 'dns', value })),
      ...SERVER_IPS.map((value) => ({ type: 'ip', value })),
    ],
  });
  serverKeyPem = ssl.ecPrivToPem(serverKey);
  serverChainPem = `${[serverCert.pem.trim(), ca.getIntermediatePem().trim()].join('\n')}\n`;
  fs.writeFileSync(statePath(SERVER_KEY_FILE), serverKeyPem, { mode: 0o600 });
  fs.writeFileSync(statePath(SERVER_CRT_FILE), serverChainPem, { mode: 0o644 });
  console.log('[db] new server certificate issued and written to disk.');
}

const serverTlsOptions = {
  key: serverKeyPem,
  cert: serverChainPem,
  ca: ca.getRootPem(),
  // One port serves both channels. A peer with no certificate reaches exactly the methods that
  // declare minSecurityLevel 'tls' -- GetTrustAnchors and Enroll -- and nothing else; the
  // transport refuses everything on the data plane before a handler runs. `rejectUnauthorized`
  // must stay false for that to be possible: with it true the handshake fails first and a
  // service that has never enrolled has no way in at all.
  requestCert: true,
  rejectUnauthorized: false,
  minVersion: 'TLSv1.2',
};

// ---------------------------------------------------------------------------------------------
// Enrolment secrets, generated once and reused
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
    altNames: config.altNames || [serviceName],
    roles: config.roles,
    maxUses: config.maxUses ?? 1,
  };
  principals[serviceName] = { roles: config.roles };
}

if (secretsChanged) fs.writeFileSync(SECRETS_FILE, JSON.stringify(savedSecrets, null, 2), { mode: 0o600 });

const caFingerprint = ssl.inspectCert(ca.getRootPem()).fingerprint256;

console.log('\n  Client configuration (stable across restarts):\n');
for (const serviceName of Object.keys(SERVICES)) {
  console.log(`    ${serviceName.padEnd(16)} secret: '${savedSecrets[serviceName]}',`);
}
console.log(`    ${'caFingerprint'.padEnd(16)}       : '${caFingerprint}',`);
console.log('');

// ---------------------------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------------------------

const server = createDatabaseServer({
  baseDir: DATA_DIR,
  principals,
  logger: console,
  enrollment: {
    caBackend: createFitfakSslCaBackend({ ca, ssl }),
    serverName: SERVER_DNS[0] || 'localhost',
    attestor: createCompositeAttestor([
      // First issuance, for a service that has an out-of-band secret and nothing else.
      createSharedSecretAttestor({ enrolments }),

      // Once the IdP is up, everything after it can enrol against a token the IdP issued
      // instead of a secret pasted into its config. Only wired when the credentials are
      // present, so the server still starts before the IdP exists.
      ...(process.env.DB_OAUTH_CLIENT_ID && process.env.DB_OAUTH_CLIENT_SECRET ? [
        createIdpTokenAttestor({
          introspectionUrl: 'https://session.fitfak.net/oauth/introspect',
          clientId: process.env.DB_OAUTH_CLIENT_ID,
          clientSecret: process.env.DB_OAUTH_CLIENT_SECRET,
          services: {
            'dns-resolver': { requiredScope: 'service:enrol', subject: { CN: 'dns-resolver' }, roles: ['reader'] },
          },
        }),
      ] : []),
    ]),
    // Renewal is authenticated by the certificate being renewed, never by the request, so it
    // belongs on its own attestor rather than in the list above -- Reenroll requires mTLS and
    // Enroll must not accept it.
    renewalAttestor: createRenewalAttestor({
      roleResolver: (certificate) => SERVICES[certificate.subject?.CN]?.roles || [],
    }),
  },
});

server.on('enrolled', (event) => console.log(`[db] issued '${event.principal}' via ${event.method}`));
server.on('enrolmentDenied', (event) => console.warn(`[db] enrolment denied for '${event.serviceName}': ${event.reason}`));
server.on('databaseCreated', (event) => console.log(`[db] '${event.by}' created database ${event.dbId}`));

// A failed client handshake -- a service with an expired certificate, a probe from elsewhere on
// the network -- must be a log line, not a dead server.
server.app.on('clientError', (err) => console.warn(`[db] TLS client error: ${err.message}`));
server.app.on('sessionError', (err) => console.warn(`[db] HTTP/2 session error: ${err.message}`));
server.app.on('error', (err) => console.error('[db] server error:', err));

server.listen(PORT, { host: HOST, tls: serverTlsOptions });
console.log(`[db] listening on ${HOST}:${PORT} (data: ${DATA_DIR}, state: ${STATE_DIR})`);

// Flush every open database's index snapshot before exiting. Without this the next start
// replays segments from the last snapshot instead of resuming from a clean one -- correct
// either way, but proportionally slower the more has been written since.
let shuttingDown = false;
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n[db] ${signal} received, closing...`);
    try { await server.close({ graceMs: 5000 }); } catch (err) { console.error('[db] close failed:', err); }
    process.exit(0);
  });
}

// An unhandled rejection defaults to killing the process in current Node. For a database that
// several services depend on, taking the whole thing down over one bad request is worse than
// logging it and staying up.
process.on('unhandledRejection', (reason) => console.error('[db] unhandled rejection:', reason));
