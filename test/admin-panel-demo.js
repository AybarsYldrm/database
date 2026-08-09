'use strict';

const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const fsp = require('node:fs/promises');

const { ServiceMetrics, ServiceRegistry } = require('../src');
const { AdminServer } = require('../src/admin/admin-server');
const { createSharedSecretAttestor } = require('../src/provisioning/attestor');

// The operator surface: metrics, the service registry, and the HTTP API behind the panel.
//
// The transport is not involved, so this runs without @fitfak/grpc. What is exercised is
// everything the panel actually depends on:
//
//   - a service registered through the API becomes enrollable IMMEDIATELY, with nothing
//     restarted. That is the property that keeps operators from raising maxUses instead of
//     registering services one at a time.
//   - rotating a secret resets the use count. Without that, a rotation hands the operator a
//     fresh credential that is refused as "already used" by a counter belonging to the one it
//     replaced.
//   - byte counters accumulate DELTAS from live sockets. Summing absolutes would multiply a
//     long-lived connection's traffic by the number of samples taken.
//   - a reset does not make an active connection's whole history reappear as one enormous delta.
//   - the API refuses a request with no token, a wrong token, and a cross-origin POST.

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

/** A socket stand-in whose counters we control, matching what metrics reads. */
function fakeSocket({ cn = null, spiffeId = null, address = '10.0.0.1' } = {}) {
  return {
    remoteAddress: address,
    bytesRead: 0,
    bytesWritten: 0,
    getPeerCertificate() {
      if (!cn) return {};
      return {
        subject: { CN: cn },
        subjectaltname: spiffeId ? `DNS:${cn}, URI:${spiffeId}` : `DNS:${cn}`,
      };
    },
  };
}

/** A session stand-in: metrics only listens for 'stream', 'close' and 'error'. */
function fakeSession(socket) {
  const handlers = new Map();
  return {
    socket,
    on(event, fn) { handlers.set(event, fn); return this; },
    once(event, fn) { handlers.set(event, fn); return this; },
    emit(event, arg) { const fn = handlers.get(event); if (fn) fn(arg); },
  };
}

function fakeHttp2Server() {
  let onSession = null;
  return {
    on(event, fn) { if (event === 'session') onSession = fn; },
    open(session) { onSession(session); },
  };
}

function request(port, method, pathname, { token = null, body = null, origin = null } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = { 'content-type': 'application/json' };
    if (token) headers['x-admin-token'] = token;
    if (origin) headers.origin = origin;
    if (payload) headers['content-length'] = Buffer.byteLength(payload);

    const req = http.request({ host: '127.0.0.1', port, method, path: pathname, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch (_) { /* html */ }
        resolve({ status: res.statusCode, json, text, headers: res.headers });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function freePort() {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

async function main() {
  const stateDir = path.join(__dirname, '..', '.tmp-admin');
  await fsp.rm(stateDir, { recursive: true, force: true });

  console.log('\n1. The registry: registering a service is not an edit-and-restart');

  const registry = await ServiceRegistry.open({ stateDir, trustDomain: 'fitfak.net' });
  const attestor = createSharedSecretAttestor({ enrolments: registry.enrolments });

  check('a fresh registry is empty', registry.list().length === 0);

  const { secret } = await registry.create({ name: 'dns-resolver', roles: ['reader'] });
  check('the SPIFFE ID is derived from the name',
    registry.get('dns-resolver').spiffeId === 'spiffe://fitfak.net/service/dns-resolver');
  check('the secret is 32 bytes', Buffer.from(secret, 'base64').length === 32);
  check('the SPIFFE ID is in the SAN list',
    registry.get('dns-resolver').altNames.includes('spiffe://fitfak.net/service/dns-resolver'));

  // The property that matters: the attestor was constructed BEFORE this service existed.
  check('the attestor sees a service registered after it was built',
    registry.enrolments.has('dns-resolver'));

  await rejects('a duplicate name is refused', () => registry.create({ name: 'dns-resolver' }));
  await rejects('a name with a slash is refused', () => registry.create({ name: 'a/b' }));
  await rejects('an uppercase name is refused', () => registry.create({ name: 'DnsResolver' }));

  console.log('\n2. Credential use is counted on the entry, so rotation resets it');

  // The timestamp is taken ONCE and passed to both sides.
  //
  // It used to be `Date.now()` in the request and another `Date.now()` inside the proof
  // helper. Object properties evaluate in order, so the two calls could straddle a millisecond
  // boundary — and when they did, the transcripts differed by one digit and the HMAC did not
  // verify. It passed locally every time and failed in CI, which is the signature of every
  // flaky test: two reads of a clock that the author thought were one.
  const enrolledAt = Date.now();
  const grant = await attestor.attest.call(null, {
    request: {
      serviceName: 'dns-resolver',
      nonce: 'n1',
      timestamp: enrolledAt,
      csrPem: 'csr',
      proof: proofFor(secret, 'dns-resolver', 'n1', enrolledAt),
    },
    channelBinding: Buffer.from('cb'),
  }).catch(() => null);
  check('an enrolment with the right proof is granted', grant && grant.principal === 'dns-resolver');
  grant.commit();
  check('the use is recorded on the registry entry', registry.get('dns-resolver').uses === 1);
  check('the panel shows the credential as spent',
    registry.list().find((s) => s.name === 'dns-resolver').credentialSpent === true);

  const rotated = await registry.rotateSecret('dns-resolver');
  check('rotation issues a different secret', rotated.secret !== secret);
  // The bug this prevents: with the count in a map beside the entry, the fresh credential is
  // refused as "already used" by a counter belonging to the one it replaced.
  check('rotation resets the use count', registry.get('dns-resolver').uses === 0);
  check('and the panel no longer shows it as spent',
    registry.list().find((s) => s.name === 'dns-resolver').credentialSpent === false);

  console.log('\n3. Disabling removes it from the attestor entirely');

  await registry.update('dns-resolver', { enabled: false });
  check('a disabled service leaves the enrolment map', !registry.enrolments.has('dns-resolver'));
  check('and leaves the principal allow-list', !registry.principals()['dns-resolver']);
  await registry.update('dns-resolver', { enabled: true });
  check('re-enabling puts it back', registry.enrolments.has('dns-resolver'));

  console.log('\n4. The registry survives a restart');

  const reopened = await ServiceRegistry.open({ stateDir, trustDomain: 'fitfak.net' });
  check('the service is still there', !!reopened.get('dns-resolver'));
  check('its secret came back', !!reopened.get('dns-resolver').secret);
  check('its use count came back', reopened.get('dns-resolver').uses === 0);

  console.log('\n5. Metrics accumulate deltas, not absolutes');

  const metrics = new ServiceMetrics({ baseDir: stateDir, sampleIntervalMs: 60_000 });
  const http2 = fakeHttp2Server();
  metrics.attach(http2);

  const socket = fakeSocket({ cn: 'dns-resolver', spiffeId: 'spiffe://fitfak.net/service/dns-resolver' });
  const session = fakeSession(socket);
  http2.open(session);

  check('the connection is attributed to the certificate subject',
    metrics.connections()[0].principal === 'dns-resolver');
  check('and carries the SPIFFE ID',
    metrics.connections()[0].spiffeId === 'spiffe://fitfak.net/service/dns-resolver');

  socket.bytesRead = 1_000_000;
  socket.bytesWritten = 2_000_000;
  metrics.sample();
  // Sampling twice must not double it. This is the whole reason deltas exist.
  metrics.sample();
  metrics.sample();
  const usage = metrics.services()[0];
  check('three samples of the same socket count it once', usage.totalBytes === 3_000_000);
  check('megabytes are reported', usage.megabytes === 2.86);

  socket.bytesRead = 1_500_000;
  metrics.sample();
  check('further traffic adds only the delta', metrics.services()[0].totalBytes === 3_500_000);

  session.emit('stream', {});
  session.emit('stream', {});
  check('requests are counted', metrics.services()[0].requests === 2);

  console.log('\n6. A connection with no certificate is unattributed, not dropped');

  const anonSocket = fakeSocket({ cn: null });
  const anonSession = fakeSession(anonSocket);
  http2.open(anonSession);
  anonSocket.bytesRead = 500_000;
  metrics.sample();
  check('its bytes land under unattributed', metrics.unattributed().bytesIn === 500_000);
  check('and not under any principal', metrics.services().length === 1);
  check('the panel can tell them apart',
    metrics.connections().filter((c) => !c.authenticated).length === 1);

  console.log('\n7. Reset does not replay history as one enormous delta');

  metrics.reset();
  check('the counters are zero', metrics.services()[0].totalBytes === 0);
  check('the live connection is still open', metrics.connections().length === 2);

  socket.bytesRead = 1_600_000; // +100 000 since the reset
  metrics.sample();
  // The bug this prevents: resetting the per-socket baseline too would make the next sample
  // count the socket's ENTIRE history again.
  check('only traffic since the reset is counted', metrics.services()[0].totalBytes === 100_000);

  console.log('\n8. Closing a connection keeps the totals');

  session.emit('close');
  check('the connection is gone', metrics.connections().length === 1);
  check('but the service total is retained', metrics.services()[0].totalBytes === 100_000);
  check('and shows no live connections', metrics.services()[0].connectionsLive === 0);

  console.log('\n9. The HTTP API');

  const port = await freePort();
  const admin = new AdminServer({
    server: fakeDatabaseServer(),
    metrics,
    registry: reopened,
    host: '127.0.0.1',
    port,
    token: 'test-token-aaaaaaaaaaaaaaaaaaaa',
    info: { trustDomain: 'fitfak.net' },
  }).listen();
  await new Promise((resolve) => admin.http.once('listening', resolve));

  const noToken = await request(port, 'GET', '/api/overview');
  check('a request with no token is refused', noToken.status === 401);

  const wrongToken = await request(port, 'GET', '/api/overview', { token: 'wrong-token-aaaaaaaaaaaa' });
  check('a request with the wrong token is refused', wrongToken.status === 401);

  // A person with a browser gets sent to sign in, not a 401 body. A 401 is what an API consumer
  // needs and a dead end for someone who came here to look at the database.
  const panelNoToken = await request(port, 'GET', '/');
  check('the panel sends an unauthenticated browser to sign in',
    panelNoToken.status === 302 && panelNoToken.headers.location === '/login');

  const login = await request(port, 'GET', '/login');
  check('the sign-in page renders', login.status === 200 && login.text.includes('<title>fitdb'));
  check('and offers the break-glass token when there is no identity provider',
    login.text.includes('var idpEnabled = false'));

  const panel = await request(port, 'GET', `/?token=${admin.token}`);
  check('the panel is served with one', panel.status === 200 && panel.text.includes('<title>fitdb'));
  check('and sets the token as an HttpOnly cookie',
    /fitdb_admin=[^;]+;.*HttpOnly/i.test(String(panel.headers['set-cookie'])));

  const overview = await request(port, 'GET', '/api/overview', { token: admin.token });
  check('the overview loads', overview.status === 200 && !!overview.json.summary);
  check('it reports the admission state', overview.json.admission.state === 'sealed');
  check('it lists registered services', overview.json.services.some((s) => s.name === 'dns-resolver'));

  const crossOrigin = await request(port, 'POST', '/api/metrics/reset', {
    token: admin.token, body: {}, origin: 'https://evil.example',
  });
  check('a cross-origin POST is refused', crossOrigin.status === 403);

  const created = await request(port, 'POST', '/api/services', {
    token: admin.token,
    body: { name: 'report-worker', roles: ['reader', 'writer'], description: 'Raporlama' },
  });
  check('a service can be created through the API', created.status === 200);
  check('the secret is returned exactly once', typeof created.json.secret === 'string');
  check('and it is immediately enrollable', reopened.enrolments.has('report-worker'));

  const listed = await request(port, 'GET', '/api/services', { token: admin.token });
  const worker = listed.json.services.find((s) => s.name === 'report-worker');
  check('the listing never contains the secret', !JSON.stringify(listed.json).includes(created.json.secret));
  check('but does report whether one exists', worker.hasSecret === true);

  const sealed = await request(port, 'POST', '/api/admission/seal', {
    token: admin.token, body: { reason: 'test' },
  });
  check('the database can be sealed from the API', sealed.status === 200);

  const settings = await request(port, 'GET', '/api/settings', { token: admin.token });
  check('settings are readable', settings.status === 200 && settings.json.trustDomain === 'fitfak.net');
  // The one thing that must never be reachable.
  check('settings contain nothing key-shaped',
    !/privateKey|-----BEGIN/i.test(JSON.stringify(settings.json)));

  await admin.close();
  metrics.close();

  console.log('\n10. Binding to a routable address has to be asked for by name');

  let refused = false;
  try {
    // eslint-disable-next-line no-new
    new AdminServer({ server: fakeDatabaseServer(), metrics, registry: reopened, host: '0.0.0.0' });
  } catch (_) { refused = true; }
  check('a non-loopback bind is refused by default', refused);
  const allowed = new AdminServer({
    server: fakeDatabaseServer(), metrics, registry: reopened, host: '0.0.0.0', allowNonLoopback: true,
  });
  check('and possible when explicitly allowed', allowed.host === '0.0.0.0');

  await fsp.rm(stateDir, { recursive: true, force: true });
  console.log(`\nOK - admin panel: ${checks} checks passed.`);
}

function fakeDatabaseServer() {
  const { createAdmissionGate } = require('../src/provisioning/admission-gate');
  const gate = createAdmissionGate({
    controlPrincipal: 'idp-service',
    installIdentity: () => {},
    restoreIdentity: () => {},
  });
  return {
    gate,
    options: { baseDir: './fitdb', trustDomain: 'fitfak.net', requireSpiffeId: true },
    manager: { openDatabases: new Map() },
    address: () => ({ address: '127.0.0.1', port: 51572 }),
  };
}

/** `timestamp` is a required argument, not a default: see the note at the call site. */
function proofFor(secretB64, serviceName, nonce, timestamp) {
  const { computeEnrolmentProof } = require('../src/provisioning/attestor');
  return computeEnrolmentProof(Buffer.from(secretB64, 'base64'), {
    serviceName, nonce, timestamp, channelBinding: Buffer.from('cb'), csrPem: 'csr',
  }).toString('base64');
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
