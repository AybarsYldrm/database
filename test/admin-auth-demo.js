'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const { createIdpAuth } = require('../src/admin/idp-auth');
const { createAdminServer } = require('../src/admin/admin-server');
const { ServiceRegistry } = require('../src/admin/service-registry');
const { createServiceMetrics } = require('../src/admin/metrics');

// Signing an operator into the database's admin panel with the identity provider.
//
// The thing under test is not "does OAuth work" -- it is that this panel stops being the one
// surface in the stack with its own idea of who an administrator is. Everything else here takes
// its authority from the IdP; a panel with a private password would make that arrangement
// decorative.
//
// The IdP is stubbed, and it has to be: the point of these checks is what THIS side does with the
// answers, including the ones a real IdP would only produce on a bad day -- a token it then
// declines to introspect, an account with the wrong role, a code replayed twice.
//
// The checks that matter most are the negative ones. A sign-in that lets the right person in is
// visible the first time anyone tries it; a sign-in that also lets the wrong person in looks
// exactly the same from the outside.

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

// ---------------------------------------------------------------------------------------------
// A stand-in identity provider.
//
// It records what it was asked, so the test can assert on the REQUEST as well as the response --
// PKCE is only worth anything if the verifier actually reaches the token endpoint, and a stub that
// ignores the body would let a broken client pass.
// ---------------------------------------------------------------------------------------------

function createStubIdp({ role = 'admin', scope = 'openid profile fitdb:admin', active = true } = {}) {
  const state = {
    tokenRequests: [], introspectRequests: [], issuedCodes: new Map(),
    role, scope, active,
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const reply = (status, payload) => {
        const body = JSON.stringify(payload);
        res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
        res.end(body);
      };

      if (req.url === '/oauth/token') {
        const form = Object.fromEntries(new URLSearchParams(raw));
        state.tokenRequests.push(form);
        const issued = state.issuedCodes.get(form.code);
        if (!issued) return reply(400, { error: 'invalid_grant', error_description: 'unknown code' });
        // Single use, like the real one. Without this the replay check below would pass for the
        // wrong reason.
        state.issuedCodes.delete(form.code);
        const expected = crypto.createHash('sha256').update(form.code_verifier || '').digest('base64url');
        if (expected !== issued.challenge) {
          return reply(400, { error: 'invalid_grant', error_description: 'PKCE verifier does not match' });
        }
        return reply(200, { access_token: `at-${form.code}`, token_type: 'Bearer', expires_in: 3600 });
      }

      if (req.url === '/oauth/introspect') {
        state.introspectRequests.push({
          body: JSON.parse(raw || '{}'),
          clientId: req.headers['x-client-id'],
          clientSecret: req.headers['x-client-secret'],
        });
        if (!state.active) return reply(200, { active: false });
        return reply(200, {
          active: true, sub: 'user-1', username: 'aybars',
          role: state.role, scope: state.scope, sid: 'sid-1',
        });
      }

      if (req.url === '/oauth/proxy-error') {
        res.writeHead(502, { 'content-type': 'text/html' });
        return res.end('<html><body>Bad Gateway</body></html>');
      }

      reply(404, { error: 'not_found' });
    });
  });

  return { server, state };
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

/** Pulls the state out of an authorization URL and pre-authorises a code for it. */
function approveAt(stub, authorizeUrl, { code = 'code-1' } = {}) {
  const url = new URL(authorizeUrl);
  stub.state.issuedCodes.set(code, { challenge: url.searchParams.get('code_challenge') });
  return { code, state: url.searchParams.get('state'), url };
}

function request(port, method, pathname, { cookie = null, token = null, origin = null } = {}) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (cookie) headers.cookie = cookie;
    if (token) headers['x-admin-token'] = token;
    if (origin) headers.origin = origin;
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
    req.end();
  });
}

const sidFrom = (res) => {
  const raw = String(res.headers['set-cookie'] || '');
  const match = /fitdb_sid=([^;]+)/.exec(raw);
  return match ? `fitdb_sid=${match[1]}` : null;
};

// ---------------------------------------------------------------------------------------------

async function main() {
  const stub = createStubIdp();
  const idpPort = await listen(stub.server);
  const issuer = `http://127.0.0.1:${idpPort}`;

  const auth = () => createIdpAuth({
    issuer,
    clientId: 'fitdb-admin-panel',
    clientSecret: 'panel-secret',
    redirectUri: 'http://127.0.2.1/auth/callback',
  });

  console.log('\n1. The redirect carries what the exchange will be checked against');

  {
    const a = auth();
    const { url } = a.beginAuthorization();
    const parsed = new URL(url);
    check('it goes to the identity provider', parsed.origin === issuer && parsed.pathname === '/oauth/authorize');
    check('as an authorization code request', parsed.searchParams.get('response_type') === 'code');
    check('naming this client', parsed.searchParams.get('client_id') === 'fitdb-admin-panel');
    check('and the exact redirect it must come back to', parsed.searchParams.get('redirect_uri') === 'http://127.0.2.1/auth/callback');
    check('asking for the scope that gates this panel', parsed.searchParams.get('scope').includes('fitdb:admin'));
    // Loopback redirects are the case PKCE was written for: on a shared host another local process
    // can race for the address, and an intercepted code is worthless without the verifier.
    check('with an S256 challenge', parsed.searchParams.get('code_challenge_method') === 'S256');
    check('and a challenge that is not the verifier', parsed.searchParams.get('code_challenge').length >= 43);
    check('state is unguessable', parsed.searchParams.get('state').length >= 32);
  }

  console.log('\n2. A completed sign-in');

  {
    const a = auth();
    const { url } = a.beginAuthorization();
    const { code, state } = approveAt(stub, url);
    const { sid, session } = await a.completeAuthorization({ code, state });

    check('a session is opened', typeof sid === 'string' && sid.length >= 32);
    check('and it names the person, not the panel', session.username === 'aybars' && session.sub === 'user-1');
    check('recording which path they came in by', session.via === 'idp');
    check('the session resolves', a.resolveSession(sid).sub === 'user-1');

    const tokenRequest = stub.state.tokenRequests.at(-1);
    check('the verifier reached the token endpoint', typeof tokenRequest.code_verifier === 'string');
    check('and so did the client secret', tokenRequest.client_secret === 'panel-secret');

    // Introspection rather than reading the token's own claims: this process holds no copy of the
    // IdP's signing key and should not grow one. It also answers a question a signature cannot --
    // whether the session behind the token has been revoked since it was issued.
    const introspect = stub.state.introspectRequests.at(-1);
    check('the token was introspected at the issuer', introspect.body.token === `at-${code}`);
    check('authenticated as this client', introspect.clientId === 'fitdb-admin-panel');
  }

  console.log('\n3. The state is single-use and must be one this process issued');

  {
    const a = auth();
    const { url } = a.beginAuthorization();
    const { code, state } = approveAt(stub, url, { code: 'code-2' });
    await a.completeAuthorization({ code, state });

    // The code is spent at the IdP, but that is the IdP's protection, not this one's. The state
    // has to be consumed here as well: a state that survives its exchange is a state that can be
    // replayed, and the replay is the attacker's.
    await rejects('the same state cannot be used twice',
      () => a.completeAuthorization({ code: 'code-2', state }), /unknown or expired/i);

    await rejects('a state this process never issued is refused',
      () => a.completeAuthorization({ code: 'code-2', state: 'made-up-state' }), /unknown or expired/i);

    await rejects('and so is a callback with no state at all',
      () => a.completeAuthorization({ code: 'code-2', state: null }), /unknown or expired/i);
  }

  console.log('\n4. A verifier that does not match the challenge is refused');

  {
    const a = auth();
    const { url } = a.beginAuthorization();
    // A code minted against SOMEONE ELSE'S challenge -- what an interception on the loopback
    // redirect actually yields.
    stub.state.issuedCodes.set('stolen', { challenge: 'a-challenge-from-another-flow' });
    const state = new URL(url).searchParams.get('state');
    await rejects('an intercepted code is useless without the verifier',
      () => a.completeAuthorization({ code: 'stolen', state }), /PKCE/i);
  }

  console.log('\n5. Being signed in is not the same as being an administrator');

  {
    stub.state.role = 'user';
    const a = auth();
    const { url } = a.beginAuthorization();
    const { code, state } = approveAt(stub, url, { code: 'code-3' });
    // Scope and role are checked separately on purpose: a consent screen can grant the first and
    // must never be able to grant the second.
    await rejects('an ordinary account is refused',
      () => a.completeAuthorization({ code, state }), /cannot administer/i);
    stub.state.role = 'admin';
  }

  {
    stub.state.scope = 'openid profile';
    const a = auth();
    const { url } = a.beginAuthorization();
    const { code, state } = approveAt(stub, url, { code: 'code-4' });
    await rejects('an admin whose token lacks the panel scope is refused',
      () => a.completeAuthorization({ code, state }), /fitdb:admin/i);
    stub.state.scope = 'openid profile fitdb:admin';
  }

  {
    stub.state.active = false;
    const a = auth();
    const { url } = a.beginAuthorization();
    const { code, state } = approveAt(stub, url, { code: 'code-5' });
    // The revoked-in-between case. A local signature check would accept this token.
    await rejects('a token the issuer no longer vouches for is refused',
      () => a.completeAuthorization({ code, state }), /rejected the token/i);
    stub.state.active = true;
  }

  console.log('\n6. Something other than the identity provider answering is said out loud');

  {
    const a = createIdpAuth({
      issuer: `${issuer}/oauth/proxy-error`.replace('/oauth/proxy-error', ''),
      clientId: 'c', clientSecret: 's', redirectUri: 'http://127.0.2.1/auth/callback',
    });
    // A proxy answering with an HTML error page is the common real failure, and reporting it as
    // "unexpected token < in JSON" sends an operator looking in the wrong process.
    const message = await rejects('a non-JSON body names the actual problem',
      () => a._post('/oauth/proxy-error', {}), /non-JSON body/);
    check('and says which address answered wrongly', /Something other than the identity provider/.test(message));
  }

  console.log('\n7. Sessions expire and can be ended');

  {
    const a = auth();
    const { url } = a.beginAuthorization();
    const { code, state } = approveAt(stub, url, { code: 'code-6' });
    const { sid } = await a.completeAuthorization({ code, state });

    check('an unknown session id resolves to nothing', a.resolveSession('not-a-session') === null);
    check('and so does no session id at all', a.resolveSession(null) === null);

    a._sessions.get(sid).expiresAt = Date.now() - 1;
    check('an expired session is not resolved', a.resolveSession(sid) === null);

    const { url: url2 } = a.beginAuthorization();
    const second = approveAt(stub, url2, { code: 'code-7' });
    const { sid: sid2 } = await a.completeAuthorization(second);
    check('signing out ends it', a.endSession(sid2) === true && a.resolveSession(sid2) === null);
  }

  console.log('\n8. In-flight sign-ins do not accumulate');

  {
    const a = auth();
    for (let i = 0; i < 64; i++) a.beginAuthorization();
    // Every unfinished redirect holds a verifier. Unbounded, a loop hitting /auth/start would grow
    // this map without ever completing a flow.
    let threw = false;
    try { a.beginAuthorization(); } catch (_) { threw = true; }
    check('the pending map is bounded', threw);

    for (const flow of a._flows.values()) flow.createdAt = Date.now() - 11 * 60 * 1000;
    a.beginAuthorization();
    check('and expired ones are swept so a new sign-in still works', a._flows.size === 1);
  }

  console.log('\n9. End to end, through the panel');

  const stateDir = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'fitdb-auth-'));
  const registry = await ServiceRegistry.open({ stateDir, trustDomain: 'fitfak.net' });
  const metrics = createServiceMetrics({ baseDir: stateDir });
  const fakeServer = { gate: null, options: { baseDir: stateDir }, address: () => ({ port: 1 }), manager: null };

  const admin = createAdminServer({
    server: fakeServer, metrics, registry,
    host: '127.0.0.1', port: 0,
    token: 'break-glass-token-aaaaaaaaaa',
    idpAuth: auth(),
  }).listen();
  await new Promise((resolve) => admin.http.once('listening', resolve));
  const port = admin.http.address().port;

  {
    const login = await request(port, 'GET', '/login');
    check('the sign-in page offers the identity provider', login.text.includes('var idpEnabled = true'));
    check('and names which one, so the button is not a leap of faith', login.text.includes(issuer));

    const start = await request(port, 'GET', '/auth/start');
    check('/auth/start redirects to the issuer', start.status === 302 && start.headers.location.startsWith(issuer));

    const { code, state } = approveAt(stub, start.headers.location, { code: 'code-8' });
    const cb = await request(port, 'GET', `/auth/callback?code=${code}&state=${state}`);
    check('the callback lands on the dashboard', cb.status === 302 && cb.headers.location === '/');

    const cookie = sidFrom(cb);
    check('with a session cookie', !!cookie);
    check('that page script cannot read', /HttpOnly/i.test(String(cb.headers['set-cookie'])));
    check('and no other origin can cause to be sent', /SameSite=Strict/i.test(String(cb.headers['set-cookie'])));

    const panel = await request(port, 'GET', '/', { cookie });
    check('the panel is served to the session', panel.status === 200 && panel.text.includes('<title>fitdb'));

    const whoami = await request(port, 'GET', '/api/whoami', { cookie });
    check('the API knows who it is talking to', whoami.json.username === 'aybars');
    check('and which credential got them in', whoami.json.via === 'idp');

    const overview = await request(port, 'GET', '/api/overview', { cookie });
    check('the dashboard reports the session with its very first payload', overview.json.session.via === 'idp');
  }

  {
    // The break-glass path stays open, because the IdP is a separate process that can be down --
    // and when it is, this database is the thing an operator most needs to look at.
    const withToken = await request(port, 'GET', '/api/overview', { token: 'break-glass-token-aaaaaaaaaa' });
    check('the break-glass token still works', withToken.status === 200);
    check('and is reported as what it is', withToken.json.session.via === 'token');

    const wrong = await request(port, 'GET', '/api/overview', { token: 'break-glass-token-bbbbbbbbbb' });
    check('a wrong token is refused', wrong.status === 401);
    check('with a pointer to the way in', wrong.json.loginUrl === '/login');
  }

  {
    const start = await request(port, 'GET', '/auth/start');
    const { code, state } = approveAt(stub, start.headers.location, { code: 'code-9' });
    const cb = await request(port, 'GET', `/auth/callback?code=${code}&state=${state}`);
    const cookie = sidFrom(cb);

    const out = await request(port, 'GET', '/logout', { cookie });
    check('signing out redirects to the sign-in page', out.status === 302 && out.headers.location.startsWith('/login'));
    check('and clears both cookies', /Max-Age=0/.test(String(out.headers['set-cookie'])));

    const after = await request(port, 'GET', '/api/overview', { cookie });
    check('the session is gone server-side, not just in the browser', after.status === 401);
  }

  {
    const failed = await request(port, 'GET', '/auth/callback?error=access_denied&error_description=nope');
    check('a refusal at the identity provider comes back as its own message',
      failed.status === 302 && decodeURIComponent(failed.headers.location).includes('nope'));

    // The error text is attacker-choosable -- anything that can send an operator to a URL picks it.
    // It must not be able to become script.
    const xss = await request(port, 'GET', '/login?error=' + encodeURIComponent('</script><img src=x onerror=alert(1)>'));
    check('an injected error cannot close the script block', !xss.text.includes('</script><img'));
    check('it is escaped instead', xss.text.includes('\\u003c/script'));
  }

  await admin.close();
  await new Promise((resolve) => stub.server.close(resolve));
  metrics.close();
  require('node:fs').rmSync(stateDir, { recursive: true, force: true });

  console.log(`\nOK - admin sign-in: ${checks} checks passed.`);
}

main().then(
  () => process.exit(0),
  (err) => { console.error('\nFAILED:', err.message, err.stack); process.exit(1); },
);
