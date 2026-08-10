'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// The operator's window into a running database.
//
// Plain HTTP on a loopback address, in the same shape as the IdP's admin host: one logical
// service per loopback IP, port 80, fronted by whatever terminates TLS at the edge.
//
//
// WHO GETS IN
//
// Two ways, and the difference between them is the point.
//
//   1. THE IDENTITY PROVIDER, which is the everyday path. The operator clicks through to the IdP,
//      signs in there with whatever it requires that day, and comes back with an authorization
//      code. The IdP decides who is an administrator; this panel only checks the answer. See
//      src/admin/idp-auth.js.
//
//   2. THE STARTUP TOKEN, which is break-glass. It exists because the IdP is a separate process
//      that can be down, and when it is down this database is the thing an operator most needs to
//      look at. A panel that fails alongside the IdP is a panel unavailable during exactly the
//      incident it would help with.
//
// The panel shows which of the two you used, because they are not equivalent and an operator
// should never be unsure which one is holding the door open.
//
//
// WHY THIS IS NOT AS ALARMING AS "PLAIN HTTP ADMIN PANEL" SOUNDS, AND WHERE IT STILL IS
//
// The bind address is the primary control. 127.0.2.1 is reachable only from this host, so the
// question "who can use this panel" reduces to "who can run code on this machine" — and anyone
// who can run code on this machine can already read the database's memory, which is strictly
// worse than anything the panel offers.
//
// That is a real boundary, but it is not the whole story, so credentials are required as well:
//
//   - a local process is not necessarily a TRUSTED local process. A build agent, a sidecar, a
//     compromised dependency in some unrelated service on the same box — all of them can reach
//     a loopback port.
//   - a browser on this host can be steered to a loopback URL by any page the operator visits.
//     The credential stops a drive-by POST; the same-origin check stops the rest.
//
// What this panel deliberately CANNOT do:
//
//   - read or export any CA private key. There is no route for it. The whole point of moving
//     that material into the encrypted store was to stop it being copyable, and an HTTP route
//     that returns it would undo that in one line.
//   - read application data. It reports sizes, not contents.
//   - issue certificates. Issuance goes through the identity provider; this panel registers who
//     may ASK for one.

const PANEL_FILE = path.join(__dirname, 'panel.html');
const LOGIN_FILE = path.join(__dirname, 'login.html');

const LOOPBACK = /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|localhost)$/;

// The panel is a single-page app and its own entry point. Landing on the dashboard means landing
// on `/` with a session already established — so the sign-in surface is a SEPARATE page rather
// than a state of the panel. A panel that renders itself and then discovers it is unauthenticated
// flashes real-looking empty tables at an operator, and an empty table and a forbidden table look
// identical.
const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

class AdminServer {
  /**
   * @param {object}   opts
   * @param {object}   opts.server      the DatabaseServer being administered
   * @param {object}   opts.metrics     ServiceMetrics
   * @param {object}   opts.registry    ServiceRegistry
   * @param {string}  [opts.host]       defaults to 127.0.2.1
   * @param {number}  [opts.port]       defaults to 80
   * @param {string}  [opts.token]      generated when omitted
   * @param {boolean} [opts.allowNonLoopback=false]
   * @param {object}  [opts.info]       static facts for the overview (target address, trust domain…)
   * @param {object}  [opts.idpAuth]    an IdpAuth; when absent the panel is token-only
   */
  constructor({
    server, metrics, registry, host = '127.0.2.1', port = 80,
    token = null, allowNonLoopback = false, info = {}, logger = null, idpAuth = null,
  }) {
    if (!server) throw new Error('fitdb admin: a DatabaseServer is required');
    if (!metrics) throw new Error('fitdb admin: ServiceMetrics is required');
    if (!registry) throw new Error('fitdb admin: a ServiceRegistry is required');

    if (!LOOPBACK.test(host) && !allowNonLoopback) {
      // Binding this to a routable address publishes an unauthenticated-by-TLS control surface
      // to the network. It is a legitimate thing to want behind a proxy that authenticates, so
      // it is possible — but it has to be asked for by name.
      throw new Error(
        `fitdb admin: refusing to bind the admin panel to ${host}. It speaks plain HTTP and its `
        + 'only transport-level protection is being unreachable from the network. Pass '
        + 'allowNonLoopback: true if something in front of it is doing authentication.',
      );
    }

    this.server = server;
    this.metrics = metrics;
    this.registry = registry;
    this.host = host;
    this.port = port;
    this.info = info;
    this._log = logger;
    this.idpAuth = idpAuth;
    this.token = token || crypto.randomBytes(24).toString('base64url');
    this.origin = `http://${host}${port === 80 ? '' : `:${port}`}`;
    this.http = null;

    // Read once at startup rather than per request: files this process ships with, and re-reading
    // them on every load would turn a panel refresh into disk I/O on the database host.
    this._panel = fs.readFileSync(PANEL_FILE, 'utf8');
    this._login = fs.readFileSync(LOGIN_FILE, 'utf8');
  }

  listen() {
    this.http = http.createServer((req, res) => {
      this._handle(req, res).catch((err) => {
        this._log?.error?.({ error: err.message, url: req.url, msg: 'admin request failed' });
        send(res, 500, { error: 'internal_error', error_description: err.message });
      });
    });
    this.http.listen(this.port, this.host);
    return this;
  }

  /** The URL an operator should open, token included. Printed once at startup. */
  url() { return `${this.origin}/?token=${this.token}`; }

  async close() {
    if (this.http) await new Promise((resolve) => this.http.close(resolve));
  }

  // ---- request plumbing ---------------------------------------------------------------------

  async _handle(req, res) {
    const url = new URL(req.url, this.origin);
    const pathname = url.pathname;

    // ---- sign-in surface --------------------------------------------------------------------
    //
    // These three run BEFORE the credential check, and have to: they are how a credential is
    // obtained. Each one is safe to reach unauthenticated on its own — /login renders a button,
    // /auth/start mints a state this process will require back, /auth/callback is useless without
    // a state that matches one.
    if (pathname === '/login' && req.method === 'GET') return this._serveLogin(req, res, url);
    if (pathname === '/auth/start' && req.method === 'GET') return this._authStart(res);
    if (pathname === '/auth/callback' && req.method === 'GET') return this._authCallback(res, url);

    if (pathname === '/logout') {
      const session = this._session(req);
      if (session?.sid) this.idpAuth?.endSession(session.sid);
      res.statusCode = 302;
      res.setHeader('set-cookie', [expiredCookie('fitdb_sid'), expiredCookie('fitdb_admin')]);
      res.setHeader('location', '/login?signed_out=1');
      return res.end();
    }

    // ---- the panel --------------------------------------------------------------------------
    //
    // Landing here signed in means landing on the dashboard, which is the whole intent: an
    // operator arriving from the IdP should see the state of the database, not a form.
    if (pathname === '/' && req.method === 'GET') {
      // A token in the query string is accepted once and immediately moved into a cookie, so it
      // does not stay in the address bar — the same reasoning as the device-code link in the IdP:
      // a URL ends up in history, in a screenshot, and over someone's shoulder.
      const supplied = url.searchParams.get('token');
      if (supplied) {
        if (!this._tokenMatches(supplied)) {
          // Said out loud rather than silently redirected. A wrong token that lands back on the
          // sign-in page with no message reads as "the page reloaded", and the operator pastes
          // the same wrong value again.
          res.statusCode = 302;
          res.setHeader('location', '/login?error=' + encodeURIComponent(
            'Bu açılış anahtarı geçerli değil. Anahtar her açılışta yeniden üretilir; '
            + 'durum dizinindeki admin-token dosyasına bakın.'));
          return res.end();
        }
        // The token moves into a cookie and the URL is dropped by the redirect, so it does not
        // stay in the address bar — the same reasoning as the device-code link in the IdP: a URL
        // ends up in history, in a screenshot, and over someone's shoulder.
        //
        // Redirecting rather than rendering here is what makes that true. Serving the panel
        // directly would leave `?token=…` in the address bar of the page being looked at, and
        // every later refresh would re-send it.
        res.statusCode = 302;
        res.setHeader('set-cookie',
          `fitdb_admin=${encodeURIComponent(this.token)}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict`);
        res.setHeader('location', '/');
        return res.end();
      }
      if (this._session(req)) return this._servePanel(res);

      // No credential: to the sign-in page, not a 401. A 401 body is what an API consumer needs
      // and a dead end for a person with a browser.
      res.statusCode = 302;
      res.setHeader('location', '/login');
      return res.end();
    }

    if (!pathname.startsWith('/api/')) return send(res, 404, { error: 'not_found' });

    const session = this._session(req);
    if (!session) return this._unauthorized(res);

    // Every state change is same-origin checked. The credential alone is not enough: a page the
    // operator visits could hold a stale token from a shared screenshot and fire a POST at
    // loopback. `Origin` is set by the browser and cannot be forged by page script.
    if (req.method === 'POST') {
      const origin = req.headers.origin;
      if (origin && origin !== this.origin) {
        return send(res, 403, { error: 'cross_origin', error_description: `refusing a POST from ${origin}` });
      }
    }

    const body = req.method === 'POST' ? await readJson(req) : {};
    const result = await this._route(pathname, req.method, body, url, session);
    if (result === undefined) return send(res, 404, { error: 'not_found' });
    return send(res, 200, result);
  }

  // ---- authentication -------------------------------------------------------------------------

  /**
   * Who is making this request, by either path.
   *
   * The IdP session is checked first so that an operator who has signed in properly is reported as
   * such even while a break-glass token cookie is still sitting in the same browser — the panel
   * displays this, and displaying the weaker of two credentials would be misleading in the one
   * direction that matters.
   */
  _session(req) {
    const sid = cookieValue(req, 'fitdb_sid');
    if (sid && this.idpAuth) {
      const found = this.idpAuth.resolveSession(sid);
      if (found) return { ...found, sid };
    }
    if (this._tokenMatches(this._suppliedToken(req))) {
      return { via: 'token', username: 'break-glass token', role: null, sub: null };
    }
    return null;
  }

  _suppliedToken(req) {
    const header = req.headers['x-admin-token'];
    if (header) return String(header);
    return cookieValue(req, 'fitdb_admin');
  }

  _servePanel(res) {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    return res.end(this._panel);
  }

  /**
   * The sign-in page.
   *
   * Rendered by substitution rather than by a template engine: there are four values, all of them
   * landing inside a <script> block, and all of them emitted as JSON literals. A template engine
   * here would be a dependency whose only job is to make four replacements slower to audit.
   *
   * The one value that is not this process's own is `error`, which arrives in the query string —
   * so anything that can send an operator to a URL can choose what that banner says. It cannot
   * become script (see jsonForScript), but it can still lie, which is why the page keeps the
   * issuer's hostname visible next to the button rather than only in the message.
   */
  _serveLogin(req, res, url) {
    // Already signed in? Then this page has nothing to offer. Rendering it anyway is how an
    // operator ends up signing in twice and wondering which session they are on.
    if (this._session(req)) {
      res.statusCode = 302;
      res.setHeader('location', '/');
      return res.end();
    }
    const html = this._login
      .replace('{{IDP_ENABLED}}', this.idpAuth ? 'true' : 'false')
      .replace('{{IDP_ISSUER}}', jsonForScript(this.idpAuth ? this.idpAuth.issuer : ''))
      .replace('{{ERROR}}', jsonForScript(url.searchParams.get('error') || ''))
      .replace('{{SIGNED_OUT}}', url.searchParams.get('signed_out') ? 'true' : 'false');

    res.statusCode = 200;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    return res.end(html);
  }

  _authStart(res) {
    if (!this.idpAuth) {
      res.statusCode = 302;
      res.setHeader('location', '/login?error=' + encodeURIComponent(
        'This database was started without identity-provider sign-in. Use the startup token.'));
      return res.end();
    }
    try {
      const { url } = this.idpAuth.beginAuthorization();
      res.statusCode = 302;
      res.setHeader('location', url);
      return res.end();
    } catch (err) {
      res.statusCode = 302;
      res.setHeader('location', `/login?error=${encodeURIComponent(err.message)}`);
      return res.end();
    }
  }

  async _authCallback(res, url) {
    const redirect = (location, cookies = null) => {
      res.statusCode = 302;
      if (cookies) res.setHeader('set-cookie', cookies);
      res.setHeader('location', location);
      res.end();
    };

    if (!this.idpAuth) return redirect('/login?error=' + encodeURIComponent('sign-in is not configured'));

    // The IdP reporting a failure is not this process's failure, and its description is the useful
    // half. Passing it through beats replacing it with a generic message that sends the operator
    // looking here instead of there.
    const idpError = url.searchParams.get('error');
    if (idpError) {
      const detail = url.searchParams.get('error_description') || idpError;
      return redirect(`/login?error=${encodeURIComponent(detail)}`);
    }

    try {
      const { sid } = await this.idpAuth.completeAuthorization({
        code: url.searchParams.get('code'),
        state: url.searchParams.get('state'),
      });
      // HttpOnly so page script cannot read it, SameSite=Strict so no other origin can cause it to
      // be sent. Not Secure, because this listener is plain HTTP on loopback and a Secure cookie
      // would simply never be stored — a flag that silently disables the session is worse than its
      // absence, which is at least visible here in a comment.
      return redirect('/', [
        `fitdb_sid=${encodeURIComponent(sid)}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict`,
      ]);
    } catch (err) {
      this._log?.warn?.({ error: err.message, msg: 'admin sign-in failed' });
      return redirect(`/login?error=${encodeURIComponent(err.message)}`);
    }
  }

  _tokenMatches(supplied) {
    if (!supplied) return false;
    const a = Buffer.from(String(supplied));
    const b = Buffer.from(this.token);
    // Length is compared separately because timingSafeEqual throws on a mismatch; the length of
    // a token is not a secret worth protecting, its contents are.
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  _unauthorized(res) {
    send(res, 401, {
      error: 'unauthorized',
      error_description: this.idpAuth
        ? 'Sign in through the identity provider at /login, or use the token printed when the database started.'
        : 'An admin token is required. It is printed once when the database starts.',
      loginUrl: '/login',
    });
  }

  // ---- routes -----------------------------------------------------------------------------

  async _route(pathname, method, body, url, session) {
    const route = `${method} ${pathname}`;

    switch (route) {
      case 'GET /api/overview':
        return this._overview(session);

      case 'GET /api/whoami':
        return {
          username: session.username,
          subject: session.sub,
          role: session.role,
          via: session.via,
          expiresAt: session.expiresAt || null,
          idp: this.idpAuth ? this.idpAuth.status() : null,
        };

      case 'GET /api/services':
        return { services: this._services() };

      case 'POST /api/services': {
        const created = await this.registry.create({
          name: body.name,
          roles: body.roles || ['reader'],
          altNames: body.altNames || [],
          maxUses: body.maxUses ?? 1,
          description: body.description || '',
          kind: body.kind || 'service',
        });
        this._log?.warn?.({ service: body.name, msg: 'service registered from the admin panel' });
        // The secret is returned exactly once, right here. There is no route that returns it
        // again, and the panel says so on the screen that shows it.
        return created;
      }

      case 'POST /api/services/update':
        return this.registry.update(body.name, body);

      case 'POST /api/services/rotate': {
        const rotated = await this.registry.rotateSecret(body.name);
        this._log?.warn?.({ service: body.name, msg: 'enrolment credential rotated from the admin panel' });
        return rotated;
      }

      case 'POST /api/services/remove': {
        const removed = await this.registry.remove(body.name);
        this.metrics.forget(body.name);
        this._log?.warn?.({ service: body.name, msg: 'service removed from the admin panel' });
        return removed;
      }

      case 'GET /api/connections':
        return { connections: this.metrics.connections(), unattributed: this.metrics.unattributed() };

      case 'GET /api/storage':
        return { databases: await this._databases() };

      case 'POST /api/metrics/reset':
        return this.metrics.reset(body.principal || null);

      case 'POST /api/admission/seal': {
        if (!this.server.gate) {
          return { sealed: false, reason: 'this database was started without admission control' };
        }
        const sealed = this.server.gate.seal(body.reason || 'sealed from the admin panel');
        this._log?.warn?.({ reason: body.reason, msg: 'database sealed from the admin panel' });
        return { sealed, state: this.server.gate.state };
      }

      case 'GET /api/settings':
        return this._settings();

      default:
        // A GET with a query is still a distinct route; handled here so the switch above stays
        // readable rather than growing string concatenation.
        if (route === 'GET /api/services/one') {
          const service = this.registry.get(url.searchParams.get('name'));
          return service ? { service: this.registry.list().find((s) => s.name === service.name) } : undefined;
        }
        return undefined;
    }
  }

  _overview(session = null) {
    const summary = this.metrics.summary();
    const gate = this.server.gate ? this.server.gate.status() : null;
    return {
      summary,
      // Returned with the dashboard rather than fetched separately, because the panel needs it on
      // its very first paint: which of the two credentials is holding the door open belongs in the
      // header, not in a second round trip that might not have landed yet.
      session: session && {
        username: session.username, role: session.role, via: session.via, subject: session.sub,
      },
      admission: gate && {
        state: gate.state,
        controlPrincipal: gate.controlPrincipal,
        controlSpiffeId: gate.controlSpiffeId,
        provisionedAt: gate.provisionedAt,
        openedAt: gate.openedAt,
        holdExpiresAt: gate.holdExpiresAt,
        identity: gate.identity,
      },
      info: {
        ...this.info,
        // Read from the live server rather than from configuration: a panel that reports the
        // port someone intended to bind is useless exactly when it matters.
        listening: this.server.address ? this.server.address() : null,
        adminOrigin: this.origin,
      },
      services: this._services(),
    };
  }

  /** Registry entries joined with what each one has actually done. */
  _services() {
    const usage = new Map(this.metrics.services().map((entry) => [entry.principal, entry]));
    const registered = this.registry.list();
    const known = new Set(registered.map((s) => s.name));

    const rows = registered.map((service) => ({
      ...service,
      registered: true,
      system: false,
      usage: usage.get(service.name) || null,
    }));

    // The identity provider is not an application, and the panel must not draw it as one.
    //
    // It is admitted by the admission gate rather than by the enrolment registry — a different
    // mechanism, for a different reason. Every other principal here obtained its certificate by
    // presenting a credential this database issued; the IdP presents a certificate signed by the
    // CA that this database's whole trust chain descends from, and it is the only principal that
    // can reach anything while the database is sealed.
    //
    // Listing it beside the applications would invite an operator to treat it like one — to
    // rotate its credential, disable it, remove it. None of those do what they appear to: it has
    // no registry entry to rotate, and "removing" it would only mean the row disappears until it
    // reconnects. Marking it as system is what makes the panel's controls honest.
    const gate = this.server.gate ? this.server.gate.status() : null;
    const controlPrincipal = gate ? gate.controlPrincipal : null;

    for (const [principal, entry] of usage) {
      if (known.has(principal)) continue;
      const isControl = principal === controlPrincipal;
      rows.push({
        name: principal,
        spiffeId: entry.spiffeId,
        kind: isControl ? 'system' : 'unknown',
        system: isControl,
        roles: isControl ? ['admin'] : [],
        altNames: [],
        registered: false,
        enabled: true,
        description: isControl
          ? 'Kimlik sağlayıcısı. Bir uygulama değil, sistemin parçası: bu veritabanını mühürden '
            + 'çıkaran ve diğer herkesin sertifikasını imzalayan taraf.'
          : '',
        usage: entry,
      });
    }

    // The control principal belongs on the list even when it has never connected — its absence is
    // the single most important thing this panel can tell an operator, and a row that simply is
    // not drawn says nothing at all.
    if (controlPrincipal && !rows.some((row) => row.name === controlPrincipal)) {
      rows.push({
        name: controlPrincipal,
        spiffeId: gate.controlSpiffeId,
        kind: 'system',
        system: true,
        roles: ['admin'],
        altNames: [],
        registered: false,
        enabled: true,
        connected: false,
        description: 'Kimlik sağlayıcısı — henüz bağlanmadı. Bağlanana kadar bu veritabanı '
          + 'mühürlü kalır ve hiçbir uygulama giremez.',
        usage: null,
      });
    }
    return rows;
  }

  async _databases() {
    const sizes = await this.metrics.storage();
    const open = this.server.manager && this.server.manager.openDatabases
      ? new Set([...this.server.manager.openDatabases.keys()].map(String))
      : new Set();
    return sizes.map((row) => ({ ...row, open: open.has(String(row.dbId)) }));
  }

  _settings() {
    const options = this.server.options || {};
    return {
      // Only the knobs an operator would want to see. No secrets, and nothing that could be
      // reassembled into one.
      baseDir: options.baseDir,
      trustDomain: options.trustDomain || null,
      requireSpiffeId: !!options.requireSpiffeId,
      subjectField: options.subjectField || 'CN',
      sessionTtlMs: options.sessionTtlMs,
      maxScanLimit: options.maxScanLimit,
      maxFindLimit: options.maxFindLimit,
      capabilityMaxTtlMs: options.capabilityMaxTtlMs,
      strictFields: !!options.strictFields,
      autoGrantOwner: options.autoGrantOwner !== false,
      admissionHoldMs: this.server.gate ? this.server.gate.holdMs : null,
      metricsSampleIntervalMs: this.metrics.sampleIntervalMs,
    };
  }
}

function cookieValue(req, name) {
  const match = new RegExp(`(?:^|;\\s*)${name}=([^;]+)`).exec(req.headers.cookie || '');
  return match ? decodeURIComponent(match[1]) : null;
}

function expiredCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict`;
}

/**
 * A JSON literal safe to paste into a <script> block.
 *
 * JSON.stringify alone is not enough. Inside a script element the parser is still looking for
 * `</script`, and it finds it inside string literals too — a value containing `</script><img
 * onerror=…>` ends the block early and everything after it is markup. Escaping `<` removes the
 * only character that can start that sequence; U+2028/9 are escaped because they terminate a line
 * in JavaScript but not in JSON, which used to be a live syntax error in older engines.
 */
function jsonForScript(value) {
  return JSON.stringify(String(value == null ? '' : value))
    .replace(/</g, '\\u003c')
    // The separators are matched by escape rather than written literally: a raw U+2028 in this
    // file is invisible in every editor and survives exactly one careless copy-paste.
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      // A body limit on an admin API is not about abuse so much as about a mistake: a paste of
      // the wrong file into a form should fail fast rather than being buffered whole.
      if (size > 256 * 1024) {
        req.destroy();
        reject(new Error('request body is too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); }
      catch (err) { reject(new Error(`request body is not valid JSON: ${err.message}`)); }
    });
    req.on('error', reject);
  });
}

function createAdminServer(options) { return new AdminServer(options); }

module.exports = { AdminServer, createAdminServer };
