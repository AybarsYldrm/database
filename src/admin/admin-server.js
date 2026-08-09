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
// WHY THIS IS NOT AS ALARMING AS "PLAIN HTTP ADMIN PANEL" SOUNDS, AND WHERE IT STILL IS
//
// The bind address is the primary control. 127.0.2.1 is reachable only from this host, so the
// question "who can use this panel" reduces to "who can run code on this machine" — and anyone
// who can run code on this machine can already read the database's memory, which is strictly
// worse than anything the panel offers.
//
// That is a real boundary, but it is not the whole story, so there is a token as well:
//
//   - a local process is not necessarily a TRUSTED local process. A build agent, a sidecar, a
//     compromised dependency in some unrelated service on the same box — all of them can reach
//     a loopback port.
//   - a browser on this host can be steered to a loopback URL by any page the operator visits.
//     The token stops a drive-by POST; the same-origin check stops the rest.
//
// The token is generated at startup and printed once. It is not a password: it is a bearer
// credential for a process-lifetime session, and rotating it means restarting.
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

const LOOPBACK = /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|localhost)$/;

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
   */
  constructor({
    server, metrics, registry, host = '127.0.2.1', port = 80,
    token = null, allowNonLoopback = false, info = {}, logger = null,
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
    this.token = token || crypto.randomBytes(24).toString('base64url');
    this.origin = `http://${host}${port === 80 ? '' : `:${port}`}`;
    this.http = null;

    // Read once at startup rather than per request: it is a file this process ships with, and
    // re-reading it on every load would turn a panel refresh into disk I/O on the database host.
    this._panel = fs.readFileSync(PANEL_FILE, 'utf8');
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

    // The panel itself is served with the token in the query string, and immediately sets it as
    // a cookie so it does not stay in the address bar — the same reasoning as the device-code
    // link in the IdP: a URL ends up in history, in a screenshot, and over someone's shoulder.
    if (pathname === '/' && req.method === 'GET') {
      const supplied = url.searchParams.get('token');
      if (!this._tokenMatches(supplied)) return this._unauthorized(res);
      res.statusCode = 200;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      res.setHeader('cache-control', 'no-store');
      res.setHeader('x-content-type-options', 'nosniff');
      res.setHeader('x-frame-options', 'DENY');
      res.setHeader('referrer-policy', 'no-referrer');
      res.setHeader('set-cookie',
        `fitdb_admin=${encodeURIComponent(this.token)}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict`);
      return res.end(this._panel);
    }

    if (!pathname.startsWith('/api/')) return send(res, 404, { error: 'not_found' });

    if (!this._tokenMatches(this._suppliedToken(req, url))) return this._unauthorized(res);

    // Every state change is same-origin checked. The token alone is not enough: a page the
    // operator visits could hold a stale token from a shared screenshot and fire a POST at
    // loopback. `Origin` is set by the browser and cannot be forged by page script.
    if (req.method === 'POST') {
      const origin = req.headers.origin;
      if (origin && origin !== this.origin) {
        return send(res, 403, { error: 'cross_origin', error_description: `refusing a POST from ${origin}` });
      }
    }

    const body = req.method === 'POST' ? await readJson(req) : {};
    const result = await this._route(pathname, req.method, body, url);
    if (result === undefined) return send(res, 404, { error: 'not_found' });
    return send(res, 200, result);
  }

  _suppliedToken(req, url) {
    const header = req.headers['x-admin-token'];
    if (header) return String(header);
    const cookie = /(?:^|;\s*)fitdb_admin=([^;]+)/.exec(req.headers.cookie || '');
    if (cookie) return decodeURIComponent(cookie[1]);
    return url.searchParams.get('token');
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
      error_description: 'An admin token is required. It is printed once when the database starts.',
    });
  }

  // ---- routes -----------------------------------------------------------------------------

  async _route(pathname, method, body, url) {
    const route = `${method} ${pathname}`;

    switch (route) {
      case 'GET /api/overview':
        return this._overview();

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

  _overview() {
    const summary = this.metrics.summary();
    const gate = this.server.gate ? this.server.gate.status() : null;
    return {
      summary,
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
      usage: usage.get(service.name) || null,
    }));

    // A principal that has connected but is not in the registry should be visible, not hidden.
    // In a correctly configured deployment there is exactly one — the identity provider, which
    // is admitted by the admission gate rather than by the enrolment registry — and anything
    // else appearing here is worth an operator's attention.
    for (const [principal, entry] of usage) {
      if (known.has(principal)) continue;
      rows.push({
        name: principal,
        spiffeId: entry.spiffeId,
        roles: [],
        altNames: [],
        registered: false,
        enabled: true,
        usage: entry,
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
