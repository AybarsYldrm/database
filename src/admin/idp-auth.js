'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

// Signing into the database's admin panel with the identity provider.
//
// The panel used to have exactly one credential: a random token printed at startup. That is fine
// for a break-glass path and wrong as the everyday one, for the reason this whole stack exists —
// a bearer token printed on a console is a second identity system. It has no owner, no expiry
// anyone tracks, no revocation, and it does not disappear when someone leaves. Every OTHER
// principal here is authenticated by the IdP; the panel being the exception is the exception that
// makes the rule meaningless.
//
// So the panel is an OAuth client like any other. An operator clicks through to the IdP, signs in
// there with whatever the IdP requires that day (password, WebAuthn, an emailed code), and comes
// back with a code the panel exchanges for a token. The IdP decides who is an admin; this file
// only checks the answer.
//
//
// WHY THE TOKEN STILL EXISTS
//
// Because the IdP can be down, and when it is, the database is the thing an operator most needs
// to look at. The dependency is real and cannot be argued away: the IdP is a distinct process, it
// can fail, and a panel that fails with it is a panel unavailable during exactly the incident it
// would help with. So the token stays as a break-glass path, printed once and written to a 0600
// file, and the panel says which of the two you used.
//
//
// WHY CONFIDENTIAL-CLIENT + PKCE, WHEN ONE WOULD DO
//
// PKCE (RFC 7636) is not optional here even though this is a confidential client with a secret.
// The redirect lands on a loopback address, which on a shared host any local process can race for
// by binding it first — and an authorization code intercepted there is useless without the
// verifier. The client secret protects the token endpoint; PKCE protects the redirect. They cover
// different attacks and neither substitutes for the other.
//
//
// WHY THE SESSION IS NOT A JWT
//
// The panel's session is a random id in a server-side Map. A self-contained token would survive a
// restart, which sounds like a feature and is not: this process holds no revocation list, so a
// stolen self-contained cookie would remain valid until it expired. An id in a Map dies with the
// process, and the process dying is the one recovery action an operator always has.

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;      // an operator's working day, then sign in again
const FLOW_TTL_MS = 10 * 60 * 1000;              // an in-flight redirect; RFC 6749 suggests 10 min
const MAX_PENDING_FLOWS = 64;

class IdpAuth {
  /**
   * @param {object}  opts
   * @param {string}  opts.issuer          e.g. https://session.fitfak.net
   * @param {string}  opts.clientId
   * @param {string}  opts.clientSecret
   * @param {string}  opts.redirectUri     must be registered at the IdP, e.g. http://127.0.2.1/auth/callback
   * @param {string} [opts.scope]
   * @param {string[]} [opts.requiredRoles=['admin']]
   * @param {object} [opts.logger]
   * @param {string} [opts.caPem]          trust anchor for the IdP's TLS, when it is privately issued
   */
  constructor({
    issuer, clientId, clientSecret, redirectUri,
    scope = 'openid profile email fitdb:admin',
    requiredRoles = ['admin'],
    logger = null, caPem = null,
  }) {
    if (!issuer) throw new Error('fitdb admin: IdP sign-in needs an issuer');
    if (!clientId || !clientSecret) throw new Error('fitdb admin: IdP sign-in needs client credentials');
    if (!redirectUri) throw new Error('fitdb admin: IdP sign-in needs a redirect URI');

    this.issuer = String(issuer).replace(/\/+$/, '');
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.scope = scope;
    this.requiredRoles = requiredRoles;
    this.caPem = caPem;
    this._log = logger;

    this._flows = new Map();     // state -> { verifier, createdAt }
    this._sessions = new Map();  // sid   -> { sub, username, role, scope, expiresAt, startedAt }
  }

  // ---- step 1: send the operator to the IdP -------------------------------------------------

  /**
   * Builds the authorization URL and remembers the verifier that goes with it.
   *
   * The state is the map key rather than something stored beside a cookie, so a callback carrying
   * a state this process never issued is rejected by a failed lookup — there is no branch where an
   * attacker-chosen state is compared against itself.
   */
  beginAuthorization() {
    this._sweep();
    if (this._flows.size >= MAX_PENDING_FLOWS) {
      // Every unfinished redirect holds a verifier. Unbounded, a loop hitting /auth/start would
      // grow this map without ever completing a flow.
      throw new Error('too many sign-ins in flight; wait for them to expire and try again');
    }

    const state = crypto.randomBytes(24).toString('base64url');
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    this._flows.set(state, { verifier, createdAt: Date.now() });

    const url = new URL(`${this.issuer}/oauth/authorize`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('scope', this.scope);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return { url: url.toString(), state };
  }

  // ---- step 2: the operator comes back ------------------------------------------------------

  /**
   * Exchanges the code, checks who came back, and opens a panel session.
   *
   * @returns {{ sid, session }}
   */
  async completeAuthorization({ code, state }) {
    this._sweep();
    const flow = state ? this._flows.get(state) : null;
    // Consumed whatever happens. A state that survives a failed exchange is a state that can be
    // retried, and the retry is the attacker's.
    if (state) this._flows.delete(state);
    if (!flow) throw new Error('unknown or expired sign-in attempt; start again from the panel');

    const tokens = await this._post('/oauth/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
      code_verifier: flow.verifier,
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });

    const accessToken = tokens.accessToken || tokens.access_token;
    if (!accessToken) throw new Error('the identity provider returned no access token');

    // Introspection rather than reading the token's own claims. This process has no copy of the
    // IdP's signing key and should not grow one: asking the issuer is both simpler and strictly
    // more correct, because it also answers "has this session been revoked since it was issued" —
    // which a signature check cannot.
    const claims = await this._post('/oauth/introspect', { token: accessToken }, {
      'x-client-id': this.clientId,
      'x-client-secret': this.clientSecret,
    });

    if (!claims.active) throw new Error('the identity provider rejected the token it just issued');

    const granted = String(claims.scope || '').split(/\s+/).filter(Boolean);
    if (this.scope.includes('fitdb:admin') && !granted.includes('fitdb:admin')) {
      throw new Error('this account was not granted the fitdb:admin scope');
    }
    if (this.requiredRoles.length && !this.requiredRoles.includes(claims.role)) {
      // Role and scope are checked separately on purpose. The scope says the operator agreed to
      // let the panel act for them; the role says the IdP considers them an administrator. A
      // consent screen cannot grant the second, which is exactly why it is not derived from it.
      throw new Error(`this account is '${claims.role || 'unknown'}', which cannot administer the database`);
    }

    const sid = crypto.randomBytes(32).toString('base64url');
    const session = {
      sub: claims.sub,
      username: claims.username || claims.preferred_username || claims.sub,
      role: claims.role || null,
      scope: claims.scope || '',
      idpSessionId: claims.sid || null,
      startedAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL_MS,
      via: 'idp',
    };
    this._sessions.set(sid, session);
    this._log?.info?.({
      subject: claims.sub, username: session.username, msg: 'operator signed in through the identity provider',
    });
    return { sid, session };
  }

  // ---- sessions -----------------------------------------------------------------------------

  resolveSession(sid) {
    if (!sid) return null;
    const session = this._sessions.get(sid);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) { this._sessions.delete(sid); return null; }
    return session;
  }

  endSession(sid) { return this._sessions.delete(sid); }

  status() {
    return {
      issuer: this.issuer,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      scope: this.scope,
      activeSessions: this._sessions.size,
      pendingFlows: this._flows.size,
    };
  }

  _sweep() {
    const now = Date.now();
    for (const [state, flow] of this._flows) {
      if (now - flow.createdAt > FLOW_TTL_MS) this._flows.delete(state);
    }
    for (const [sid, session] of this._sessions) {
      if (session.expiresAt <= now) this._sessions.delete(sid);
    }
  }

  // ---- transport ----------------------------------------------------------------------------

  /**
   * A form-encoded POST to the IdP, returning parsed JSON.
   *
   * Hand-rolled rather than pulling in a client, because this is two requests against one known
   * peer and the failure mode that matters is the one a library would hide: a body that is not
   * JSON. That happens when a proxy answers instead of the IdP, and reporting it as "unexpected
   * token < in JSON" would send an operator looking in the wrong process.
   */
  _post(pathname, form, extraHeaders = {}) {
    const url = new URL(this.issuer + pathname);
    const isJson = pathname === '/oauth/introspect';
    const body = isJson ? JSON.stringify(form) : new URLSearchParams(form).toString();
    const transport = url.protocol === 'http:' ? http : https;

    return new Promise((resolve, reject) => {
      const req = transport.request({
        hostname: url.hostname,
        port: url.port || (url.protocol === 'http:' ? 80 : 443),
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'content-type': isJson ? 'application/json' : 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body),
          accept: 'application/json',
          ...extraHeaders,
        },
        // When the IdP's certificate comes from its own root — which it does, that root is the
        // one this database trusts for everything else — the system store knows nothing about it.
        ...(this.caPem ? { ca: this.caPem } : {}),
        timeout: 10_000,
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > 256 * 1024) { req.destroy(new Error('identity provider response is too large')); return; }
          chunks.push(chunk);
        });
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed;
          try { parsed = JSON.parse(raw); } catch (_) {
            return reject(new Error(
              `${pathname} returned ${res.statusCode} with a non-JSON body (${raw.slice(0, 120)}). `
              + 'Something other than the identity provider is answering this address.',
            ));
          }
          if (res.statusCode >= 400) {
            return reject(new Error(
              `${pathname} failed: ${parsed.error || res.statusCode}`
              + `${parsed.error_description ? ` — ${parsed.error_description}` : ''}`,
            ));
          }
          resolve(parsed);
        });
      });
      req.on('timeout', () => req.destroy(new Error(`${pathname} timed out after 10s`)));
      req.on('error', reject);
      req.end(body);
    });
  }
}

function createIdpAuth(options) { return new IdpAuth(options); }

module.exports = { IdpAuth, createIdpAuth, SESSION_TTL_MS };
