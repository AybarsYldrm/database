'use strict';

const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

const { EnrolmentDenied } = require('./attestor');

// The database as an identity client of the IdP.
//
// createTokenAttestor takes a `verify` function and asks nothing about where the answer comes
// from. This is that function for an OAuth 2.0 IdP: the enrolling peer presents an access
// token it already holds, and the database asks the IdP's introspection endpoint (RFC 7662)
// what that token actually is.
//
// This is the half of the loop that closes it. The IdP's own first enrolment uses a shared
// secret, because at that moment there is no IdP to ask. Once it is up, every service after it
// enrols with an IdP-issued token, and the shared-secret path can stay switched off. That is
// the whole point of the composite attestor: one endpoint, two eras.
//
// What a token may become is deliberately narrow. An access token proves the caller holds a
// grant; it does not decide what certificate identity that grant maps to. If it did, anyone
// able to mint a token with an arbitrary `sub` could name themselves any principal in the
// system. So the mapping from token to identity happens HERE, against configuration, and the
// token only selects among identities the operator already wrote down.

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * @param {object}   opts
 * @param {string}   opts.introspectionUrl   e.g. 'https://session.fitfak.net/oauth/introspect'
 * @param {string}   opts.clientId           this database's own OAuth client id
 * @param {string}   opts.clientSecret       its secret, used to authenticate to the IdP
 * @param {object}   opts.services           serviceName -> { requiredScope, subject, altNames, roles, validityDays }
 * @param {number}  [opts.timeoutMs]
 * @param {function}[opts.fetchImpl]         injectable for tests
 */
function createIdpTokenAttestor({
  introspectionUrl, clientId, clientSecret, services,
  timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = null, name = 'idp-token', logger = null,
}) {
  if (!introspectionUrl) throw new Error('fitdb enrol: createIdpTokenAttestor requires an introspectionUrl');
  if (!services || Object.keys(services).length === 0) {
    // Without a service map the attestor would have to trust the token to name its own
    // identity, which is exactly the escalation this design is shaped to prevent.
    throw new Error('fitdb enrol: createIdpTokenAttestor requires a `services` map; a token must '
      + 'not be able to choose which identity it becomes');
  }

  const introspect = fetchImpl || defaultIntrospect({ introspectionUrl, clientId, clientSecret, timeoutMs });

  return {
    name,

    async attest({ request }) {
      const { token, serviceName } = request;
      if (!token) throw new EnrolmentDenied('enrolment request is missing a token');
      if (!serviceName) throw new EnrolmentDenied('enrolment request is missing a serviceName');

      const entry = services[serviceName];
      // Same message for an unknown service as for a rejected token: telling an
      // unauthenticated caller which service names exist is free reconnaissance.
      if (!entry) throw new EnrolmentDenied('enrolment rejected');

      let introspection;
      try {
        introspection = await introspect(token);
      } catch (err) {
        // An IdP that is down must not read as "token invalid" -- that would let an outage
        // silently become an authorisation decision, and the operator would see denials
        // rather than an unreachable dependency.
        logger?.warn?.(`[enrol] token introspection failed: ${err.message}`);
        throw new EnrolmentDenied(`identity provider unreachable: ${err.message}`);
      }

      if (!introspection || introspection.active !== true) {
        throw new EnrolmentDenied('enrolment rejected');
      }

      // Scope is what distinguishes "a valid token" from "a token allowed to do this". Any
      // logged-in user holds a valid token; only a token carrying the required scope may
      // enrol a service identity.
      const scopes = String(introspection.scope || '').split(/\s+/).filter(Boolean);
      if (entry.requiredScope && !scopes.includes(entry.requiredScope)) {
        throw new EnrolmentDenied('enrolment rejected');
      }

      // An expiry in the past passed off as active is an IdP bug, but it costs one comparison
      // to not depend on the IdP being right about it.
      if (introspection.exp && Number(introspection.exp) * 1000 < Date.now()) {
        throw new EnrolmentDenied('enrolment rejected');
      }

      logger?.info?.(`[enrol] token accepted for '${serviceName}' (sub=${introspection.sub || 'unknown'})`);

      return {
        principal: serviceName,
        // From configuration, never from the token. The token says the caller is entitled;
        // this table says what they are entitled to become.
        subject: entry.subject || { CN: serviceName },
        altNames: entry.altNames || [],
        roles: entry.roles || [],
        validityDays: entry.validityDays,
        idpSubject: introspection.sub || null,
      };
    },
  };
}

function defaultIntrospect({ introspectionUrl, clientId, clientSecret, timeoutMs }) {
  return (token) => new Promise((resolve, reject) => {
    const url = new URL(introspectionUrl);
    const body = JSON.stringify({ token });
    const transport = url.protocol === 'http:' ? http : https;

    const req = transport.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-client-id': clientId || '',
        'x-client-secret': clientSecret || '',
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(new Error(`introspection returned HTTP ${res.statusCode}`));
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (err) { reject(new Error(`introspection returned malformed JSON: ${err.message}`)); }
      });
    });

    req.on('timeout', () => { req.destroy(new Error(`introspection timed out after ${timeoutMs}ms`)); });
    req.on('error', reject);
    req.end(body);
  });
}

module.exports = { createIdpTokenAttestor };
