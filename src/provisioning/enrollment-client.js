'use strict';

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { GrpcClient } = require('@fitfak/grpc');

const { ENROLMENT_SCHEMAS } = require('./enrollment-service');
const { computeEnrolmentProof } = require('./attestor');

// The enrolling side of the bootstrap flow, and the thing that makes "connect without a
// certificate, then connect with one" a supported operation rather than a manual dance:
//
//   1. Open a server-authenticated TLS channel.           <- no client certificate yet
//   2. Establish that this really is the right server.    <- CA bundle, or a pinned fingerprint
//   3. Fetch the trust anchors.
//   4. Generate a key pair and a CSR (the key never leaves this process).
//   5. Prove entitlement, bound to this TLS session and to this CSR.
//   6. Receive a certificate.
//   7. Upgrade the same client object to mTLS.            <- everything after this is mutual
//   8. Renew over mTLS, well before expiry.
//
// Step 2 is the one worth dwelling on. Until the peer has a certificate it has nothing to
// authenticate *with*, but it still has to authenticate the server it is about to hand an
// enrolment credential to -- otherwise the first connection is an open invitation to anyone
// who can answer on that address. So one of three things must be true, and there is no
// silent fourth option: the caller supplies the CA bundle out of band, or supplies a
// fingerprint to pin, or explicitly opts into trust-on-first-use knowing what that means.

const DEFAULT_ENROLMENT_PATHS = {
  getTrustAnchors: '/custom.network.EnrollmentService/GetTrustAnchors',
  enroll: '/custom.network.EnrollmentService/Enroll',
  reenroll: '/custom.network.EnrollmentService/Reenroll',
};

class TrustError extends Error {
  constructor(message) { super(message); this.name = 'TrustError'; }
}

/**
 * A certificate obtained by enrolment, plus everything needed to keep it current.
 *
 * `client` is a live GrpcClient already upgraded to mTLS -- callers use it directly rather
 * than building a second one, which also means there is exactly one place that knows how to
 * swap the credentials when a renewal lands.
 */
class ManagedIdentity extends EventEmitter {
  constructor({ client, credentials, certPem, privateKeyPem, chainPem, principal, roles, notAfter, renewAfter, enroller }) {
    super();
    this.client = client;
    this.credentials = credentials;
    this.certPem = certPem;
    this.privateKeyPem = privateKeyPem;
    this.chainPem = chainPem;
    this.principal = principal;
    this.roles = roles;
    this.notAfter = notAfter;
    this.renewAfter = renewAfter;
    this._enroller = enroller;
    this._renewalTimer = null;
  }

  get expiresInMs() { return this.notAfter - Date.now(); }

  /**
   * Renews over the existing mTLS channel and upgrades the client onto the new certificate.
   * Failure is non-destructive: the current certificate keeps working until it actually
   * expires, so a transient CA outage does not take the service down.
   */
  async renew() {
    const renewed = await this._enroller.reenroll(this);
    Object.assign(this, renewed);
    await this.client.upgrade(this.credentials);
    this.emit('renewed', { principal: this.principal, notAfter: this.notAfter });
    return this;
  }

  /**
   * Schedules renewal at the server-advertised `renewAfter`, which sits at roughly two thirds
   * of the certificate's lifetime -- early enough that a failure leaves time for several more
   * attempts before anything expires.
   */
  startAutoRenewal({ retryMs = 60 * 60 * 1000, maxTimerMs = 24 * 60 * 60 * 1000 } = {}) {
    this.stopAutoRenewal();
    const schedule = () => {
      // setTimeout silently fires immediately past ~24.8 days, so a long-lived certificate
      // needs the wait broken into chunks rather than one enormous timer.
      const untilRenewal = Math.max(0, this.renewAfter - Date.now());
      const delay = Math.min(untilRenewal, maxTimerMs);
      this._renewalTimer = setTimeout(async () => {
        if (Date.now() < this.renewAfter) return schedule();
        try { await this.renew(); }
        catch (err) {
          this.emit('renewalFailed', err);
          this._renewalTimer = setTimeout(schedule, retryMs);
          this._renewalTimer.unref?.();
          return;
        }
        schedule();
      }, delay);
      this._renewalTimer.unref?.();
    };
    schedule();
    return this;
  }

  stopAutoRenewal() {
    if (this._renewalTimer) { clearTimeout(this._renewalTimer); this._renewalTimer = null; }
    return this;
  }

  close() {
    this.stopAutoRenewal();
    this.client.close();
  }
}

/**
 * Runs the bootstrap flow and returns a ManagedIdentity whose `client` is already on mTLS.
 *
 * @param {object}   opts
 * @param {string}   opts.target        e.g. 'https://db.internal:8443'
 * @param {string}   opts.serviceName   the identity being claimed
 * @param {object}   opts.csrProvider   see csr-provider.js
 * @param {object}   opts.trust         { caPem } | { pinnedFingerprints } | { trustOnFirstUse: true }
 * @param {object}  [opts.bootstrap]    { secret } for the shared-secret attestor, or { token }
 * @param {object}  [opts.subject]      defaults to { CN: serviceName }
 * @param {string[]}[opts.altNames]
 * @param {object}  [opts.clientOptions] passed through to GrpcClient
 * @param {object}  [opts.paths]        override the service paths
 */
async function enroll({
  target, serviceName, csrProvider, trust = {}, bootstrap = {},
  subject = null, altNames = [], clientOptions = {}, paths = {}, logger = null,
}) {
  if (!target) throw new Error('fitdb enrol: target is required');
  if (!serviceName) throw new Error('fitdb enrol: serviceName is required');
  if (!csrProvider) throw new Error('fitdb enrol: a csrProvider is required (see createFitfakSslCsrProvider)');

  const routes = { ...DEFAULT_ENROLMENT_PATHS, ...paths };
  const log = logger || null;
  const { caPem, pinnedFingerprints = [], trustOnFirstUse = false } = trust;

  if (!caPem && pinnedFingerprints.length === 0 && !trustOnFirstUse) {
    throw new TrustError(
      'fitdb enrol: refusing to bootstrap without a way to authenticate the server. '
      + 'Supply trust.caPem (preferred), trust.pinnedFingerprints, or set trust.trustOnFirstUse '
      + 'if you accept that the first connection is unverified.',
    );
  }

  // With a CA bundle, Node validates the chain during the handshake and there is nothing more
  // to do. Without one, the handshake cannot be validated, so verification has to happen
  // immediately afterwards -- and crucially BEFORE any enrolment credential is transmitted.
  const verifiedByTls = !!caPem;
  const client = new GrpcClient(target, {
    ...clientOptions,
    credentials: verifiedByTls
      ? { ...(clientOptions.credentials || {}), ca: caPem }
      : { ...(clientOptions.credentials || {}), rejectUnauthorized: false },
  });

  await client.connect();

  const channel = client.channelInfo();
  const pins = pinnedFingerprints.map(normalizeFingerprint);
  const matchesPin = (value) => pins.includes(normalizeFingerprint(value));

  // Fetching trust anchors is safe against an unverified peer: they are public data and the
  // request carries no credential. Everything after this point does, so verification has to
  // be settled before then -- which is the only ordering constraint that matters here.
  const anchors = await client.unary(routes.getTrustAnchors, ENROLMENT_SCHEMAS,
    'EnrollmentService_GetTrustAnchorsReq', 'EnrollmentService_GetTrustAnchorsRes', {});

  if (!verifiedByTls) {
    if (pins.length > 0) {
      // A pin may name the leaf or the CA. Pinning the CA is usually what you want: it
      // survives a legitimate server-certificate rotation, which a leaf pin does not.
      const leafMatch = matchesPin(channel.serverFingerprint256);
      const anchorMatch = (anchors.fingerprints || []).some(matchesPin);
      if (!leafMatch && !anchorMatch) {
        client.close();
        throw new TrustError(
          `fitdb enrol: the server presented ${channel.serverFingerprint256} with anchors `
          + `[${(anchors.fingerprints || []).join(', ')}], none of which match the pinned fingerprints. `
          + 'No enrolment credential was sent.',
        );
      }
      log?.info?.(`[enrol] server verified against a pinned ${leafMatch ? 'certificate' : 'trust anchor'}`);
    } else {
      log?.warn?.(
        `[enrol] TRUST ON FIRST USE: accepting ${channel.serverFingerprint256} from ${target} without verification. `
        + 'Pin this fingerprint or supply the CA out of band before doing this in production.',
      );
    }
  }

  const keyPair = await csrProvider.generateKeyPair();
  const csrSubject = subject || { CN: serviceName };
  const csrPem = await csrProvider.createCsr({ keyPair, subject: csrSubject, altNames });

  const request = buildEnrolmentRequest({ serviceName, csrPem, bootstrap, client });
  const issued = await client.unary(routes.enroll, ENROLMENT_SCHEMAS,
    'EnrollmentService_EnrollReq', 'EnrollmentService_EnrollRes', request);

  const chainPem = issued.chainPem && issued.chainPem.length ? issued.chainPem : anchors.chainPem;
  const credentials = {
    key: keyPair.privateKeyPem,
    cert: [issued.certPem, ...chainPem.slice(0, -1)].join(''),
    // From here on the server is validated against the anchors it just handed us over a
    // channel we had already authenticated, so the upgraded connection is verified properly
    // even if the bootstrap leg was pinned or trust-on-first-use.
    ca: chainPem.join(''),
    rejectUnauthorized: true,
  };

  await client.upgrade(credentials);
  log?.info?.(`[enrol] '${issued.principal}' enrolled; channel upgraded to mTLS`);

  const enroller = { reenroll: (identity) => reenroll({ identity, csrProvider, routes, subject: csrSubject, altNames, logger: log }) };

  return new ManagedIdentity({
    client,
    credentials,
    certPem: issued.certPem,
    privateKeyPem: keyPair.privateKeyPem,
    chainPem,
    principal: issued.principal,
    roles: issued.roles || [],
    notAfter: Number(issued.notAfter),
    renewAfter: Number(issued.renewAfter),
    enroller,
  });
}

/**
 * Renewal over the already-authenticated channel. A fresh key pair is generated rather than
 * re-certifying the old one: if the previous key was ever exposed, renewing onto it would
 * carry the exposure forward for another full lifetime.
 */
async function reenroll({ identity, csrProvider, routes = DEFAULT_ENROLMENT_PATHS, subject = null, altNames = [], logger = null }) {
  const keyPair = await csrProvider.generateKeyPair();
  const csrPem = await csrProvider.createCsr({
    keyPair,
    subject: subject || { CN: identity.principal },
    altNames,
  });

  const issued = await identity.client.unary(routes.reenroll, ENROLMENT_SCHEMAS,
    'EnrollmentService_ReenrollReq', 'EnrollmentService_ReenrollRes',
    { serviceName: identity.principal, csrPem, method: 'mtls-renewal' });

  const chainPem = issued.chainPem && issued.chainPem.length ? issued.chainPem : identity.chainPem;
  logger?.info?.(`[enrol] renewed '${issued.principal}' until ${new Date(Number(issued.notAfter)).toISOString()}`);

  return {
    credentials: {
      key: keyPair.privateKeyPem,
      cert: [issued.certPem, ...chainPem.slice(0, -1)].join(''),
      ca: chainPem.join(''),
      rejectUnauthorized: true,
    },
    certPem: issued.certPem,
    privateKeyPem: keyPair.privateKeyPem,
    chainPem,
    principal: issued.principal,
    roles: issued.roles || [],
    notAfter: Number(issued.notAfter),
    renewAfter: Number(issued.renewAfter),
  };
}

function buildEnrolmentRequest({ serviceName, csrPem, bootstrap, client }) {
  const request = { serviceName, csrPem, method: bootstrap.method || '' };

  if (bootstrap.token) {
    request.token = bootstrap.token;
    return request;
  }

  if (!bootstrap.secret) {
    throw new Error('fitdb enrol: bootstrap needs either a `secret` (shared-secret attestor) or a `token`');
  }

  const channelBinding = client.channelBinding();
  if (!channelBinding) {
    // Proceeding unbound would silently drop the protection that stops a TLS-terminating
    // proxy from replaying this proof, so it fails loudly instead.
    throw new Error(
      'fitdb enrol: this TLS connection cannot export channel binding material (RFC 9266), '
      + 'so the enrolment proof cannot be bound to it. Use TLS 1.3, or configure the server\'s '
      + 'attestor with requireChannelBinding:false if you accept the replay exposure.',
    );
  }

  const nonce = crypto.randomBytes(16).toString('base64');
  const timestamp = Date.now();
  request.nonce = nonce;
  request.timestamp = BigInt(timestamp);
  request.proof = computeEnrolmentProof(bootstrap.secret, {
    serviceName, nonce, timestamp, channelBinding, csrPem,
  }).toString('base64');
  return request;
}

function normalizeFingerprint(value) {
  return String(value || '').replace(/:/g, '').toLowerCase();
}

module.exports = { enroll, reenroll, ManagedIdentity, TrustError, DEFAULT_ENROLMENT_PATHS };
