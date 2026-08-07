'use strict';

const crypto = require('node:crypto');
const { GRPC_STATUS, GrpcError, SECURITY_LEVELS } = require('@fitfak/grpc');

// The handover that unseals a database.
//
// A sealed database has an ephemeral self-signed identity and no trust anchors, so it cannot
// validate anybody and nobody should trust it. This service is the one thing reachable in that
// state, and it does exactly one job: let the identity provider install the certificate, key and
// trust anchors that the database will serve from then on.
//
// The direction is worth stating plainly, because it is the opposite of the usual arrangement:
// the database does not go and fetch a certificate, and it does not mint one for itself. The IdP
// -- which owns the root -- pushes one in. That is what keeps the database from having a PKI of
// its own. It has a key because someone gave it one, and it can lose the ability to serve simply
// by being sealed again.
//
//
// AUTHENTICATION IN BOTH DIRECTIONS
//
// The channel here is server-authenticated by a certificate nobody has a reason to trust, so the
// TLS layer alone establishes nothing. Both sides authenticate with a pre-shared bootstrap
// secret, and both directions matter for different reasons:
//
//   client -> server   without it, anyone who can reach the port can install a server identity
//                      and the database will serve an attacker's certificate.
//
//   server -> client   without it, an interceptor terminates TLS, receives the certificate AND
//                      PRIVATE KEY the IdP meant for the database, and can impersonate the
//                      database to the IdP from then on. This is the direction a naive design
//                      forgets, and forgetting it is fatal: the bootstrap message carries a
//                      private key, so an unauthenticated peer is being handed the keys to the
//                      thing it is pretending to be.
//
// Both proofs are HMACs over a transcript that includes the TLS exporter value (RFC 9266
// tls-exporter channel binding). That is what stops an interceptor from forwarding either proof:
// it holds two TLS sessions with two different exporter values, so a proof computed for one
// leg does not verify on the other.
//
// The transcript also covers a hash of the material being installed. Without that, an
// interceptor who cannot forge a proof could still keep a valid one and substitute a
// certificate and key of their own choosing -- the proof would say "the IdP authorised an
// installation", which is true, and say nothing about what was installed.
//
// Both nonces, the timestamp and the single-use nonce record bound to the connection's exporter
// value close the replay window from three directions: a captured message is refused because
// the nonce is spent, because the timestamp is stale, and because the exporter value belongs to
// a session the replayer does not have.

const CONTROL_SCHEMAS = {
  ControlPlaneService_ChallengeReq: [
    { no: 1, name: 'clientNonce', type: 'string' },
  ],
  ControlPlaneService_ChallengeRes: [
    { no: 1, name: 'state', type: 'string' },
    { no: 2, name: 'serverNonce', type: 'string' },
    // HMAC proving this endpoint holds the bootstrap secret, bound to this TLS session.
    { no: 3, name: 'serverConfirmation', type: 'string' },
    { no: 4, name: 'bootstrapFingerprint', type: 'string' },
    { no: 5, name: 'channelBindingSupported', type: 'bool' },
    { no: 6, name: 'serverName', type: 'string' },
    { no: 7, name: 'holdMs', type: 'int64' },
  ],
  ControlPlaneService_InstallReq: [
    { no: 1, name: 'serverNonce', type: 'string' },
    { no: 2, name: 'timestamp', type: 'int64' },
    { no: 3, name: 'proof', type: 'string' },
    { no: 4, name: 'certPem', type: 'string' },
    { no: 5, name: 'privateKeyPem', type: 'string' },
    { no: 6, name: 'chainPem', type: 'string', repeated: true },
    // What this database will validate CLIENT certificates against from now on. Delivered by
    // the IdP rather than configured locally, because "whose certificates do I believe" is the
    // same question as "who is my identity provider", and it should have one answer.
    { no: 7, name: 'trustAnchorsPem', type: 'string', repeated: true },
    { no: 8, name: 'controlSpiffeId', type: 'string' },
  ],
  ControlPlaneService_InstallRes: [
    { no: 1, name: 'installed', type: 'bool' },
    { no: 2, name: 'state', type: 'string' },
    { no: 3, name: 'holdExpiresAt', type: 'int64' },
    { no: 4, name: 'fingerprint256', type: 'string' },
  ],
  ControlPlaneService_StatusReq: [],
  ControlPlaneService_StatusRes: [
    { no: 1, name: 'state', type: 'string' },
    { no: 2, name: 'controlPrincipal', type: 'string' },
    { no: 3, name: 'provisionedAt', type: 'int64' },
    { no: 4, name: 'openedAt', type: 'int64' },
    { no: 5, name: 'holdExpiresAt', type: 'int64' },
    { no: 6, name: 'subject', type: 'string' },
    { no: 7, name: 'notAfter', type: 'int64' },
  ],
};

const CONFIRM_CONTEXT = 'fitdb-control-server-confirm-v1';
const INSTALL_CONTEXT = 'fitdb-control-install-v1';

const DEFAULT_CLOCK_SKEW_MS = 60_000;
const NONCE_TTL_MS = 120_000;

function field(value) {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? ''), 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(buf.length);
  // Length-prefixed rather than delimiter-separated: with a delimiter, a caller who controls
  // two adjacent fields can move the boundary between them and produce the same transcript from
  // different values. Prefixing the length makes the encoding injective.
  return Buffer.concat([length, buf]);
}

/** The bytes both sides HMAC when the server proves it holds the bootstrap secret. */
function confirmTranscript({ clientNonce, serverNonce, channelBinding }) {
  return Buffer.concat([
    field(CONFIRM_CONTEXT), field(clientNonce), field(serverNonce), field(channelBinding || Buffer.alloc(0)),
  ]);
}

/** The bytes both sides HMAC when the client installs a server identity. */
function installTranscript({
  serverNonce, timestamp, channelBinding, certPem, privateKeyPem, chainPem, trustAnchorsPem, controlSpiffeId,
}) {
  const materialHash = crypto.createHash('sha256').update(Buffer.concat([
    field(certPem), field(privateKeyPem),
    field((chainPem || []).join('\n')),
    field((trustAnchorsPem || []).join('\n')),
    field(controlSpiffeId || ''),
  ])).digest();

  return Buffer.concat([
    field(INSTALL_CONTEXT), field(serverNonce), field(String(timestamp)),
    field(channelBinding || Buffer.alloc(0)), field(materialHash),
  ]);
}

function computeServerConfirmation(secret, parts) {
  return crypto.createHmac('sha256', secret).update(confirmTranscript(parts)).digest();
}

function computeInstallProof(secret, parts) {
  return crypto.createHmac('sha256', secret).update(installTranscript(parts)).digest();
}

function timingSafeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * @param {object}   opts
 * @param {Buffer}   opts.bootstrapSecret   pre-shared with the identity provider, out of band
 * @param {object}   opts.gate              the AdmissionGate this service drives
 * @param {string}  [opts.serverName]       advertised for diagnostics
 * @param {function}[opts.bootstrapFingerprint] () => string, for a client that pins
 * @param {boolean} [opts.requireChannelBinding=true]
 * @param {number}  [opts.clockSkewMs]
 * @param {function}[opts.onTrustAnchors]   (pemArray) => void, so the server can start
 *                                          validating client certificates against them
 */
function createControlPlaneService({
  bootstrapSecret,
  gate,
  serverName = '',
  bootstrapFingerprint = null,
  requireChannelBinding = true,
  clockSkewMs = DEFAULT_CLOCK_SKEW_MS,
  onTrustAnchors = null,
  logger = null,
} = {}) {
  if (!Buffer.isBuffer(bootstrapSecret) || bootstrapSecret.length < 32) {
    throw new Error('fitdb control: createControlPlaneService requires a bootstrapSecret of at '
      + 'least 32 bytes (crypto.randomBytes(32)); it is the only thing authenticating the '
      + 'exchange that installs this server\'s identity');
  }
  if (!gate) throw new Error('fitdb control: createControlPlaneService requires an admission gate');

  const log = logger || null;
  const nonces = new Map(); // serverNonce -> { channelBinding, expiresAt }

  function pruneNonces() {
    const now = Date.now();
    for (const [nonce, entry] of nonces) if (entry.expiresAt < now) nonces.delete(nonce);
  }

  const controller = {
    /**
     * Step one. The client sends a nonce, the server answers with its own plus a confirmation
     * that it holds the bootstrap secret. Nothing sensitive has moved yet, and the client can
     * abandon the exchange here if the confirmation does not verify -- which is the whole point
     * of doing it in this order.
     */
    GetBootstrapChallenge: {
      kind: 'unary',
      minSecurityLevel: SECURITY_LEVELS.TLS,
      schemas: CONTROL_SCHEMAS,
      requestType: 'ControlPlaneService_ChallengeReq',
      responseType: 'ControlPlaneService_ChallengeRes',
      handler: async (req, call) => {
        const channelBinding = call.peer.channelBinding;
        if (requireChannelBinding && (!channelBinding || channelBinding.length === 0)) {
          throw new GrpcError(GRPC_STATUS.FAILED_PRECONDITION,
            'the control plane requires TLS channel binding (RFC 9266), which this connection '
            + 'cannot provide');
        }
        if (!req.clientNonce) {
          throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'a clientNonce is required');
        }

        pruneNonces();
        const serverNonce = crypto.randomBytes(32).toString('base64');
        // Bound to this connection's exporter value. The install call has to arrive on the same
        // TLS session, so a nonce observed on one connection is useless on another.
        nonces.set(serverNonce, {
          channelBinding: channelBinding ? Buffer.from(channelBinding) : Buffer.alloc(0),
          expiresAt: Date.now() + NONCE_TTL_MS,
        });

        return {
          state: gate.state,
          serverNonce,
          serverConfirmation: computeServerConfirmation(bootstrapSecret, {
            clientNonce: req.clientNonce, serverNonce, channelBinding,
          }).toString('base64'),
          bootstrapFingerprint: typeof bootstrapFingerprint === 'function' ? (bootstrapFingerprint() || '') : (bootstrapFingerprint || ''),
          channelBindingSupported: !!channelBinding,
          serverName,
          holdMs: BigInt(gate.holdMs || 0),
        };
      },
    },

    /**
     * Step two. The identity provider installs the certificate, key and trust anchors. On
     * success the gate moves to PROVISIONED and starts its hold timer; the database is still
     * closed to everyone until the IdP comes back over mTLS.
     */
    InstallServerIdentity: {
      kind: 'unary',
      minSecurityLevel: SECURITY_LEVELS.TLS,
      schemas: CONTROL_SCHEMAS,
      requestType: 'ControlPlaneService_InstallReq',
      responseType: 'ControlPlaneService_InstallRes',
      handler: async (req, call) => {
        const channelBinding = call.peer.channelBinding;

        pruneNonces();
        const record = nonces.get(req.serverNonce);
        // Burned before anything else is checked. A nonce exists to make one message
        // unrepeatable, and that has to hold whether the message goes on to succeed or fail --
        // otherwise a rejected attempt leaves a live nonce for the next attacker.
        if (record) nonces.delete(req.serverNonce);
        if (!record) throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'provisioning rejected');

        if (requireChannelBinding && !timingSafeEqual(record.channelBinding, Buffer.from(channelBinding || []))) {
          throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'provisioning rejected');
        }

        const age = Math.abs(Date.now() - Number(req.timestamp || 0));
        if (!Number.isFinite(age) || age > clockSkewMs) {
          throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'provisioning rejected');
        }

        if (!req.certPem || !req.privateKeyPem) {
          throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'a certificate and private key are required');
        }
        if (!req.trustAnchorsPem || req.trustAnchorsPem.length === 0) {
          // Installing a server identity without anchors would leave the database serving a real
          // certificate while still unable to validate a single client -- it would look
          // provisioned and authenticate nobody.
          throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT,
            'trust anchors are required: without them this database cannot validate any client certificate');
        }

        const expected = computeInstallProof(bootstrapSecret, {
          serverNonce: req.serverNonce,
          timestamp: req.timestamp,
          channelBinding,
          certPem: req.certPem,
          privateKeyPem: req.privateKeyPem,
          chainPem: req.chainPem,
          trustAnchorsPem: req.trustAnchorsPem,
          controlSpiffeId: req.controlSpiffeId,
        });
        if (!timingSafeEqual(expected, Buffer.from(String(req.proof || ''), 'base64'))) {
          log?.warn?.({ msg: 'control-plane installation rejected: proof did not verify' });
          throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'provisioning rejected');
        }

        // Parsed before installation, not after: an unparseable certificate installed into the
        // live secure context takes the listener down, and it would do so having already passed
        // every authentication check -- a self-inflicted outage triggered by a legitimate peer.
        let certificate;
        try {
          certificate = new crypto.X509Certificate(req.certPem);
        } catch (err) {
          throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, `the supplied certificate could not be parsed: ${err.message}`);
        }
        if (new Date(certificate.validTo).getTime() <= Date.now()) {
          throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'the supplied certificate has already expired');
        }

        const chain = [req.certPem.trim(), ...(req.chainPem || []).map((p) => p.trim())].filter(Boolean);
        const anchors = req.trustAnchorsPem.map((p) => p.trim()).filter(Boolean);

        if (typeof onTrustAnchors === 'function') onTrustAnchors(anchors);

        gate.provision({
          key: req.privateKeyPem,
          cert: `${chain.join('\n')}\n`,
          ca: `${anchors.join('\n')}\n`,
          info: {
            subject: certificate.subject.replace(/\n/g, ', '),
            notAfter: new Date(certificate.validTo).getTime(),
            fingerprint256: certificate.fingerprint256,
            controlSpiffeId: req.controlSpiffeId || null,
          },
        });

        if (req.controlSpiffeId) gate.controlSpiffeId = req.controlSpiffeId;

        const status = gate.status();
        return {
          installed: true,
          state: status.state,
          holdExpiresAt: BigInt(status.holdExpiresAt || 0),
          fingerprint256: certificate.fingerprint256,
        };
      },
    },

    /**
     * Readable without authentication, and deliberately so: "this database is sealed" is the
     * answer an operator needs when nothing can connect, and making them authenticate to a
     * database that authenticates nobody is a diagnostic dead end. Nothing here is a secret --
     * a peer that can reach the port already learns the state from the refusals it gets.
     */
    GetAdmissionStatus: {
      kind: 'unary',
      minSecurityLevel: SECURITY_LEVELS.TLS,
      schemas: CONTROL_SCHEMAS,
      requestType: 'ControlPlaneService_StatusReq',
      responseType: 'ControlPlaneService_StatusRes',
      handler: async () => {
        const status = gate.status();
        return {
          state: status.state,
          controlPrincipal: status.controlPrincipal,
          provisionedAt: BigInt(status.provisionedAt || 0),
          openedAt: BigInt(status.openedAt || 0),
          holdExpiresAt: BigInt(status.holdExpiresAt || 0),
          subject: status.identity?.subject || '',
          notAfter: BigInt(status.identity?.notAfter || 0),
        };
      },
    },
  };

  return { controller, schemas: CONTROL_SCHEMAS, gate };
}

/** Generates a bootstrap secret to share with the identity provider. */
function generateBootstrapSecret() { return crypto.randomBytes(32); }

module.exports = {
  createControlPlaneService,
  generateBootstrapSecret,
  computeServerConfirmation,
  computeInstallProof,
  confirmTranscript,
  installTranscript,
  CONTROL_SCHEMAS,
  CONFIRM_CONTEXT,
  INSTALL_CONTEXT,
};
