'use strict';

const crypto = require('node:crypto');
const { GrpcClient } = require('@fitfak/grpc');

const {
  CONTROL_SCHEMAS, computeServerConfirmation, computeInstallProof,
} = require('./control-plane-service');

// The identity provider's side of the handover.
//
// This is what the IdP calls before it enrols. The database it is talking to is sealed: it has
// an ephemeral self-signed certificate, no trust anchors and no principals. This call gives it
// the certificate it will serve, the key for that certificate, and the anchors it will validate
// clients against -- all minted by the IdP's own CA.
//
// The order of operations is the security property, so it is worth reading in order:
//
//   1. connect, without validating the server's certificate (there is nothing to validate it
//      against, and pretending otherwise would mean shipping the database a trust anchor for a
//      key it generated itself)
//   2. send a nonce, receive the server's nonce and its confirmation HMAC
//   3. VERIFY THAT CONFIRMATION. Nothing sensitive has been sent yet; if this fails, the peer
//      does not hold the bootstrap secret and the exchange stops here having disclosed nothing
//   4. only then send the certificate, key and anchors, with a proof bound to the TLS exporter
//      and to a hash of exactly that material
//
// Step 3 is the step a naive implementation skips, and skipping it hands a private key to
// whoever answered on that address.

const DEFAULT_CONTROL_PATHS = {
  challenge: '/custom.network.ControlPlaneService/GetBootstrapChallenge',
  install: '/custom.network.ControlPlaneService/InstallServerIdentity',
  status: '/custom.network.ControlPlaneService/GetAdmissionStatus',
};

class ControlPlaneError extends Error {
  constructor(message) { super(message); this.name = 'ControlPlaneError'; }
}

function timingSafeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Provisions a sealed database with the server identity the identity provider minted for it.
 *
 * @param {object}   opts
 * @param {string}   opts.target             e.g. 'https://db.internal:51572'
 * @param {Buffer}   opts.bootstrapSecret    shared with the database out of band
 * @param {object}   opts.serverIdentity     { certPem, privateKeyPem, chainPem[] } for the DATABASE
 * @param {string[]} opts.trustAnchorsPem    what the database will validate client certificates against
 * @param {string}  [opts.controlSpiffeId]   the SPIFFE ID the IdP's own client certificate carries
 * @param {string[]}[opts.pinnedFingerprints] optional extra check on the bootstrap certificate
 * @returns {Promise<{ state, holdExpiresAt, fingerprint256, alreadyOpen }>}
 */
async function provisionServerIdentity({
  target,
  bootstrapSecret,
  serverIdentity,
  trustAnchorsPem,
  controlSpiffeId = '',
  pinnedFingerprints = [],
  clientOptions = {},
  paths = {},
  logger = null,
}) {
  if (!target) throw new ControlPlaneError('target is required');
  if (!Buffer.isBuffer(bootstrapSecret) || bootstrapSecret.length < 32) {
    throw new ControlPlaneError('bootstrapSecret must be at least 32 bytes');
  }
  if (!serverIdentity?.certPem || !serverIdentity?.privateKeyPem) {
    throw new ControlPlaneError('serverIdentity needs certPem and privateKeyPem');
  }
  if (!trustAnchorsPem || trustAnchorsPem.length === 0) {
    throw new ControlPlaneError('trustAnchorsPem is required: a database with no anchors can validate no client');
  }

  const routes = { ...DEFAULT_CONTROL_PATHS, ...paths };
  const client = new GrpcClient(target, {
    ...clientOptions,
    // Not a lapse: the peer's certificate is one it generated for itself thirty seconds ago.
    // Authentication happens at the application layer, in step 3 below, before anything worth
    // stealing is transmitted.
    credentials: { ...(clientOptions.credentials || {}), rejectUnauthorized: false },
  });

  try {
    await client.connect();

    const channelBinding = client.channelBinding();
    if (!channelBinding) {
      throw new ControlPlaneError(
        'this TLS connection cannot export channel-binding material (RFC 9266), so neither side '
        + 'can prove which session it is talking on. Refusing to send a private key over it.',
      );
    }

    if (pinnedFingerprints.length > 0) {
      const presented = normalizeFingerprint(client.channelInfo().serverFingerprint256);
      if (!pinnedFingerprints.map(normalizeFingerprint).includes(presented)) {
        throw new ControlPlaneError(
          `the database presented ${presented}, which is not among the pinned bootstrap fingerprints`,
        );
      }
    }

    const clientNonce = crypto.randomBytes(32).toString('base64');
    const challenge = await client.unary(routes.challenge, CONTROL_SCHEMAS,
      'ControlPlaneService_ChallengeReq', 'ControlPlaneService_ChallengeRes', { clientNonce });

    if (challenge.state === 'open') {
      // Already provisioned and committed by an earlier run. Re-installing would re-arm the hold
      // timer on a database that is serving traffic, so the right answer is to leave it alone.
      logger?.info?.('[control] the database is already open; no provisioning needed');
      return { state: challenge.state, alreadyOpen: true, holdExpiresAt: 0, fingerprint256: '' };
    }

    const expected = computeServerConfirmation(bootstrapSecret, {
      clientNonce, serverNonce: challenge.serverNonce, channelBinding,
    });
    if (!timingSafeEqual(expected, Buffer.from(String(challenge.serverConfirmation || ''), 'base64'))) {
      throw new ControlPlaneError(
        'the peer at this address did not prove it holds the bootstrap secret. No certificate or '
        + 'key was sent. Either the secret is wrong on one side, or something is answering in '
        + "the database's place.",
      );
    }
    logger?.info?.('[control] the database proved it holds the bootstrap secret');

    const timestamp = Date.now();
    const chainPem = serverIdentity.chainPem || [];
    const proof = computeInstallProof(bootstrapSecret, {
      serverNonce: challenge.serverNonce,
      timestamp,
      channelBinding,
      certPem: serverIdentity.certPem,
      privateKeyPem: serverIdentity.privateKeyPem,
      chainPem,
      trustAnchorsPem,
      controlSpiffeId,
    }).toString('base64');

    const result = await client.unary(routes.install, CONTROL_SCHEMAS,
      'ControlPlaneService_InstallReq', 'ControlPlaneService_InstallRes', {
        serverNonce: challenge.serverNonce,
        timestamp: BigInt(timestamp),
        proof,
        certPem: serverIdentity.certPem,
        privateKeyPem: serverIdentity.privateKeyPem,
        chainPem,
        trustAnchorsPem,
        controlSpiffeId,
      });

    logger?.info?.(
      `[control] server identity installed (${result.fingerprint256}); the database is `
      + `${result.state} and will re-seal at ${new Date(Number(result.holdExpiresAt)).toISOString()} `
      + 'unless this identity provider completes its mutually authenticated connection',
    );

    return {
      state: result.state,
      alreadyOpen: false,
      holdExpiresAt: Number(result.holdExpiresAt),
      fingerprint256: result.fingerprint256,
    };
  } finally {
    // The bootstrap connection has done its job. Leaving it open would keep an unverified TLS
    // session alive next to the verified one that replaces it.
    client.close();
  }
}

/** Reads the admission state without provisioning anything -- for health checks and diagnostics. */
async function readAdmissionStatus({ target, clientOptions = {}, paths = {} }) {
  const routes = { ...DEFAULT_CONTROL_PATHS, ...paths };
  const client = new GrpcClient(target, {
    ...clientOptions,
    credentials: { ...(clientOptions.credentials || {}), rejectUnauthorized: false },
  });
  try {
    await client.connect();
    const status = await client.unary(routes.status, CONTROL_SCHEMAS,
      'ControlPlaneService_StatusReq', 'ControlPlaneService_StatusRes', {});
    return {
      state: status.state,
      controlPrincipal: status.controlPrincipal,
      provisionedAt: Number(status.provisionedAt) || null,
      openedAt: Number(status.openedAt) || null,
      holdExpiresAt: Number(status.holdExpiresAt) || null,
      subject: status.subject || null,
      notAfter: Number(status.notAfter) || null,
    };
  } finally {
    client.close();
  }
}

function normalizeFingerprint(value) {
  return String(value || '').replace(/:/g, '').toLowerCase();
}

module.exports = { provisionServerIdentity, readAdmissionStatus, ControlPlaneError, DEFAULT_CONTROL_PATHS };
