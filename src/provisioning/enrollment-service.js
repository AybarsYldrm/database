'use strict';

const { EventEmitter } = require('node:events');
const { GRPC_STATUS, GrpcError, SECURITY_LEVELS } = require('@fitfak/grpc');
const { computeEnrolmentProof, EnrolmentDenied } = require('./attestor');

// The Registration Authority half of the bootstrap flow, exposed as a gRPC service.
//
// The whole point is the security level split. `GetTrustAnchors` and `Enroll` are reachable
// on a channel where only the SERVER has authenticated (`minSecurityLevel: 'tls'`), because a
// peer that has never been issued a certificate has no other way to reach anything.
// `Reenroll` requires 'mtls', because renewal is authenticated by the certificate being
// renewed. Everything else on the server -- the entire data plane -- is 'mtls'.
//
// This service never signs anything. It authenticates the caller, decides what identity that
// caller is allowed to be issued, checks that the CSR asks for exactly that identity and no
// more, and hands the CSR to the configured CA backend. Keeping the signing key out of this
// process is the difference between "the database can vouch for who a service is" and "the
// database is a CA".

const ENROLMENT_SCHEMAS = {
  EnrollmentService_GetTrustAnchorsReq: [],
  EnrollmentService_GetTrustAnchorsRes: [
    { no: 1, name: 'chainPem', type: 'string', repeated: true },
    { no: 2, name: 'fingerprints', type: 'string', repeated: true },
    { no: 3, name: 'serverName', type: 'string' },
    { no: 4, name: 'channelBindingSupported', type: 'bool' },
  ],
  EnrollmentService_EnrollReq: [
    { no: 1, name: 'serviceName', type: 'string' },
    { no: 2, name: 'csrPem', type: 'string' },
    { no: 3, name: 'nonce', type: 'string' },
    { no: 4, name: 'timestamp', type: 'int64' },
    { no: 5, name: 'proof', type: 'string' },      // base64 HMAC over the enrolment transcript
    { no: 6, name: 'token', type: 'string' },      // alternative to proof, for token attestors
    { no: 7, name: 'method', type: 'string' },     // names one attestor when several are configured
  ],
  EnrollmentService_EnrollRes: [
    { no: 1, name: 'certPem', type: 'string' },
    { no: 2, name: 'chainPem', type: 'string', repeated: true },
    { no: 3, name: 'principal', type: 'string' },
    { no: 4, name: 'roles', type: 'string', repeated: true },
    { no: 5, name: 'notAfter', type: 'int64' },
    { no: 6, name: 'serialNumber', type: 'string' },
    { no: 7, name: 'renewAfter', type: 'int64' },
  ],
};
// Re-enrolment is the same exchange with a different security level, so it reuses the shapes.
ENROLMENT_SCHEMAS.EnrollmentService_ReenrollReq = ENROLMENT_SCHEMAS.EnrollmentService_EnrollReq;
ENROLMENT_SCHEMAS.EnrollmentService_ReenrollRes = ENROLMENT_SCHEMAS.EnrollmentService_EnrollRes;

const DEFAULT_VALIDITY_DAYS = 397;

/**
 * @param {object}   opts
 * @param {object}   opts.caBackend    see ca-backend.js
 * @param {object}   opts.attestor     see attestor.js
 * @param {object}  [opts.renewalAttestor] used by Reenroll; defaults to `attestor`
 * @param {string}  [opts.serverName]  advertised to enrolling peers for pinning/diagnostics
 * @param {number}  [opts.renewalRatio] fraction of lifetime after which renewal should start
 */
function createEnrollmentService({
  caBackend,
  attestor,
  renewalAttestor = null,
  serverName = '',
  defaultValidityDays = DEFAULT_VALIDITY_DAYS,
  renewalRatio = 2 / 3,
  logger = null,
} = {}) {
  if (!caBackend) throw new Error('fitdb enrol: createEnrollmentService requires a caBackend');
  if (!attestor) throw new Error('fitdb enrol: createEnrollmentService requires an attestor');

  const events = new EventEmitter();
  const log = logger || null;

  async function runEnrolment(req, call, { attestorToUse, kind }) {
    const peer = call.peer;

    if (!req.csrPem) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'a certificate signing request is required');

    let grant;
    try {
      grant = await attestorToUse.attest({ request: req, peer, channelBinding: peer.channelBinding });
    } catch (err) {
      // Everything the attestor rejects comes back as one status with one message. Telling an
      // unauthenticated caller whether the service name was unknown, the nonce replayed or the
      // HMAC wrong is an oracle for probing the enrolment surface.
      log?.warn?.(`[enrol] ${kind} denied for '${req.serviceName || 'unknown'}': ${err.message}`);
      events.emit('denied', { kind, serviceName: req.serviceName, reason: err.message, peer });
      throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'enrolment rejected');
    }

    // Proof of possession: the CSR is self-signed by the key being certified. Without this
    // check a caller could submit a CSR built over someone else's public key and have the CA
    // certify that key under a name the caller was authorised for.
    const parsed = await caBackend.parseCsr(req.csrPem);
    if (parsed.verified === false) {
      throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'the certificate signing request is not correctly self-signed');
    }

    // The grant says what this caller may become; the CSR says what it asked for. Issuing the
    // intersection is not enough -- a mismatch means the request and the authorisation
    // disagree, and the safe response to that is refusal, not quiet narrowing.
    assertIdentityMatchesGrant(parsed, grant);

    const validityDays = grant.validityDays || defaultValidityDays;
    const issued = await caBackend.issue({
      csrPem: req.csrPem,
      subject: grant.subject,
      altNames: grant.altNames,
      roles: grant.roles,
      validityDays,
    });

    const anchors = await caBackend.getTrustAnchors();
    const notAfter = issued.notAfter ? new Date(issued.notAfter).getTime() : Date.now() + validityDays * 86400000;
    // Telling the peer when to come back is what keeps renewal from being a cron job that
    // drifts out of sync with the actual expiry.
    const renewAfter = Date.now() + Math.floor((notAfter - Date.now()) * renewalRatio);

    // Only now is the credential considered spent -- see the note on `commit` in attestor.js.
    // A request that authenticated but was rejected for asking the wrong identity, or that
    // died because the CA was unreachable, leaves the credential usable.
    if (typeof grant.commit === 'function') grant.commit();

    const result = {
      principal: grant.principal,
      roles: grant.roles || [],
      method: grant.method || attestorToUse.name,
      serialNumber: issued.serialNumber || '',
      notAfter,
      peer,
    };
    log?.info?.(`[enrol] ${kind} issued '${grant.principal}' via ${result.method}, expires ${new Date(notAfter).toISOString()}`);
    events.emit('issued', result);

    return {
      certPem: issued.certPem,
      chainPem: issued.chainPem && issued.chainPem.length ? issued.chainPem : anchors.chainPem,
      principal: grant.principal,
      roles: grant.roles || [],
      notAfter: BigInt(notAfter),
      serialNumber: String(issued.serialNumber || ''),
      renewAfter: BigInt(renewAfter),
    };
  }

  const controller = {
    /**
     * First call of the bootstrap flow. Hands back the CA chain the peer will need in order to
     * validate this server on its next (mutually authenticated) connection, plus fingerprints
     * it can pin. Deliberately requires no authentication: trust anchors are public data, and
     * a peer that cannot fetch them cannot verify anything afterwards.
     */
    GetTrustAnchors: {
      kind: 'unary',
      minSecurityLevel: SECURITY_LEVELS.TLS,
      schemas: ENROLMENT_SCHEMAS,
      requestType: 'EnrollmentService_GetTrustAnchorsReq',
      responseType: 'EnrollmentService_GetTrustAnchorsRes',
      handler: async (req, call) => {
        const anchors = await caBackend.getTrustAnchors();
        return {
          chainPem: anchors.chainPem,
          fingerprints: anchors.fingerprints,
          serverName,
          // The peer needs to know this before it builds a proof: if the connection cannot
          // export keying material, an attestor that requires channel binding will reject it,
          // and it is better to learn that here than after generating a key pair.
          channelBindingSupported: !!call.peer.channelBinding,
        };
      },
    },

    /** First issuance, on the bootstrap channel, authenticated by whatever the attestor accepts. */
    Enroll: {
      kind: 'unary',
      minSecurityLevel: SECURITY_LEVELS.TLS,
      schemas: ENROLMENT_SCHEMAS,
      requestType: 'EnrollmentService_EnrollReq',
      responseType: 'EnrollmentService_EnrollRes',
      handler: (req, call) => runEnrolment(req, call, { attestorToUse: attestor, kind: 'enroll' }),
    },

    /**
     * Renewal, authenticated by the certificate being renewed. Requires mTLS, which is what
     * allows the bootstrap credential to be single-use: a service only ever needs it once.
     */
    Reenroll: {
      kind: 'unary',
      minSecurityLevel: SECURITY_LEVELS.MTLS,
      schemas: ENROLMENT_SCHEMAS,
      requestType: 'EnrollmentService_ReenrollReq',
      responseType: 'EnrollmentService_ReenrollRes',
      handler: (req, call) => runEnrolment(req, call, {
        attestorToUse: renewalAttestor || attestor,
        kind: 'reenroll',
      }),
    },
  };

  return { controller, schemas: ENROLMENT_SCHEMAS, events, caBackend };
}

/**
 * A CSR may not ask for an identity the grant does not cover. Both directions matter: a CN
 * the grant did not authorise is an obvious escalation, and a SAN the grant did not authorise
 * is the same escalation wearing a different hat -- most TLS stacks match on SAN, not CN, so
 * checking only the CN would leave the actually-load-bearing field unchecked.
 */
function assertIdentityMatchesGrant(parsedCsr, grant) {
  const requestedCn = parsedCsr.subject?.CN;
  const grantedCn = grant.subject?.CN;

  // Fail closed when the CN cannot be read.
  //
  // This guard used to be `if (grantedCn && requestedCn && ...)`, which meant a backend whose
  // parseCsr did not decode a subject made the whole comparison evaporate -- no error, no
  // warning, just an authorisation check that silently stopped running. The @fitfak/ssl
  // backend was exactly that case, so a peer granted 'idp-service' could enrol a CSR naming
  // any other principal and be certified as it. A check that no-ops when its input is missing
  // is worse than no check at all, because it reads like protection.
  if (grantedCn && requestedCn === undefined) {
    throw new GrpcError(GRPC_STATUS.INTERNAL,
      'the CA backend did not report a subject for this CSR, so the requested identity cannot be '
      + 'checked against the grant; refusing to issue');
  }
  if (grantedCn && requestedCn !== grantedCn) {
    throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED,
      `the request asks for CN='${requestedCn}' but this credential only authorises CN='${grantedCn}'`);
  }

  // A second CN would pass the equality test above on its first occurrence while a relying
  // party that reads the last one sees something else entirely.
  if (Array.isArray(parsedCsr.commonNames) && parsedCsr.commonNames.length > 1) {
    throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED,
      'the certificate signing request carries more than one common name');
  }

  const allowed = new Set((grant.altNames || []).map(normalizeAltName));
  if (grantedCn) allowed.add(normalizeAltName(grantedCn));

  for (const requested of parsedCsr.altNames || []) {
    if (!allowed.has(normalizeAltName(requested))) {
      throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED,
        `the request asks for subjectAltName '${requested}', which this credential does not authorise`);
    }
  }
}

function normalizeAltName(value) {
  return String(value).replace(/^(DNS|IP Address|IP|email|URI):/i, '').trim().toLowerCase();
}

module.exports = {
  createEnrollmentService,
  ENROLMENT_SCHEMAS,
  computeEnrolmentProof,
  EnrolmentDenied,
  assertIdentityMatchesGrant,
};
