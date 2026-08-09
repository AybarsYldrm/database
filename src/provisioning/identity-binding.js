'use strict';

const spiffe = require('./spiffe');

// The check that decides what identity an enrolling peer walks away with.
//
// A grant says what the attestor authorised this caller to become. A CSR says what the caller
// asked for. These are two different statements from two different parties and the safe response
// to a disagreement is refusal, not quiet narrowing to the intersection -- a request and an
// authorisation that disagree mean one of them is wrong, and issuing "the part they agree on"
// certifies something neither side asked for.
//
// This lives apart from enrollment-service.js because it is pure policy: no transport, no CA, no
// I/O. That separation is not tidiness. The service module requires @fitfak/grpc at load time,
// so as long as these functions lived inside it, the single most security-critical comparison in
// the enrolment path could only be tested with the whole transport installed -- and the last
// escalation found in this codebase was precisely a comparison here that silently stopped
// running (see test/enrolment-identity-binding-demo.js).

/** A denial the transport can map to a status, whether or not @fitfak/grpc is loadable here. */
function denial(statusName, message) {
  try {
    // eslint-disable-next-line global-require
    const { GrpcError, GRPC_STATUS } = require('@fitfak/grpc');
    return new GrpcError(GRPC_STATUS[statusName], message);
  } catch (_) {
    const err = new Error(message);
    err.name = 'IdentityBindingError';
    err.grpcStatusName = statusName;
    return err;
  }
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
    throw denial('INTERNAL',
      'the CA backend did not report a subject for this CSR, so the requested identity cannot be '
      + 'checked against the grant; refusing to issue');
  }
  if (grantedCn && requestedCn !== grantedCn) {
    throw denial('PERMISSION_DENIED',
      `the request asks for CN='${requestedCn}' but this credential only authorises CN='${grantedCn}'`);
  }

  // A second CN would pass the equality test above on its first occurrence while a relying
  // party that reads the last one sees something else entirely.
  if (Array.isArray(parsedCsr.commonNames) && parsedCsr.commonNames.length > 1) {
    throw denial('PERMISSION_DENIED',
      'the certificate signing request carries more than one common name');
  }

  assertSpiffeMatchesGrant(parsedCsr, grant);

  const allowed = new Set((grant.altNames || []).map(normalizeAltName));
  if (grantedCn) allowed.add(normalizeAltName(grantedCn));
  if (grant.spiffeId) allowed.add(normalizeAltName(grant.spiffeId));

  for (const requested of parsedCsr.altNames || []) {
    if (!allowed.has(normalizeAltName(requested))) {
      throw denial('PERMISSION_DENIED',
        `the request asks for subjectAltName '${requested}', which this credential does not authorise`);
    }
  }
}

/**
 * The SPIFFE half of the same check, kept separate because it fails in a direction the SAN loop
 * above cannot see: a CSR that asks for NO SPIFFE ID when the grant carries one.
 *
 * That loop only rejects names the grant does not cover, so a peer granted
 * `spiffe://fitfak.net/service/dns` could simply omit the URI SAN and be issued a certificate
 * with no SPIFFE ID at all. Against a relying party that authorises on the SPIFFE ID that
 * certificate is inert, but against one that falls back to the CN it is a working credential
 * that has shed the field carrying the authorisation. Requiring the grant's ID to be present,
 * exactly once, closes that.
 */
function assertSpiffeMatchesGrant(parsedCsr, grant) {
  const requested = [];
  for (const entry of parsedCsr.altNames || []) {
    const value = String(entry).replace(/^URI:/i, '').trim();
    if (!value.toLowerCase().startsWith(`${spiffe.SPIFFE_SCHEME}://`)) continue;
    let parsed;
    try { parsed = spiffe.parse(value); }
    catch (err) {
      throw denial('INVALID_ARGUMENT',
        `the request carries '${value}', which is not a well-formed SPIFFE ID: ${err.message}`);
    }
    requested.push(parsed.uri);
  }

  if (requested.length > 1) {
    throw denial('PERMISSION_DENIED',
      `the request asks for ${requested.length} SPIFFE IDs (${requested.join(', ')}); a certificate `
      + 'whose identity depends on which one the verifier reads is not an identity');
  }

  if (!grant.spiffeId) {
    // No grant, no ID. The point of routing identity through an attestor is that the applicant
    // does not get to choose what it is called.
    if (requested.length > 0) {
      throw denial('PERMISSION_DENIED',
        `the request asks for the SPIFFE ID '${requested[0]}', which this credential does not authorise`);
    }
    return;
  }

  const granted = spiffe.parse(grant.spiffeId).uri;
  if (requested.length === 0) {
    throw denial('PERMISSION_DENIED',
      `this credential authorises the SPIFFE ID '${granted}' and the request omits it; a certificate `
      + 'issued without it would carry no verifiable identity');
  }
  if (requested[0] !== granted) {
    throw denial('PERMISSION_DENIED',
      `the request asks for SPIFFE ID '${requested[0]}' but this credential only authorises '${granted}'`);
  }
}

function normalizeAltName(value) {
  return String(value).replace(/^(DNS|IP Address|IP|email|URI):/i, '').trim().toLowerCase();
}

module.exports = { assertIdentityMatchesGrant, assertSpiffeMatchesGrant, normalizeAltName };
