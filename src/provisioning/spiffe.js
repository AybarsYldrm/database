'use strict';

// SPIFFE identity, as an X.509 URI SAN.
//
// Every workload in this stack is named by a SPIFFE ID -- `spiffe://<trust domain>/<path>` --
// and that name lives in the certificate's subjectAltName as a uniformResourceIdentifier, not
// in the Common Name. The distinction is not cosmetic:
//
//   - RFC 6125 §6.4.4 deprecated CN-as-identity a decade ago. Every TLS stack worth trusting
//     matches on SAN; CN survives as a display string. An authorisation decision read from CN
//     is a decision read from a field nothing else validates.
//   - A CN is a bag of text. A SPIFFE ID is a URI with a trust domain, which means "is this
//     peer from my trust domain" is answerable without a lookup table, and federation between
//     domains is a comparison rather than a convention.
//   - SPIRE, Istio and every CNCF workload-identity implementation already read this field.
//     Writing it costs one extension and buys interoperability we would otherwise have to
//     build.
//
// This module is deliberately only the *name*: parsing, validating and formatting. What a name
// is allowed to become is a policy question and lives in the attestors; what a name may do once
// connected lives in the principal resolver and the ACLs.
//
// The grammar below is the SPIFFE-ID specification's, not a loose approximation of it. Being
// strict here is what makes the rest safe to be simple: a component that has parsed a SPIFFE ID
// can assume there is no userinfo to confuse an authority comparison, no query string to smuggle
// a second identity in, and no dot-segments for a path comparison to normalise differently from
// whatever wrote the certificate.

const SPIFFE_SCHEME = 'spiffe';

// The spec's limits. A trust domain is a DNS-ish label set; a full ID is bounded so that a
// certificate cannot be inflated by a caller choosing a 60 KB path.
const MAX_TRUST_DOMAIN_LENGTH = 255;
const MAX_ID_LENGTH = 2048;

// Trust domain: lowercase letters, digits, dot, dash, underscore. No uppercase -- the spec
// requires lowercase so that two spellings of the same domain cannot compare unequal.
const TRUST_DOMAIN_RE = /^[a-z0-9._-]+$/;
// Path segment: the unreserved characters of RFC 3986, minus '~'. No percent-encoding, so a
// byte-for-byte comparison of two IDs is the same as a semantic comparison of them.
const PATH_SEGMENT_RE = /^[A-Za-z0-9._-]+$/;

class SpiffeError extends Error {
  constructor(message) { super(message); this.name = 'SpiffeError'; }
}

/**
 * A parsed SPIFFE ID. Immutable: an identity that can be edited after it has been checked is
 * an identity whose check means nothing.
 */
class SpiffeId {
  constructor(trustDomain, segments) {
    this.trustDomain = trustDomain;
    this.segments = Object.freeze([...segments]);
    this.path = segments.length ? `/${segments.join('/')}` : '';
    this.uri = `${SPIFFE_SCHEME}://${trustDomain}${this.path}`;
    Object.freeze(this);
  }

  toString() { return this.uri; }
  toJSON() { return this.uri; }

  /** Same trust domain -- the question federation turns on. */
  sameTrustDomain(other) {
    const parsed = other instanceof SpiffeId ? other : parse(other);
    return this.trustDomain === parsed.trustDomain;
  }

  /**
   * Whether this ID sits under `prefix`, comparing whole segments.
   *
   * Segment-wise and not string-wise on purpose: `spiffe://fitfak.net/service/idp-evil`
   * starts with the string `spiffe://fitfak.net/service/idp` and is a different workload.
   * A prefix check that gets this wrong hands one service another's authority.
   */
  isUnder(prefix) {
    const parsed = prefix instanceof SpiffeId ? prefix : parse(prefix);
    if (parsed.trustDomain !== this.trustDomain) return false;
    if (parsed.segments.length > this.segments.length) return false;
    return parsed.segments.every((segment, i) => segment === this.segments[i]);
  }

  /** The first path segment, which is this stack's convention for "what kind of thing is it". */
  get kind() { return this.segments[0] || ''; }
}

/**
 * Parses a SPIFFE ID, throwing on anything the specification does not allow.
 *
 * Note what is rejected rather than repaired: a trailing slash, an empty segment, a dot
 * segment, a port, a userinfo, a query, a fragment, any uppercase in the trust domain. Every
 * one of those is a place where two implementations could disagree about what the identity is,
 * and an identity two parties read differently is not an identity.
 */
function parse(value) {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) throw new SpiffeError('a SPIFFE ID is required');
  if (raw.length > MAX_ID_LENGTH) throw new SpiffeError(`a SPIFFE ID may not exceed ${MAX_ID_LENGTH} characters`);

  let url;
  try {
    url = new URL(raw);
  } catch (err) {
    throw new SpiffeError(`'${raw}' is not a URI (${err.message})`);
  }

  if (url.protocol !== `${SPIFFE_SCHEME}:`) {
    throw new SpiffeError(`a SPIFFE ID must use the '${SPIFFE_SCHEME}' scheme, got '${url.protocol.replace(/:$/, '')}'`);
  }
  if (url.username || url.password) throw new SpiffeError('a SPIFFE ID may not carry userinfo');
  if (url.port) throw new SpiffeError('a SPIFFE ID may not carry a port');
  if (url.search) throw new SpiffeError('a SPIFFE ID may not carry a query string');
  if (url.hash) throw new SpiffeError('a SPIFFE ID may not carry a fragment');

  // WHATWG URL lowercases the host for special schemes only, and `spiffe` is not one of them,
  // so an uppercase trust domain arrives here unchanged -- which is exactly what has to be
  // rejected rather than quietly folded.
  const trustDomain = url.hostname;
  if (!trustDomain) throw new SpiffeError('a SPIFFE ID must name a trust domain');
  if (trustDomain.length > MAX_TRUST_DOMAIN_LENGTH) {
    throw new SpiffeError(`a trust domain may not exceed ${MAX_TRUST_DOMAIN_LENGTH} characters`);
  }
  if (!TRUST_DOMAIN_RE.test(trustDomain)) {
    throw new SpiffeError(`'${trustDomain}' is not a valid trust domain (lowercase letters, digits, '.', '-' and '_' only)`);
  }

  // The path is read from the RAW input, not from url.pathname.
  //
  // WHATWG URL applies dot-segment removal while parsing, so `spiffe://fitfak.net/service/../admin`
  // arrives at url.pathname as `/admin` -- the traversal has already happened and there is
  // nothing left to reject. Any check written against the parsed path is therefore checking a
  // string the attacker has already had rewritten in their favour. Percent-encoding is the same
  // story with a different mechanism: `%2e%2e` survives parsing here but not everywhere.
  //
  // So the raw path is what gets validated, and the canonical-form check at the bottom catches
  // every remaining way the two could differ.
  const authorityStart = `${SPIFFE_SCHEME}://`.length;
  const pathStart = raw.indexOf('/', authorityStart);
  const rawPath = pathStart === -1 ? '' : raw.slice(pathStart);

  if (rawPath === '') return canonical(new SpiffeId(trustDomain, []), raw);
  if (rawPath === '/') throw new SpiffeError('a SPIFFE ID path may not end in a separator');
  if (rawPath.endsWith('/')) throw new SpiffeError('a SPIFFE ID path may not end in a separator');
  if (rawPath.includes('%')) {
    throw new SpiffeError('a SPIFFE ID may not use percent-encoding; two parties that normalise it '
      + 'differently would read the same certificate as two different identities');
  }

  const segments = rawPath.slice(1).split('/');
  for (const segment of segments) {
    if (segment === '') throw new SpiffeError('a SPIFFE ID path may not contain an empty segment');
    if (segment === '.' || segment === '..') throw new SpiffeError("a SPIFFE ID path may not contain '.' or '..' segments");
    if (!PATH_SEGMENT_RE.test(segment)) {
      throw new SpiffeError(`'${segment}' is not a valid SPIFFE path segment (letters, digits, '.', '-' and '_' only)`);
    }
  }
  return canonical(new SpiffeId(trustDomain, segments), raw);
}

/**
 * The last line of defence: what we parsed must serialise back to exactly what we were given.
 *
 * Every check above targets a specific known trick. This one catches the ones nobody thought of,
 * by refusing any input whose canonical form differs from itself. It is what lets the rest of
 * the codebase compare SPIFFE IDs with `===` and be right.
 */
function canonical(id, raw) {
  if (id.uri !== raw) {
    throw new SpiffeError(`'${raw}' is not in canonical form (it denotes '${id.uri}'); a SPIFFE ID `
      + 'must be written exactly as it is compared');
  }
  return id;
}

/** parse() without the throw, for the many call sites that only want to know "is it one". */
function tryParse(value) {
  try { return parse(value); } catch (_) { return null; }
}

function isSpiffeId(value) { return tryParse(value) !== null; }

/**
 * Builds an ID from a trust domain and path segments, validating the result.
 *
 * Going through parse() rather than string concatenation is the point: a segment containing a
 * slash would otherwise silently deepen the path, and a caller passing user-controlled text
 * (a device id, a session id) is exactly how that happens.
 */
function build(trustDomain, ...segments) {
  const flat = segments.flat().filter((s) => s !== undefined && s !== null).map(String);
  return parse(`${SPIFFE_SCHEME}://${trustDomain}${flat.length ? `/${flat.join('/')}` : ''}`);
}

// ---- this stack's naming convention ------------------------------------------------------------
//
// SPIFFE says nothing about what paths mean; that is each deployment's decision, and writing it
// down in one place is what keeps `service/` from becoming `services/` in the next file. The
// first segment is the kind, the rest identify the instance.

const KINDS = Object.freeze({
  SERVICE: 'service',    // a long-lived server-side workload: the IdP, the SMTP relay
  WORKLOAD: 'workload',  // a scheduled/ephemeral workload instance
  DEVICE: 'device',      // an enrolled device holding a hardware-backed credential
  USER: 'user',          // a human, in the context of a client certificate
  SESSION: 'session',    // one authenticated session -- the short-lived BeyondCorp case
  AGENT: 'agent',        // an automation/CI principal
});

const factories = {
  forService: (trustDomain, name) => build(trustDomain, KINDS.SERVICE, name),
  forWorkload: (trustDomain, name, instance) => build(trustDomain, KINDS.WORKLOAD, name, ...(instance ? [instance] : [])),
  forDevice: (trustDomain, deviceId) => build(trustDomain, KINDS.DEVICE, deviceId),
  forUser: (trustDomain, userId) => build(trustDomain, KINDS.USER, userId),
  forSession: (trustDomain, sessionId) => build(trustDomain, KINDS.SESSION, sessionId),
  forAgent: (trustDomain, agentId) => build(trustDomain, KINDS.AGENT, agentId),
};

// ---- certificates ------------------------------------------------------------------------------

/**
 * Pulls the SPIFFE ID out of a peer certificate's SANs.
 *
 * Two shapes are accepted because two layers produce them: Node's X509Certificate renders
 * `subjectAltName` as a comma-joined `URI:spiffe://...` string, while this package's transport
 * hands over an array of those same entries.
 *
 * More than one SPIFFE URI is a hard error, not a "take the first". A certificate naming two
 * identities is a certificate where the relying party's choice of which to read decides the
 * authorisation outcome, and different relying parties will choose differently.
 */
function fromCertificate(certificate) {
  if (!certificate) return null;
  const entries = normalizeAltNames(certificate);
  const found = [];
  for (const entry of entries) {
    const match = /^URI:(.*)$/i.exec(entry);
    const candidate = match ? match[1] : entry;
    if (!candidate.toLowerCase().startsWith(`${SPIFFE_SCHEME}://`)) continue;
    found.push(parse(candidate));
  }
  if (found.length === 0) return null;
  if (found.length > 1) {
    throw new SpiffeError(
      `this certificate carries ${found.length} SPIFFE IDs (${found.join(', ')}); an identity that `
      + 'depends on which one the relying party reads is not an identity',
    );
  }
  return found[0];
}

function normalizeAltNames(certificate) {
  const raw = certificate.altNames || certificate.subjectAltName || [];
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  return list.map((entry) => String(entry).trim()).filter(Boolean);
}

/**
 * The SAN entry to put in a CSR or certificate. @fitfak/ssl's SAN shape is `{ type, value }`;
 * `uri` is the type that becomes a uniformResourceIdentifier GeneralName (RFC 5280 §4.2.1.6).
 */
function toSanEntry(id) {
  const parsed = id instanceof SpiffeId ? id : parse(id);
  return { type: 'uri', value: parsed.uri };
}

/**
 * A verifier for the relying-party side: does this peer hold an ID we accept?
 *
 * `allowed` may contain exact IDs and prefixes; a prefix is any ID whose path is a proper
 * ancestor, so `spiffe://fitfak.net/service` admits every service without naming each one.
 * `trustDomain`, when given, is checked first and independently -- an allow-list entry from
 * another domain would otherwise silently federate two PKIs that never agreed to trust
 * each other.
 */
function createVerifier({ trustDomain = null, allowed = null } = {}) {
  const prefixes = (allowed || []).map((entry) => parse(entry));
  return function verify(certificateOrId) {
    const id = certificateOrId instanceof SpiffeId
      ? certificateOrId
      : (typeof certificateOrId === 'string' ? parse(certificateOrId) : fromCertificate(certificateOrId));

    if (!id) throw new SpiffeError('the peer presented no SPIFFE ID');
    if (trustDomain && id.trustDomain !== trustDomain) {
      throw new SpiffeError(`'${id}' belongs to trust domain '${id.trustDomain}', not '${trustDomain}'`);
    }
    if (prefixes.length && !prefixes.some((prefix) => id.isUnder(prefix))) {
      throw new SpiffeError(`'${id}' is not an accepted identity here`);
    }
    return id;
  };
}

module.exports = {
  SpiffeId,
  SpiffeError,
  SPIFFE_SCHEME,
  KINDS,
  parse,
  tryParse,
  isSpiffeId,
  build,
  fromCertificate,
  toSanEntry,
  createVerifier,
  ...factories,
};
