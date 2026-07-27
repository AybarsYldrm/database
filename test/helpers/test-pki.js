'use strict';

const crypto = require('node:crypto');

// TEST FIXTURE ONLY -- not under src/, not exported from the package, not a PKI.
//
// In production the CA is central (the ACME authority at trust.fitfak.net) and the PKI
// primitives -- CSR generation and parsing, chain verification, OCSP, CRL -- come from
// @fitfak/ssl. @fitfak/database talks to both through the CaBackend and CsrProvider
// interfaces and implements neither.
//
// This file exists so the enrolment flow can be tested offline: it writes just enough DER to
// produce an X.509 chain and PKCS#10 requests, and implements the same two interfaces the
// real adapters do. If it disagrees with @fitfak/ssl about anything, @fitfak/ssl is right.

// ---- DER writer -----------------------------------------------------------------------------

const TAG = {
  BOOLEAN: 0x01, INTEGER: 0x02, BIT_STRING: 0x03, OCTET_STRING: 0x04, NULL: 0x05,
  OID: 0x06, UTF8_STRING: 0x0c, PRINTABLE_STRING: 0x13, IA5_STRING: 0x16,
  UTC_TIME: 0x17, GENERALIZED_TIME: 0x18, SEQUENCE: 0x30, SET: 0x31,
};

function encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

const seq = (parts) => tlv(TAG.SEQUENCE, Buffer.concat(parts));
const set = (parts) => tlv(TAG.SET, Buffer.concat(parts));
const bool = (v) => tlv(TAG.BOOLEAN, Buffer.from([v ? 0xff : 0x00]));
const octets = (buf) => tlv(TAG.OCTET_STRING, buf);
const ctx = (n, content, constructed = true) => tlv((constructed ? 0xa0 : 0x80) | n, content);

function integer(value) {
  let buf = Buffer.isBuffer(value) ? value : Buffer.from([value]);
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0 && (buf[i + 1] & 0x80) === 0) i++;
  buf = buf.subarray(i);
  if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
  return tlv(TAG.INTEGER, buf);
}

const bitString = (buf, unused = 0) => tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([unused]), buf]));

function oid(dotted) {
  const parts = dotted.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let n = part;
    do { chunk.unshift(n & 0x7f); n >>>= 7; } while (n > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return tlv(TAG.OID, Buffer.from(bytes));
}

function time(date) {
  const p = (n) => String(n).padStart(2, '0');
  const y = date.getUTCFullYear();
  const rest = `${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return y < 2050
    ? tlv(TAG.UTC_TIME, Buffer.from(`${p(y % 100)}${rest}`, 'ascii'))
    : tlv(TAG.GENERALIZED_TIME, Buffer.from(`${y}${rest}`, 'ascii'));
}

// ---- DER reader -------------------------------------------------------------------------------

function read(buf, offset = 0) {
  const tag = buf[offset];
  let pos = offset + 1;
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++];
  }
  return {
    tag,
    length: len,
    content: buf.subarray(pos, pos + len),
    full: buf.subarray(offset, pos + len), // needed verbatim for signature verification
    next: pos + len,
  };
}

function* children(node) {
  let offset = 0;
  while (offset < node.content.length) {
    const child = read(node.content, offset);
    yield child;
    offset = child.next;
  }
}

function decodeOid(content) {
  const first = content[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    value = (value << 7) | (content[i] & 0x7f);
    if ((content[i] & 0x80) === 0) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

const OID_MAP = { C: '2.5.4.6', ST: '2.5.4.8', L: '2.5.4.7', O: '2.5.4.10', OU: '2.5.4.11', CN: '2.5.4.3' };
const OID_REVERSE = Object.fromEntries(Object.entries(OID_MAP).map(([k, v]) => [v, k]));
const OID_EXTENSION_REQUEST = '1.2.840.113549.1.9.14';
const OID_SUBJECT_ALT_NAME = '2.5.29.17';

function keyIdentifier(spkiDer) {
  const outer = read(spkiDer);
  const [, bits] = [...children(outer)];
  return crypto.createHash('sha1').update(bits.content.subarray(1)).digest();
}

// ---- names and extensions ----------------------------------------------------------------------

function name(subject) {
  const rdns = [];
  for (const key of ['C', 'ST', 'L', 'O', 'OU', 'CN']) {
    if (!subject[key]) continue;
    const stringTag = key === 'C' ? TAG.PRINTABLE_STRING : TAG.UTF8_STRING;
    rdns.push(set([seq([oid(OID_MAP[key]), tlv(stringTag, Buffer.from(String(subject[key]), 'utf8'))])]));
  }
  return seq(rdns);
}

function parseName(node) {
  const out = {};
  for (const rdn of children(node)) {
    for (const attr of children(rdn)) {
      const [typeNode, valueNode] = [...children(attr)];
      const key = OID_REVERSE[decodeOid(typeNode.content)];
      if (key) out[key] = valueNode.content.toString('utf8');
    }
  }
  return out;
}

function ipToBuffer(ip) {
  if (!ip.includes(':')) return Buffer.from(ip.split('.').map(Number));
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':').filter(Boolean) : [];
  const t = tail ? tail.split(':').filter(Boolean) : [];
  const groups = ip.includes('::') ? [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t] : ip.split(':');
  const buf = Buffer.alloc(16);
  groups.forEach((g, i) => buf.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return buf;
}

function bufferToIp(buf) {
  if (buf.length === 4) return [...buf].join('.');
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(buf.readUInt16BE(i).toString(16));
  return groups.join(':');
}

function generalNames(altNames) {
  return seq(altNames.map((entry) => {
    const value = typeof entry === 'string' ? entry : entry.value;
    const type = typeof entry === 'string' ? inferType(value) : entry.type;
    if (type === 'ip') return ctx(7, ipToBuffer(value), false);
    if (type === 'email') return ctx(1, Buffer.from(value, 'ascii'), false);
    if (type === 'uri') return ctx(6, Buffer.from(value, 'ascii'), false);
    return ctx(2, Buffer.from(value, 'ascii'), false);
  }));
}

function parseGeneralNames(node) {
  const out = [];
  for (const child of children(node)) {
    const kind = child.tag & 0x1f;
    if (kind === 2 || kind === 1 || kind === 6) out.push(child.content.toString('ascii'));
    else if (kind === 7) out.push(bufferToIp(child.content));
  }
  return out;
}

function inferType(value) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || (value.includes(':') && !value.includes('/'))) return 'ip';
  if (value.includes('@')) return 'email';
  if (value.includes('://')) return 'uri';
  return 'dns';
}

const KEY_USAGE_BITS = { digitalSignature: 0, keyEncipherment: 2, keyCertSign: 5, cRLSign: 6 };

function keyUsage(usages) {
  let mask = 0;
  let highest = -1;
  for (const u of usages) { mask |= 0x80 >> KEY_USAGE_BITS[u]; highest = Math.max(highest, KEY_USAGE_BITS[u]); }
  return bitString(Buffer.from([mask]), 7 - (highest % 8));
}

function extension(id, critical, valueDer) {
  const parts = [oid(id)];
  if (critical) parts.push(bool(true));
  parts.push(octets(valueDer));
  return seq(parts);
}

function toPem(der, label) {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

function fromPem(pem) {
  const body = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}

const ECDSA_SHA256 = () => seq([oid('1.2.840.10045.4.3.2')]);

// ---- keys, certificates, CSRs ---------------------------------------------------------------------

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    keyType: 'ec',
    publicKey,
    privateKey,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    publicKeyBuf: publicKey.export({ type: 'spki', format: 'der' }),
  };
}

function issue({ subject, spkiDer, keyPair = null, issuer = null, ca = false, altNames = [], eku = [], validityDays = 365 }) {
  const spki = spkiDer || keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const selfSigned = !issuer;
  const signingKey = selfSigned ? keyPair.privateKey : issuer.privateKey;

  const notBefore = new Date(Date.now() - 60000);
  const notAfter = new Date(notBefore.getTime() + validityDays * 86400000);
  const serial = crypto.randomBytes(16);
  serial[0] = (serial[0] & 0x7f) || 1;

  const extensions = [
    extension('2.5.29.19', true, seq(ca ? [bool(true)] : [])),
    extension('2.5.29.15', true, keyUsage(ca ? ['digitalSignature', 'keyCertSign', 'cRLSign'] : ['digitalSignature', 'keyEncipherment'])),
    extension('2.5.29.14', false, octets(keyIdentifier(spki))),
  ];
  if (eku.length) {
    extensions.push(extension('2.5.29.37', false, seq(eku.map((p) => oid(
      p === 'serverAuth' ? '1.3.6.1.5.5.7.3.1' : p === 'clientAuth' ? '1.3.6.1.5.5.7.3.2' : p,
    )))));
  }
  if (altNames.length) extensions.push(extension(OID_SUBJECT_ALT_NAME, false, generalNames(altNames)));
  if (!selfSigned) {
    const issuerSpki = new crypto.X509Certificate(issuer.certPem).publicKey.export({ type: 'spki', format: 'der' });
    extensions.push(extension('2.5.29.35', false, seq([ctx(0, keyIdentifier(issuerSpki), false)])));
  }

  const tbs = seq([
    ctx(0, integer(Buffer.from([2]))),
    integer(serial),
    ECDSA_SHA256(),
    name(selfSigned ? subject : issuer.subject),
    seq([time(notBefore), time(notAfter)]),
    name(subject),
    spki,
    ctx(3, seq(extensions)),
  ]);

  const certDer = seq([tbs, ECDSA_SHA256(), bitString(crypto.sign('sha256', tbs, signingKey))]);
  const x509 = new crypto.X509Certificate(certDer);
  return {
    certPem: toPem(certDer, 'CERTIFICATE'),
    privateKeyPem: keyPair?.privateKeyPem,
    privateKey: keyPair?.privateKey,
    subject,
    notAfter,
    serialNumber: x509.serialNumber,
    fingerprint256: x509.fingerprint256,
  };
}

/** PKCS#10 (RFC 2986), with SANs carried in the extensionRequest attribute. */
function createCsr({ keyPair, subject, altNames = [] }) {
  const spki = keyPair.publicKey.export({ type: 'spki', format: 'der' });

  const attributes = altNames.length
    ? ctx(0, seq([oid(OID_EXTENSION_REQUEST), set([seq([extension(OID_SUBJECT_ALT_NAME, false, generalNames(altNames))])])]))
    : ctx(0, Buffer.alloc(0));

  const info = seq([integer(Buffer.from([0])), name(subject), spki, attributes]);
  // Self-signed with the key being certified: this signature IS the proof of possession the
  // enrolment service checks.
  const signature = crypto.sign('sha256', info, keyPair.privateKey);
  return toPem(seq([info, ECDSA_SHA256(), bitString(signature)]), 'CERTIFICATE REQUEST');
}

function parseCsr(csrPem) {
  const der = fromPem(csrPem);
  const outer = read(der);
  const [info, , signatureNode] = [...children(outer)];
  const [, subjectNode, spkiNode, attributesNode] = [...children(info)];

  const altNames = [];
  if (attributesNode && (attributesNode.tag & 0x1f) === 0) {
    for (const attribute of children(attributesNode)) {
      const [attrOid, attrValues] = [...children(attribute)];
      if (decodeOid(attrOid.content) !== OID_EXTENSION_REQUEST) continue;
      for (const extensionsNode of children(attrValues)) {
        for (const ext of children(extensionsNode)) {
          const parts = [...children(ext)];
          if (decodeOid(parts[0].content) !== OID_SUBJECT_ALT_NAME) continue;
          const value = parts[parts.length - 1];
          altNames.push(...parseGeneralNames(read(value.content)));
        }
      }
    }
  }

  const publicKey = crypto.createPublicKey({ key: spkiNode.full, format: 'der', type: 'spki' });
  let verified = false;
  try { verified = crypto.verify('sha256', info.full, publicKey, signatureNode.content.subarray(1)); }
  catch (_) { verified = false; }

  return {
    subject: parseName(subjectNode),
    altNames,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    spkiDer: spkiNode.full,
    verified,
  };
}

// ---- the two interfaces @fitfak/database actually consumes -------------------------------------

/** A CaBackend (see src/provisioning/ca-backend.js) backed by a local self-signed root. */
function createTestCaBackend({ caSubject = { CN: 'fitfak test CA', O: 'fitfak' } } = {}) {
  const caKey = generateKeyPair();
  const ca = issue({ subject: caSubject, keyPair: caKey, ca: true, validityDays: 3650 });
  const issuer = { certPem: ca.certPem, privateKey: caKey.privateKey, subject: caSubject };
  const issued = [];

  return {
    name: 'test-ca',
    ca,
    issuer,
    issued,
    issueDirect: (opts) => issue({ ...opts, issuer }),

    async getTrustAnchors() {
      return { chainPem: [ca.certPem], fingerprints: [ca.fingerprint256] };
    },

    async parseCsr(csrPem) { return parseCsr(csrPem); },

    async issue({ csrPem, validityDays = 397 }) {
      const parsed = parseCsr(csrPem);
      if (!parsed.verified) throw new Error('test-ca: refusing to sign a CSR whose self-signature does not verify');
      const cert = issue({
        subject: parsed.subject,
        spkiDer: parsed.spkiDer,
        issuer,
        altNames: parsed.altNames,
        eku: ['clientAuth'],
        validityDays,
      });
      issued.push({ subject: parsed.subject, serialNumber: cert.serialNumber });
      return { certPem: cert.certPem, chainPem: [ca.certPem], notAfter: cert.notAfter, serialNumber: cert.serialNumber };
    },
  };
}

/** A CsrProvider (see src/provisioning/csr-provider.js). */
function createTestCsrProvider() {
  return {
    name: 'test-csr',
    async generateKeyPair() { return generateKeyPair(); },
    async createCsr({ keyPair, subject, altNames }) { return createCsr({ keyPair, subject, altNames }); },
  };
}

/** Server-side TLS material issued by the same test CA. */
function createServerIdentity(caBackend, { commonName = 'localhost', altNames = ['localhost', '127.0.0.1', '::1'] } = {}) {
  const keyPair = generateKeyPair();
  const cert = caBackend.issueDirect({
    subject: { CN: commonName, O: 'fitfak' }, keyPair, altNames, eku: ['serverAuth'],
  });
  return {
    ...cert,
    // requestCert asks every client for a certificate; rejectUnauthorized:false lets a peer
    // that has none complete the handshake, so the enrolment endpoints stay reachable while
    // the data plane's mtls requirement keeps everything else closed.
    tlsOptions: {
      key: cert.privateKeyPem,
      cert: cert.certPem,
      ca: caBackend.ca.certPem,
      requestCert: true,
      rejectUnauthorized: false,
    },
    strictTlsOptions: {
      key: cert.privateKeyPem,
      cert: cert.certPem,
      ca: caBackend.ca.certPem,
      requestCert: true,
      rejectUnauthorized: true,
    },
  };
}

module.exports = {
  generateKeyPair, issue, createCsr, parseCsr, toPem, fromPem,
  createTestCaBackend, createTestCsrProvider, createServerIdentity,
};
