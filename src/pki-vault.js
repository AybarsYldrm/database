'use strict';

const crypto = require('node:crypto');
const { SecretStore, SECRET_KINDS, SECRET_STATES } = require('./secret-store');

// Certificate authorities that live in the database rather than in files.
//
// The thing this replaces is four files in a directory:
//
//     .certs/root_ca.key   0600
//     .certs/root_ca.crt
//     .certs/sub_ca.key    0600
//     .certs/sub_ca.crt
//
// Those permissions are the entire protection. Anything that can read the filesystem as that
// user reads the root key: a backup job, a container image layer, a volume mounted into a
// sidecar, a log shipper with an over-broad glob, `docker cp`, a path-traversal bug somewhere
// else in the process. And because the file is the authority, a copy of it is a copy of the
// authority -- there is no way to tell that it happened.
//
// Here the same material is a record in the secrets collection, which means it is encrypted at
// rest under a key derived from the database's DDK, which is itself only reachable through a
// KeyProvider holding the root secret. A copy of the data directory is inert without that
// secret. Reads go through the same authenticated path as every other record, so they are
// subject to the same ACLs and appear in the same audit trail.
//
// What this is NOT, and it matters: an HSM. The key is decrypted into this process's memory
// whenever it signs something, exactly like every other record. A threat model that includes
// reading a live process's heap needs a signer that never releases the key -- a TPM, a PKCS#11
// device, a cloud KMS -- and this class is then the wrong tool, not a weaker version of the
// right one. What it does remove is the much more common failure: the key sitting in a file,
// at rest, where it can be copied without anyone noticing.
//
//
// WHY SUB-CAs, AND WHY MORE THAN ONE
//
// The root signs one thing: intermediates. Everything else is signed by an intermediate, and
// there is one intermediate per purpose -- TLS servers, workload identities, human client
// certificates, S/MIME, code signing.
//
// That is not bureaucracy. A CA can be constrained (name constraints, EKU constraints, path
// length), and constraints only mean something if the thing they constrain is narrow. One
// intermediate signing everything can be constrained to nothing. It also means a compromise is
// bounded: retiring the workload intermediate invalidates workload certificates and leaves
// e-mail certificates alone, and the root -- which is what you cannot recover from losing --
// only ever comes out to sign a replacement intermediate.

const DEFAULT_NAMESPACE = 'pki';

const AUTHORITY_ROLES = Object.freeze({
  ROOT: 'root',
  INTERMEDIATE: 'intermediate',
});

/**
 * The purposes an intermediate can be designated for. A certificate request names a purpose;
 * the vault answers with the intermediate designated for it, and refuses if there is none --
 * rather than falling back to "whichever one exists", which is how a single intermediate ends
 * up signing everything again.
 */
const PURPOSES = Object.freeze({
  TLS_SERVER: 'tls-server',
  TLS_CLIENT: 'tls-client',
  WORKLOAD: 'workload',      // short-lived SPIFFE identities
  EMAIL: 'email',            // S/MIME
  CODE_SIGNING: 'code-signing',
  TIMESTAMPING: 'timestamping',
  OCSP: 'ocsp-responder',
});

class PkiVaultError extends Error {
  constructor(message) { super(message); this.name = 'PkiVaultError'; }
}

class PkiVault {
  /**
   * @param {object}  opts
   * @param {SecretStore} opts.secrets
   * @param {string} [opts.namespace]  prefix for every record this vault owns
   * @param {object} [opts.ssl]        @fitfak/ssl, required lazily by the methods that need it
   */
  constructor({ secrets, namespace = DEFAULT_NAMESPACE, ssl = null }) {
    this.secrets = secrets;
    this.namespace = namespace;
    this._ssl = ssl;
    // Parsed signing material, keyed by authority name. Deriving the @fitfak/ssl shape from PEM
    // costs a key import and a DER walk, and an issuer that does it per certificate cannot serve
    // the connection rates short-lived certificates imply. Invalidated on rotation.
    this._signers = new Map();
  }

  static async open(database, { collection = 'secrets', namespace = DEFAULT_NAMESPACE, ssl = null } = {}) {
    const secrets = await SecretStore.open(database, { collection });
    return new PkiVault({ secrets, namespace, ssl });
  }

  get ssl() {
    if (!this._ssl) {
      try {
        // eslint-disable-next-line global-require
        this._ssl = require('@fitfak/ssl');
      } catch (err) {
        throw new PkiVaultError('the PKI vault needs @fitfak/ssl installed, or an `ssl` module '
          + `passed in, to create or load a certificate authority (${err.message})`);
      }
    }
    return this._ssl;
  }

  _name(authorityName) { return `${this.namespace}/${authorityName}`; }

  // ---- creating authorities -------------------------------------------------------------------

  /**
   * Creates the root, once. Refuses if one already exists rather than versioning a new one on
   * top: a second root is not a rotation, it is a second trust anchor, and every certificate
   * issued under the first stops verifying the moment consumers pick up the second. Replacing a
   * root is a deliberate migration with an overlap period, not a call to this method.
   */
  async createRoot({
    name = 'root',
    commonName = 'FITFAK Global Trust Network Root CA G1',
    organization = 'FITFAK',
    country = 'TR',
    curveName = 'P-256',
    trustDomain = null,
  } = {}) {
    const existing = await this.secrets.getActive(this._name(name));
    if (existing) {
      throw new PkiVaultError(`a root authority named '${name}' already exists in this vault. `
        + 'Creating a second one would publish a second trust anchor, not rotate the first.');
    }

    const root = this.ssl.generateEcRootCA({
      curveName, commonName, organization, country, verbose: false,
    });

    await this._store(name, {
      certPem: root.certPem,
      privateKeyPem: this.ssl.ecPrivToPem(root),
      role: AUTHORITY_ROLES.ROOT,
      parent: null,
      purposes: [],
      trustDomain,
    });

    return this.getAuthority(name);
  }

  /**
   * Issues an intermediate from an existing authority (normally the root) and designates it for
   * a set of purposes.
   *
   * This is what the admin panel calls. The root's key is loaded, used, and dropped from the
   * signer cache immediately afterwards -- it has no other job, and keeping it parsed and warm
   * for the life of the process would mean the one key that must never be usable casually is
   * permanently one function call away.
   */
  async createIntermediate({
    name,
    parent = 'root',
    commonName,
    organization = 'FITFAK',
    country = 'TR',
    curveName = 'P-256',
    purposes = [],
    trustDomain = null,
    ocspUrl = null,
    caIssuersUrl = null,
    crlUrls = [],
  }) {
    if (!name) throw new PkiVaultError('createIntermediate needs a name');
    if (!commonName) throw new PkiVaultError('createIntermediate needs a commonName');

    const unknown = purposes.filter((p) => !Object.values(PURPOSES).includes(p));
    if (unknown.length) {
      // A typo in a purpose would otherwise produce an intermediate that exists, looks
      // configured, and is never selected for anything.
      throw new PkiVaultError(`unknown purpose(s): ${unknown.join(', ')}. `
        + `Known purposes: ${Object.values(PURPOSES).join(', ')}`);
    }

    const existing = await this.secrets.getActive(this._name(name));
    if (existing) throw new PkiVaultError(`an authority named '${name}' already exists in this vault`);

    const parentSigner = await this.loadSigner(parent);
    const intermediate = this.ssl.generateEcIntermediateCA(parentSigner, {
      curveName,
      commonName,
      organization,
      country,
      verbose: false,
      // Each link in the chain points at its OWN issuer's revocation information. Pointing a
      // leaf's CRL at the root, or an intermediate's at itself, is the quiet way "revoking an
      // intermediate drops everything under it" stops working at the verifier.
      ...(ocspUrl ? { ocspUrl } : {}),
      ...(caIssuersUrl ? { caIssuersUrl } : {}),
      ...(crlUrls.length ? { crlUrls } : {}),
    });

    await this._store(name, {
      certPem: intermediate.certPem,
      privateKeyPem: this.ssl.ecPrivToPem(intermediate),
      role: AUTHORITY_ROLES.INTERMEDIATE,
      parent,
      purposes,
      trustDomain,
    });

    // The root goes back in its box.
    this._signers.delete(parent);

    return this.getAuthority(name);
  }

  async _store(name, { certPem, privateKeyPem, role, parent, purposes, trustDomain }) {
    await this.secrets.putCertificate({
      name: this._name(name),
      certPem,
      privateKeyPem,
      metadata: {
        pkiRole: role,
        pkiParent: parent,
        pkiPurposes: purposes,
        pkiTrustDomain: trustDomain,
        pkiAuthorityName: name,
      },
    });
    this._signers.delete(name);
  }

  // ---- reading ---------------------------------------------------------------------------------

  /** Metadata and certificate for one authority. Never the private key -- see loadSigner(). */
  async getAuthority(name) {
    const record = await this.secrets.getActive(this._name(name));
    if (!record) return null;
    return describeAuthority(record);
  }

  /**
   * Every authority in this vault.
   *
   * Note how this is done: `kind` is a plain index so it can be enumerated, `name` is a blind
   * index so it cannot. Listing therefore means "fetch every certificate secret and keep the
   * ones carrying PKI metadata", which is a scan of the certificates rather than of the whole
   * store. That asymmetry is deliberate and explained in secret-store.js -- the set of secret
   * kinds is not sensitive, the set of secret names is.
   */
  async listAuthorities({ includeRetired = false } = {}) {
    const records = await this.secrets.listByKind(SECRET_KINDS.CERTIFICATE, { includeRetired });
    return records
      .filter((record) => {
        const metadata = parseMetadata(record);
        return metadata.pkiRole && String(record.name || '').startsWith(`${this.namespace}/`);
      })
      .map(describeAuthority)
      .sort((a, b) => (a.role === b.role ? a.name.localeCompare(b.name) : (a.role === AUTHORITY_ROLES.ROOT ? -1 : 1)));
  }

  /** The intermediate designated for a purpose. */
  async findIssuerForPurpose(purpose) {
    const authorities = await this.listAuthorities();
    const candidates = authorities.filter((a) => a.role === AUTHORITY_ROLES.INTERMEDIATE
      && a.purposes.includes(purpose)
      && a.state === SECRET_STATES.ACTIVE);

    if (candidates.length === 0) {
      throw new PkiVaultError(`no active intermediate authority is designated for '${purpose}'. `
        + 'Create one in the admin panel rather than letting another intermediate cover it -- an '
        + 'intermediate that signs everything can be constrained to nothing.');
    }
    if (candidates.length > 1) {
      // Two issuers for one purpose means issuance is non-deterministic: two requests for the
      // same kind of certificate chain to different intermediates, and a revocation of one
      // silently covers half the population.
      throw new PkiVaultError(`${candidates.length} active intermediates are designated for `
        + `'${purpose}' (${candidates.map((c) => c.name).join(', ')}); exactly one must be`);
    }
    return candidates[0];
  }

  /**
   * The @fitfak/ssl signing shape for an authority: private key, public key, subject DN in DER,
   * subject key identifier, certificate.
   *
   * This is the only method that decrypts a CA private key, which makes it the one place worth
   * auditing for "who can sign as this authority".
   */
  async loadSigner(name) {
    const cached = this._signers.get(name);
    if (cached) return cached;

    const certRecord = await this.secrets.getActive(this._name(name));
    if (!certRecord) throw new PkiVaultError(`no authority named '${name}' in this vault`);
    if (certRecord.state === SECRET_STATES.COMPROMISED) {
      throw new PkiVaultError(`the authority '${name}' is marked compromised and must not sign anything`);
    }

    const keyRecord = await this.secrets.getActive(`${this._name(name)}.key`);
    if (!keyRecord) {
      throw new PkiVaultError(`the authority '${name}' has a certificate but no private key in this `
        + 'vault, so it cannot sign. It may have been imported certificate-only.');
    }

    const certPem = certRecord.material.toString('utf8');
    const keyInfo = this.ssl.pemToEcPriv(keyRecord.material.toString('utf8'));

    const signer = {
      keyType: 'ec',
      curveName: keyInfo.curveName,
      hashAlg: 'sha256',
      privateKey: keyInfo.privateKey,
      publicKeyBuf: keyInfo.publicKeyBuf,
      // The issuer DN that goes into every certificate this authority signs, taken from its own
      // subject. Reconstructing it from the metadata instead would let a metadata edit change
      // what the chain says.
      name: this.ssl.certInfoFromPem(certPem).subjectNameDer,
      skid: this.ssl.asn1.computeEcSKID(keyInfo.publicKeyBuf),
      certPem,
    };

    this._signers.set(name, signer);
    return signer;
  }

  /** The PEM chain a client needs to validate certificates issued by `name`, leaf-first. */
  async getChainPem(name) {
    const chain = [];
    let current = name;
    const seen = new Set();
    while (current) {
      if (seen.has(current)) {
        // A parent cycle would spin here forever. It can only come from hand-edited metadata,
        // which is exactly when a loop is most likely and least expected.
        throw new PkiVaultError(`the authority chain starting at '${name}' contains a cycle at '${current}'`);
      }
      seen.add(current);
      const authority = await this.getAuthority(current);
      if (!authority) throw new PkiVaultError(`the authority chain starting at '${name}' references '${current}', which does not exist`);
      chain.push(authority.certPem);
      current = authority.parent;
    }
    return chain;
  }

  /** Just the root certificate(s) -- what a peer pins or installs as a trust anchor. */
  async getTrustAnchorsPem() {
    const authorities = await this.listAuthorities();
    return authorities.filter((a) => a.role === AUTHORITY_ROLES.ROOT).map((a) => a.certPem);
  }

  // ---- lifecycle -------------------------------------------------------------------------------

  /**
   * Marks an authority compromised. Every version of its key and certificate is flagged, and the
   * signer cache is dropped so nothing already loaded keeps signing with it.
   *
   * What this does NOT do is revoke anything at the parent CA, publish a CRL, or invalidate the
   * certificates already issued underneath. Those are the parent's job and the relying parties'.
   * This is the local half of a revocation and calling it "revoke" would overstate it.
   */
  async markCompromised(name, { reason = '' } = {}) {
    const versions = await this.secrets.markCompromised(this._name(name), { reason });
    await this.secrets.markCompromised(`${this._name(name)}.key`, { reason });
    this._signers.delete(name);
    return { authority: name, versionsMarked: versions };
  }

  /**
   * Brings existing on-disk CA material into the vault, so a deployment that already has
   * `root_ca.key` and friends can migrate without regenerating its trust anchor and
   * re-provisioning every peer.
   *
   * Deliberately does not delete the files: a migration that removes the only copy of a root key
   * before anyone has confirmed the import worked is a migration that can lose a PKI. Removing
   * them is a separate, manual, reversible step -- and the message says so.
   */
  async importAuthority({ name, certPem, privateKeyPem, role, parent = null, purposes = [], trustDomain = null }) {
    if (!certPem || !privateKeyPem) throw new PkiVaultError('importAuthority needs certPem and privateKeyPem');
    const existing = await this.secrets.getActive(this._name(name));
    if (existing) return { imported: false, reason: 'already present', name };

    const certificate = new crypto.X509Certificate(certPem);
    const resolvedRole = role || (certificate.subject === certificate.issuer
      ? AUTHORITY_ROLES.ROOT
      : AUTHORITY_ROLES.INTERMEDIATE);

    await this._store(name, {
      certPem, privateKeyPem, role: resolvedRole, parent, purposes, trustDomain,
    });
    return { imported: true, name, role: resolvedRole, subject: certificate.subject.replace(/\n/g, ', ') };
  }
}

function parseMetadata(record) {
  if (!record?.metadataJson) return {};
  try { return JSON.parse(record.metadataJson); } catch (_) { return {}; }
}

function describeAuthority(record) {
  const metadata = parseMetadata(record);
  return {
    name: metadata.pkiAuthorityName || String(record.name || '').split('/').pop(),
    role: metadata.pkiRole,
    parent: metadata.pkiParent || null,
    purposes: metadata.pkiPurposes || [],
    trustDomain: metadata.pkiTrustDomain || null,
    certPem: record.material.toString('utf8'),
    subject: record.subject || '',
    fingerprint: record.fingerprint || '',
    serialNumber: metadata.serialNumber || '',
    notAfter: Number(record.notAfter),
    notBefore: Number(record.notBefore),
    version: record.version,
    state: record.state,
  };
}

module.exports = { PkiVault, PkiVaultError, AUTHORITY_ROLES, PURPOSES, DEFAULT_NAMESPACE };
