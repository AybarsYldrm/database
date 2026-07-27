'use strict';

const crypto = require('node:crypto');

// Certificates, private keys and other secret material, stored in a fitdb collection.
//
// Why this belongs here rather than in a file on disk: the storage engine already encrypts
// every record under a key derived from the database's DDK, which is itself only reachable
// through a KeyProvider. A private key written into a collection is therefore encrypted at
// rest with the same construction as everything else, and a copy of the data directory is
// useless without the root secret. A PEM file in /etc is not.
//
// What this is NOT: a hardware security module. The material is decrypted into this process's
// memory whenever it is read, exactly like every other record (see the "honest caveat" in the
// README). If the threat model includes a memory dump of a live process, the answer is a
// TPM/HSM-backed signer that never releases the key at all, not a different database.
//
// Two properties that shape the schema:
//
//   - `name` is blind-indexed, so the server can answer "give me the secret called X" without
//     holding a plaintext-searchable table of secret names. It structurally cannot answer
//     "list every secret", which is deliberate -- see listByKind() for what browsing looks like.
//   - Secrets are versioned, never overwritten. Rotation is what a secret store is for, and an
//     overwrite means every consumer that has not yet picked up the new value breaks at the
//     instant of rotation. Keeping the previous version live until it is explicitly retired is
//     what makes a rotation a transition rather than a cutover.

const SECRET_KINDS = Object.freeze({
  CERTIFICATE: 'certificate',
  PRIVATE_KEY: 'private-key',
  SYMMETRIC_KEY: 'symmetric-key',
  API_TOKEN: 'api-token',
  PASSWORD: 'password',
  OTHER: 'other',
});

const SECRET_STATES = Object.freeze({
  ACTIVE: 'active',       // the version consumers should be using
  PENDING: 'pending',     // issued, not yet promoted (staged rotation)
  RETIRED: 'retired',     // superseded, kept so in-flight consumers still verify
  COMPROMISED: 'compromised',
});

const SECRETS_SCHEMA_FIELDS = [
  // Exact-match lookup only. A blind index answers "does a record with this exact value
  // exist"; it cannot enumerate, which is precisely the leakage it exists to prevent.
  { no: 2, name: 'name', type: 'string', blindIndex: true, required: true },
  { no: 3, name: 'versionKey', type: 'string', blindIndex: true }, // `${name}@${version}`
  { no: 4, name: 'kind', type: 'string', index: true, required: true },
  { no: 5, name: 'state', type: 'string', index: true },
  { no: 6, name: 'version', type: 'int32' },
  // The secret itself. Encrypted at rest by the storage engine along with the rest of the record.
  { no: 7, name: 'material', type: 'bytes', required: true },
  { no: 8, name: 'contentType', type: 'string' },
  // Bucketed by day so "what expires this week" is answerable without the server learning
  // exact expiry timestamps -- see the rangeBucket discussion in the README.
  { no: 9, name: 'notAfter', type: 'int64', rangeBucket: { width: 86400000 }, diskBacked: true },
  { no: 10, name: 'notBefore', type: 'int64' },
  { no: 11, name: 'createdAt', type: 'int64' },
  { no: 12, name: 'rotatedAt', type: 'int64' },
  { no: 13, name: 'metadataJson', type: 'string' },
  // For certificates: lets a caller find the key belonging to a certificate, and lets a
  // rotation verify it is pairing the right two records.
  { no: 14, name: 'fingerprint', type: 'string', blindIndex: true },
  { no: 15, name: 'subject', type: 'string' },
];

class SecretStore {
  /**
   * @param {object}  opts
   * @param {object}  opts.database    an open fitdb Database
   * @param {string} [opts.collection] defaults to 'secrets'
   */
  constructor({ database, collection = 'secrets' }) {
    this.database = database;
    this.collectionName = collection;
    this.secrets = database.collection(collection);
  }

  static async defineCollection(database, { collection = 'secrets', ...opts } = {}) {
    return database.defineCollectionAsync(collection, {
      title: 'Secrets',
      description: 'Certificates, keys and other secret material, versioned',
      fields: SECRETS_SCHEMA_FIELDS,
      ...opts,
    });
  }

  static async open(database, options = {}) {
    await SecretStore.defineCollection(database, options);
    return new SecretStore({ database, ...options });
  }

  // ---- writing ----------------------------------------------------------------------------

  /**
   * Stores a new version of `name`. The previous active version is retired rather than
   * deleted, so a consumer that has not yet reloaded keeps verifying against something real.
   *
   * @param {object}  entry
   * @param {string}  entry.name
   * @param {Buffer|string} entry.material
   * @param {string}  entry.kind        one of SECRET_KINDS
   * @param {boolean}[entry.activate=true] false stages the version as PENDING
   */
  async put({ name, material, kind = SECRET_KINDS.OTHER, contentType = '', notAfter = 0, notBefore = 0, metadata = null, activate = true, fingerprint = '', subject = '' }) {
    if (!name) throw new Error('fitdb secrets: name is required');
    if (!material) throw new Error('fitdb secrets: material is required');

    const previous = await this.getActive(name);
    const version = previous ? previous.version + 1 : 1;
    const now = Date.now();

    const id = await this.secrets.insert({
      name,
      versionKey: `${name}@${version}`,
      kind,
      state: activate ? SECRET_STATES.ACTIVE : SECRET_STATES.PENDING,
      version,
      material: Buffer.isBuffer(material) ? material : Buffer.from(material),
      contentType,
      notAfter: BigInt(notAfter || 0),
      notBefore: BigInt(notBefore || 0),
      createdAt: BigInt(now),
      rotatedAt: BigInt(0),
      metadataJson: metadata ? JSON.stringify(metadata) : '',
      fingerprint,
      subject,
    });

    if (activate && previous) {
      await this.secrets.update(previous._id, { ...previous, state: SECRET_STATES.RETIRED, rotatedAt: BigInt(now) });
    }
    return { id, name, version };
  }

  /**
   * Convenience for the case this store exists to serve: an X.509 certificate and its private
   * key, stored as a pair with expiry and fingerprint filled in from the certificate itself.
   * Deriving those rather than trusting the caller means an expiry sweep cannot be defeated by
   * a caller that simply forgot to pass notAfter.
   */
  async putCertificate({ name, certPem, privateKeyPem = null, chainPem = [], metadata = null, activate = true }) {
    const certificate = new crypto.X509Certificate(certPem);
    const notAfter = new Date(certificate.validTo).getTime();
    const notBefore = new Date(certificate.validFrom).getTime();

    const stored = await this.put({
      name,
      material: Buffer.from(certPem, 'utf8'),
      kind: SECRET_KINDS.CERTIFICATE,
      contentType: 'application/x-pem-file',
      notAfter,
      notBefore,
      fingerprint: certificate.fingerprint256,
      subject: certificate.subject.replace(/\n/g, ', '),
      metadata: { ...(metadata || {}), chainPem, serialNumber: certificate.serialNumber },
      activate,
    });

    let key = null;
    if (privateKeyPem) {
      // Same lifetime as the certificate: retiring one without the other leaves a pair that
      // cannot be used, and an expiry sweep that only sees half of it.
      key = await this.put({
        name: `${name}.key`,
        material: Buffer.from(privateKeyPem, 'utf8'),
        kind: SECRET_KINDS.PRIVATE_KEY,
        contentType: 'application/x-pem-file',
        notAfter,
        notBefore,
        fingerprint: certificate.fingerprint256,
        metadata: { pairedWith: name },
        activate,
      });
    }
    return { certificate: stored, key, notAfter, fingerprint: certificate.fingerprint256 };
  }

  /** Promotes a PENDING version to ACTIVE, retiring whichever version was active. */
  async activate(name, version) {
    const target = await this.getVersion(name, version);
    if (!target) throw new Error(`fitdb secrets: '${name}' has no version ${version}`);
    const current = await this.getActive(name);
    const now = Date.now();
    if (current && String(current._id) !== String(target._id)) {
      await this.secrets.update(current._id, { ...current, state: SECRET_STATES.RETIRED, rotatedAt: BigInt(now) });
    }
    await this.secrets.update(target._id, { ...target, state: SECRET_STATES.ACTIVE, rotatedAt: BigInt(now) });
    return this.getActive(name);
  }

  /**
   * Marks every version of a secret compromised. Note what this does NOT do: it does not
   * delete the material, because an incident response needs to know what was exposed, and it
   * does not revoke a certificate at the CA -- that is the CA's job (see @fitfak/ssl's CRL and
   * OCSP support). This is the local half of a revocation, not the whole of one.
   */
  async markCompromised(name, { reason = '' } = {}) {
    const versions = await this.listVersions(name);
    const now = Date.now();
    for (const record of versions) {
      const metadata = record.metadataJson ? JSON.parse(record.metadataJson) : {};
      await this.secrets.update(record._id, {
        ...record,
        state: SECRET_STATES.COMPROMISED,
        rotatedAt: BigInt(now),
        metadataJson: JSON.stringify({ ...metadata, compromisedAt: now, reason }),
      });
    }
    return versions.length;
  }

  // ---- reading ------------------------------------------------------------------------------

  /** The version consumers should use. Null when the secret does not exist or is not active. */
  async getActive(name) {
    const versions = await this.secrets.find('name', name);
    const active = versions.filter((r) => r.state === SECRET_STATES.ACTIVE);
    if (active.length === 0) return null;
    // Defensive: two active versions means a rotation was interrupted mid-write. Serving the
    // newest is the right recovery, and silently serving an arbitrary one is not.
    return active.sort((a, b) => b.version - a.version)[0];
  }

  async getVersion(name, version) {
    return this.secrets.findOne('versionKey', `${name}@${version}`);
  }

  async listVersions(name) {
    const versions = await this.secrets.find('name', name);
    return versions.sort((a, b) => a.version - b.version);
  }

  /** Material of the active version, as a Buffer. */
  async getMaterial(name) {
    const record = await this.getActive(name);
    return record ? record.material : null;
  }

  /** Material of the active version decoded as UTF-8 -- the usual case for PEM. */
  async getText(name) {
    const material = await this.getMaterial(name);
    return material ? material.toString('utf8') : null;
  }

  /** The certificate and key stored together by putCertificate(), ready for a TLS context. */
  async getCertificatePair(name) {
    const certificate = await this.getActive(name);
    if (!certificate) return null;
    const key = await this.getActive(`${name}.key`);
    const metadata = certificate.metadataJson ? JSON.parse(certificate.metadataJson) : {};
    return {
      certPem: certificate.material.toString('utf8'),
      privateKeyPem: key ? key.material.toString('utf8') : null,
      chainPem: metadata.chainPem || [],
      notAfter: Number(certificate.notAfter),
      fingerprint: certificate.fingerprint,
      version: certificate.version,
    };
  }

  /**
   * Browsing goes through `kind`, which is a PLAIN index, not through `name`. That asymmetry
   * is the point: the set of secret *kinds* in use is not sensitive, while the set of secret
   * *names* is, so names get a blind index that cannot enumerate and kinds get one that can.
   */
  async listByKind(kind, { includeRetired = false } = {}) {
    const records = await this.secrets.find('kind', kind);
    return records.filter((r) => includeRetired || r.state === SECRET_STATES.ACTIVE);
  }

  /**
   * Everything expiring within `withinMs`. Built on the bucketed range index, so the server
   * learns which day-bucket a secret expires in, not the exact timestamp; the exact filter is
   * applied after decryption. This is the query that makes automated renewal possible.
   */
  async listExpiring(withinMs = 30 * 86400000, { now = Date.now() } = {}) {
    const records = await this.secrets.findRange('notAfter', now, now + withinMs);
    return records
      .filter((r) => r.state === SECRET_STATES.ACTIVE && Number(r.notAfter) > 0)
      .sort((a, b) => Number(a.notAfter) - Number(b.notAfter));
  }

  /** Already past their notAfter and still marked active -- a renewal that did not happen. */
  async listExpired({ now = Date.now() } = {}) {
    const records = await this.secrets.findRange('notAfter', 1, now);
    return records.filter((r) => r.state === SECRET_STATES.ACTIVE);
  }

  async findByFingerprint(fingerprint) {
    return this.secrets.find('fingerprint', fingerprint);
  }

  /**
   * Push notification of secret changes, so a process holding a certificate in memory learns
   * about a rotation instead of discovering it when the old one expires. Same mechanism as
   * the DNS cache: one subscription, no polling.
   */
  watch(handler) {
    return this.database.watch(this.collectionName, (event) => {
      if (event.op !== 'put' || !event.record) return handler(event);
      return handler({
        ...event,
        secret: {
          name: event.record.name,
          kind: event.record.kind,
          state: event.record.state,
          version: event.record.version,
        },
      });
    });
  }
}

module.exports = { SecretStore, SECRETS_SCHEMA_FIELDS, SECRET_KINDS, SECRET_STATES };
