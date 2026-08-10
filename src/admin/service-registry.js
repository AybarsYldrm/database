'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

const spiffe = require('../provisioning/spiffe');

// Which services exist, what identity each may hold, and what it may do.
//
// This is the list that used to be a hard-coded `SERVICES` object at the top of db-server.js.
// Moving it here is what makes "register a new application" something an operator does in a
// panel rather than an edit-and-restart. The pressure that removes is worth naming: when adding
// a service means restarting the database, operators stop adding services one at a time and
// start raising `maxUses` on an existing credential instead — turning a single-shot bootstrap
// secret into a standing key to the identity system.
//
// The registry hands the enrolment attestor a LIVE Map (see createSharedSecretAttestor), so a
// service registered here is enrollable on its next request with nothing restarted.
//
//
// WHAT IS AND IS NOT STORED
//
// Stored: the service name, its SPIFFE ID, its roles, its SAN list, how many times its
// credential may be used, and how many times it has been.
//
// Also stored: the enrolment secret itself, base64, in a 0600 file. That is a real exposure and
// it is the same one the previous `enrolment-secrets.json` had — the credential has to survive a
// restart or the service cannot be provisioned after one. What reduces it is that the secret is
// single-use by default and spent the moment the service first enrols; after that the file holds
// a value that no longer opens anything. `revealSecret` exists so the panel can show it once,
// and the panel is explicit that it will not show it again.

const DEFAULT_FILE = 'services.json';

class ServiceRegistry extends EventEmitter {
  /**
   * @param {object}  opts
   * @param {string}  opts.stateDir      where services.json lives
   * @param {string} [opts.trustDomain]  used to build SPIFFE IDs for new services
   * @param {string} [opts.file]
   */
  constructor({ stateDir, trustDomain = 'fitfak.net', file = DEFAULT_FILE }) {
    super();
    if (!stateDir) throw new Error('fitdb registry: a stateDir is required');
    this.stateDir = stateDir;
    this.trustDomain = trustDomain;
    this.file = path.join(stateDir, file);

    // The live map the attestor holds by reference. Keys are service names; values are the
    // shape createSharedSecretAttestor expects, with `secret` as a Buffer.
    this.enrolments = new Map();
    // The same services as the principal allow-list the data plane checks. Kept as a plain
    // object because createPrincipalResolver takes one and copies it into a Map at
    // construction — so this one is rebuilt, not mutated. See `principals()`.
    this._services = new Map();
  }

  static async open(options) {
    const registry = new ServiceRegistry(options);
    await registry.load();
    return registry;
  }

  // ---- persistence --------------------------------------------------------------------------

  async load() {
    await fsp.mkdir(this.stateDir, { recursive: true, mode: 0o700 });
    if (!fs.existsSync(this.file)) return this;

    let raw;
    try {
      raw = JSON.parse(await fsp.readFile(this.file, 'utf8'));
    } catch (err) {
      // Overwriting an unreadable registry would silently de-provision every service. Stop and
      // let an operator look at it.
      throw new Error(`fitdb registry: ${this.file} exists but could not be parsed (${err.message}). `
        + 'Refusing to overwrite it.');
    }

    for (const entry of raw.services || []) this._install(entry);
    return this;
  }

  async save() {
    const payload = {
      version: 1,
      savedAt: Date.now(),
      services: [...this._services.values()].map((service) => ({
        ...service,
        secret: service.secret ? service.secret.toString('base64') : null,
      })),
    };
    await fsp.mkdir(this.stateDir, { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.tmp`;
    // 0600 and temp-then-rename: writing in place leaves a half-written file if the process
    // dies mid-write, and the next start finds it "present but corrupt" — which the loader
    // above deliberately refuses to overwrite.
    await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
    await fsp.rename(tmp, this.file);
    return this;
  }

  _install(entry) {
    const service = {
      name: entry.name,
      spiffeId: entry.spiffeId,
      kind: entry.kind || 'service',
      roles: entry.roles || [],
      altNames: entry.altNames || [],
      maxUses: entry.maxUses ?? 1,
      uses: entry.uses || 0,
      enabled: entry.enabled !== false,
      description: entry.description || '',
      createdAt: entry.createdAt || Date.now(),
      rotatedAt: entry.rotatedAt || null,
      enrolledAt: entry.enrolledAt || null,
      secret: entry.secret ? Buffer.from(entry.secret, 'base64') : null,
    };
    this._services.set(service.name, service);
    this._syncEnrolment(service);
    return service;
  }

  /**
   * Mirrors one service into the live enrolment map the attestor reads.
   *
   * A disabled service is REMOVED from that map rather than flagged in it. The attestor has no
   * concept of "disabled", and adding one would mean a second place that decides whether a
   * credential works — the kind of split where one of the two eventually stops being checked.
   */
  _syncEnrolment(service) {
    if (!service.enabled || !service.secret) {
      this.enrolments.delete(service.name);
      return;
    }
    // The SAME object the attestor increments `uses` on, so a use recorded during enrolment is
    // visible here and gets persisted by `recordUse`.
    this.enrolments.set(service.name, {
      secret: service.secret,
      subject: { CN: service.name },
      spiffeId: service.spiffeId,
      altNames: service.altNames,
      roles: service.roles,
      maxUses: service.maxUses,
      get uses() { return service.uses; },
      set uses(value) { service.uses = value; },
    });
  }

  // ---- reading ------------------------------------------------------------------------------

  /** The allow-list shape the principal resolver takes. Rebuilt on every call, never mutated. */
  principals() {
    const out = {};
    for (const service of this._services.values()) {
      if (!service.enabled) continue; // removing an entry locks that certificate out immediately
      out[service.name] = { roles: service.roles, spiffeId: service.spiffeId };
    }
    return out;
  }

  /** For the panel. Never includes the secret — see `revealSecret`. */
  list() {
    return [...this._services.values()].map((service) => ({
      name: service.name,
      spiffeId: service.spiffeId,
      // What this principal IS, not just what it is called. It decides the SPIFFE path segment
      // (`/service/dns-resolver` vs `/app/reports`) and it is how the panel separates
      // infrastructure from the applications an operator registers day to day. Defaulted rather
      // than required, so registry files written before this field existed still load.
      kind: service.kind || 'service',
      roles: service.roles,
      altNames: service.altNames,
      maxUses: service.maxUses,
      uses: service.uses,
      enabled: service.enabled,
      description: service.description,
      createdAt: service.createdAt,
      rotatedAt: service.rotatedAt,
      enrolledAt: service.enrolledAt,
      hasSecret: !!service.secret,
      // The single most useful column: a service whose credential is spent and which has never
      // enrolled is a provisioning that failed silently.
      credentialSpent: service.maxUses > 0 && service.uses >= service.maxUses,
    })).sort((a, b) => a.name.localeCompare(b.name));
  }

  get(name) { return this._services.get(name) || null; }

  // ---- writing ------------------------------------------------------------------------------

  /**
   * Registers a service and returns its enrolment secret ONCE.
   *
   * The SPIFFE ID is derived rather than accepted from the caller unless one is given
   * explicitly, and either way it is validated: a service name arriving from a form is exactly
   * how a slash gets into a path segment and quietly deepens an identity.
   */
  async create({
    name, roles = ['reader'], altNames = [], maxUses = 1, description = '',
    spiffeId = null, kind = 'service',
  }) {
    if (!name || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(name)) {
      throw new Error("a service name must be lowercase letters, digits and hyphens, 2-63 characters");
    }
    if (this._services.has(name)) throw new Error(`a service named '${name}' already exists`);

    const identity = spiffeId
      ? spiffe.parse(spiffeId)
      : spiffe.build(this.trustDomain, kind, name);
    if (identity.trustDomain !== this.trustDomain) {
      throw new Error(`'${identity}' belongs to trust domain '${identity.trustDomain}', not '${this.trustDomain}'`);
    }

    const secret = crypto.randomBytes(32);
    const service = this._install({
      name,
      spiffeId: identity.uri,
      kind,
      roles,
      // The SPIFFE ID is always in the SAN list: it is the identity the certificate will
      // actually carry, and the enrolment service refuses a CSR that omits the granted one.
      altNames: [identity.uri, name, ...altNames.filter((n) => n !== name)],
      maxUses,
      description,
      createdAt: Date.now(),
      secret: secret.toString('base64'),
    });
    await this.save();
    this.emit('created', { name, spiffeId: identity.uri });

    return { service: this.list().find((s) => s.name === name), secret: secret.toString('base64') };
  }

  /**
   * Issues a fresh secret and resets the use count.
   *
   * Resetting the count is the whole point and is why the count lives on the entry rather than
   * in a map beside it: a rotation that left the old count in place would hand the operator a
   * new credential that is refused as "already used".
   */
  async rotateSecret(name) {
    const service = this._services.get(name);
    if (!service) throw new Error(`no service named '${name}'`);
    const secret = crypto.randomBytes(32);
    service.secret = secret;
    service.uses = 0;
    service.rotatedAt = Date.now();
    this._syncEnrolment(service);
    await this.save();
    this.emit('rotated', { name });
    return { secret: secret.toString('base64') };
  }

  async update(name, patch) {
    const service = this._services.get(name);
    if (!service) throw new Error(`no service named '${name}'`);
    if (patch.roles !== undefined) service.roles = patch.roles;
    if (patch.altNames !== undefined) {
      service.altNames = [service.spiffeId, name, ...patch.altNames.filter((n) => n !== name && n !== service.spiffeId)];
    }
    if (patch.maxUses !== undefined) service.maxUses = Number(patch.maxUses);
    if (patch.description !== undefined) service.description = String(patch.description);
    if (patch.enabled !== undefined) service.enabled = !!patch.enabled;
    this._syncEnrolment(service);
    await this.save();
    this.emit('updated', { name });
    return this.list().find((s) => s.name === name);
  }

  /**
   * Removes a service. Its certificate stops being accepted on the next connection, however
   * long it remains cryptographically valid — the allow-list is the revocation mechanism at
   * this layer, which is adequate for a closed set of known services and is why the set is
   * kept closed.
   */
  async remove(name) {
    if (!this._services.has(name)) throw new Error(`no service named '${name}'`);
    this._services.delete(name);
    this.enrolments.delete(name);
    await this.save();
    this.emit('removed', { name });
    return { removed: true, name };
  }

  /** Records that a credential was spent, so the panel can show it. */
  async recordUse(name) {
    const service = this._services.get(name);
    if (!service) return;
    service.enrolledAt = Date.now();
    await this.save();
  }
}

module.exports = { ServiceRegistry, DEFAULT_FILE };
