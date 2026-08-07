'use strict';

const { EventEmitter } = require('node:events');
const { GrpcApplication, GRPC_STATUS, GrpcError, SECURITY_LEVELS } = require('@fitfak/grpc');

const { DatabaseManager } = require('../database-manager');
const { ClientSecretKeyProvider } = require('../key-provider');
const { DB_PERMISSIONS } = require('../rbac');
const { CapabilityKeyRing, CapabilityTokenService } = require('../capability-token');
const { SnowflakeGenerator } = require('../snowflake');
const { CHANGE_OPS } = require('../change-stream');
const { DATABASE_SCHEMAS, WATCH_EVENTS, DB_SERVICE_NAME } = require('./schemas');
const { createPrincipalResolver, requirePermission } = require('./identity');
const { adapt, getLevel } = require('../logger');
const { toJson, readPayload, writePayload, recordToJsonObject, recordsToJson } = require('./record-codec');

// The database as a gRPC service.
//
// Shape of the deployment this is built for:
//
//   - The server obtains its own certificate from the central authority. It is not a CA and
//     cannot sign anything; see provisioning/ca-backend.js.
//   - A service that has never connected before reaches the enrolment endpoints over a
//     server-authenticated-only channel, proves entitlement, receives a certificate, and
//     upgrades to mTLS. Nothing in DatabaseService is reachable before that.
//   - From then on the client certificate IS the identity: `principalResolver` maps it to a
//     principal, and the per-database ACL decides what that principal may do.
//
// Every method below therefore declares `minSecurityLevel: 'mtls'`. That is enforced by the
// transport before the handler runs, so it cannot be forgotten in a handler.
//
// ADMISSION, when `options.admission` is configured, adds a step in front of all of that: the
// server starts SEALED, wearing an ephemeral self-signed certificate, and serves nobody until
// the identity provider has connected and handed it a real one. See provisioning/admission-gate.js
// for why the ordering is a requirement rather than a preference. Without `options.admission`
// the server behaves exactly as before, which is the right default for a deployment whose
// certificates are managed entirely outside this process.

const DEFAULT_OPTIONS = {
  packageName: 'custom.network',
  serviceName: DB_SERVICE_NAME,
  baseDir: './fitdb-data',
  sessionTtlMs: 15 * 60 * 1000,
  maxScanLimit: 1000,
  maxFindLimit: 5000,
  watchPingMs: 25000,
  watchBacklogLimit: 512,
  watchSnapshotChunkSize: 500,  // records per snapshot message; keeps it under the wire limit
  strictFields: false,          // reject unknown fields on write instead of dropping them
  autoGrantOwner: true,         // creating a database grants the creating principal ADMIN
  capabilityMaxTtlMs: 120000,
  logger: null,
};

class DatabaseServer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = { ...DEFAULT_OPTIONS, ...options };
    const log = this.options.logger;

    this.snowflake = options.snowflake || new SnowflakeGenerator({ workerId: options.workerId || 1 });
    this.manager = options.manager || new DatabaseManager({
      baseDir: this.options.baseDir,
      snowflake: this.snowflake,
      sessionTtlMs: this.options.sessionTtlMs,
      // Without this the engine logged to its own default destination while the server logged
      // to the operator's -- so the lines that explain a slow or failing request (a discarded
      // snapshot, a whole-field sweep, a collection that never opened) never appeared next to
      // the request they belonged to.
      logger: this.options.logger || undefined,
    });

    this.capabilityKeys = options.capabilityKeyRing || new CapabilityKeyRing();
    this.capabilityTokens = options.capabilityTokens || new CapabilityTokenService(this.capabilityKeys, this.snowflake);

    this.resolvePrincipal = options.principalResolver || createPrincipalResolver({
      principals: options.principals || null,
      defaultRoles: options.defaultRoles || null,
      subjectField: options.subjectField || 'CN',
      pinnedIssuers: options.pinnedIssuers || null,
      trustDomain: options.trustDomain || null,
      requireSpiffeId: options.requireSpiffeId || false,
    });

    // Remembers which secret opened which database, so a session that the manager's TTL has
    // expired can be transparently reopened instead of failing a request that was legitimate
    // a minute ago. Held in memory only, and only for databases this process actually serves.
    this._secrets = new Map(); // dbId -> { secret, ownerId }
    // Adapted, not used as given: `logger: console` is a completely reasonable thing to pass
    // and `console` has no child()/timer(). Going through adapt() means the server gets the
    // full surface while the caller's logger still receives every line.
    this._log = adapt(log, 'fitdb:server');

    this.app = options.app || new GrpcApplication({
      packageName: this.options.packageName,
      minSecurityLevel: SECURITY_LEVELS.MTLS,
      logger: log,
      ...(options.grpc || {}),
    });
    this._ownsApp = !options.app;

    // Admission is set up before the services are registered, because it wraps both the
    // principal resolver (which guards the data plane) and the enrolment attestor (which guards
    // issuance). A wrapper installed after registration would leave whichever service was
    // registered first holding an unwrapped reference, which is the same as having no gate.
    if (options.admission) this._setUpAdmission(options.admission);

    this._registerDatabaseService();
    if (options.enrollment) this._registerEnrollmentService(options.enrollment);
  }

  // ---- admission ----------------------------------------------------------------------------

  /**
   * Starts this server sealed and mounts the control plane that unseals it.
   *
   * @param {object}  admission
   * @param {string}  admission.controlPrincipal   the identity provider's principal name
   * @param {Buffer}  admission.bootstrapSecret    pre-shared with the identity provider
   * @param {object}  admission.bootstrapIdentity  { key, cert, ca, fingerprint256 } -- ephemeral,
   *                                               from provisioning/bootstrap-identity.js
   * @param {string} [admission.controlSpiffeId]
   * @param {number} [admission.holdMs]
   */
  _setUpAdmission(admission) {
    // eslint-disable-next-line global-require
    const { createAdmissionGate } = require('../provisioning/admission-gate');
    // eslint-disable-next-line global-require
    const { createControlPlaneService } = require('../provisioning/control-plane-service');

    const bootstrap = admission.bootstrapIdentity || null;
    // What the server falls back to when a provisioned identity is never committed. Captured
    // once here rather than read from `admission` later, so that a caller mutating their own
    // options object cannot change what "roll back" means after the fact.
    const bootstrapContext = bootstrap
      ? { key: bootstrap.key, cert: bootstrap.cert, ca: bootstrap.ca }
      : null;

    this.gate = createAdmissionGate({
      controlPrincipal: admission.controlPrincipal,
      controlSpiffeId: admission.controlSpiffeId || null,
      holdMs: admission.holdMs,
      logger: this._log,
      installIdentity: ({ key, cert, ca }) => {
        this._clientTrustAnchors = ca;
        this.rotateServerCertificate({ key, cert, ca });
      },
      restoreIdentity: () => {
        if (!bootstrapContext) return;
        this._clientTrustAnchors = bootstrapContext.ca;
        this.rotateServerCertificate(bootstrapContext);
      },
    });

    this.resolvePrincipal = this.gate.wrapPrincipalResolver(this.resolvePrincipal);

    this._controlPlane = createControlPlaneService({
      bootstrapSecret: admission.bootstrapSecret,
      gate: this.gate,
      serverName: admission.serverName || '',
      bootstrapFingerprint: () => bootstrap?.fingerprint256 || '',
      logger: this._log,
    });
    this.app.registerController(admission.serviceName || 'ControlPlaneService', this._controlPlane.controller);

    this.gate.on('opened', (event) => this.emit('admissionOpened', event));
    this.gate.on('sealed', (event) => this.emit('admissionSealed', event));
    return this;
  }

  /**
   * The PEM anchors this server currently validates client certificates against, as installed
   * by the control plane. Null while sealed with no bootstrap identity.
   *
   * Exposed because the CA backend needs them: an enrolling peer is handed these so it can
   * validate this server on its next, mutually authenticated connection, and they arrive from
   * the identity provider rather than from local configuration.
   */
  get clientTrustAnchors() {
    if (!this._clientTrustAnchors) return null;
    const matches = String(this._clientTrustAnchors)
      .match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    return matches ? matches.map((pem) => `${pem}\n`) : null;
  }

  // ---- registration -------------------------------------------------------------------------

  /** Mounts these services onto an existing GrpcApplication instead of running a second one. */
  attachTo(app) {
    this.app = app;
    this._ownsApp = false;
    this._registerDatabaseService();
    if (this.options.enrollment) this._registerEnrollmentService(this.options.enrollment);
    return this;
  }

  _registerEnrollmentService(enrollment) {
    // Required lazily: a deployment whose certificates are managed entirely outside this
    // process has no reason to configure a CA backend, and should not be made to.
    const { createEnrollmentService } = require('../provisioning/enrollment-service');
    // While the server is sealed, issuance is closed to everyone but the identity provider.
    // Without this a service could collect a perfectly valid certificate during the bootstrap
    // window and walk in the instant the gate opened -- the same escalation the gate exists to
    // prevent, deferred by a few seconds.
    const gated = this.gate && !enrollment.controller
      ? {
        ...enrollment,
        attestor: this.gate.wrapAttestor(enrollment.attestor),
        renewalAttestor: enrollment.renewalAttestor ? this.gate.wrapAttestor(enrollment.renewalAttestor) : null,
      }
      : enrollment;

    const service = enrollment.controller
      ? enrollment
      : createEnrollmentService({ logger: this._log, ...gated });

    this.enrollment = service;
    this._enrolmentEnabled = true;
    // Issuance and refusal are logged by the enrolment service itself, which is given this
    // server's logger above -- it holds the detail (kind, method, reason), so logging here
    // too would only print each event twice.
    service.events.on('issued', (event) => this.emit('enrolled', event));
    service.events.on('denied', (event) => this.emit('enrolmentDenied', event));
    this.app.registerController(enrollment.serviceName || 'EnrollmentService', service.controller);
    return this;
  }

  // ---- request plumbing ---------------------------------------------------------------------

  _principal(call) {
    if (!call._principal) call._principal = this.resolvePrincipal(call.peer);
    return call._principal;
  }

  /**
   * Resolves the open database for a request, re-opening it if the manager's session TTL
   * lapsed. The alternative -- returning FAILED_PRECONDITION and making every caller
   * implement re-open-and-retry -- pushes an internal cache lifetime into every client.
   */
  async _database(call, dbId) {
    if (!dbId) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'dbId is required');
    const principal = this._principal(call);

    let database = this.manager.getOpenDatabase(dbId);
    if (!database) {
      const remembered = this._secrets.get(dbId);
      if (!remembered) {
        throw new GrpcError(GRPC_STATUS.FAILED_PRECONDITION,
          `database '${dbId}' is not open on this node; call OpenDatabase with its clientSecret first`);
      }
      database = await this._open({ dbId, ownerId: remembered.ownerId, clientSecret: remembered.secret, principal });
    }

    if (database.acl.effectiveMaskFor(principal.id) === 0) {
      // No ACL entry at all: the certificate is valid and the principal is authorised to talk
      // to this server, but has been granted nothing on this particular database. Reporting
      // NOT_FOUND rather than PERMISSION_DENIED would be friendlier to enumeration, but the
      // database id is already known to the caller here, so there is nothing to hide.
      throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED,
        `'${principal.id}' has no access to database '${dbId}'`);
    }
    return { database, principal };
  }

  async _open({ dbId, ownerId, clientSecret, principal }) {
    let secret;
    try { secret = Buffer.from(clientSecret, 'base64'); }
    catch (_) { throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'clientSecret must be base64'); }
    if (secret.length < 32) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'clientSecret must decode to at least 32 bytes');

    try {
      const database = await this.manager.openDatabase({
        ownerId: ownerId || principal.id,
        dbId,
        requesterId: principal.id,
        keyProvider: new ClientSecretKeyProvider(secret),
        requiredPermission: DB_PERMISSIONS.READ,
      });
      this._secrets.set(dbId, { secret, ownerId: ownerId || principal.id });
      return database;
    } catch (err) {
      // A wrong secret surfaces as an AEAD authentication failure while decrypting the
      // manifest. That is indistinguishable from a corrupt manifest from the outside, and
      // saying "wrong secret" is both more useful and no more revealing than the alternative.
      if (/unsupported state or unable to authenticate|bad decrypt/i.test(err.message)) {
        throw new GrpcError(GRPC_STATUS.UNAUTHENTICATED, 'the supplied clientSecret cannot open this database');
      }
      if (/access denied/i.test(err.message)) {
        throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, `'${principal.id}' is not on this database's access control list`);
      }
      if (/ENOENT/.test(err.message)) throw new GrpcError(GRPC_STATUS.NOT_FOUND, `no database '${dbId}' for that owner`);
      throw err;
    }
  }

  /**
   * Writes an ACL change through to the manifest.
   *
   * The in-memory manifest is updated first, and that is the whole point. This used to persist
   * `{ ...database.manifest, acl: database.acl.toJSON() }` -- a throwaway copy -- so the
   * database's own `manifest.acl` still held the pre-grant table. The next thing to persist the
   * manifest for any other reason (defining a collection, a migration) wrote that stale copy
   * back out, silently undoing the grant on disk while it kept working in memory until the next
   * restart. Sharing a database with a second service is exactly the operation that trips it.
   */
  async _persistAcl(database) {
    database.manifest.acl = database.acl.toJSON();
    await database._persistManifest(database.manifest);
  }

  _collection(database, name) {
    try { return database.collection(name); }
    catch (_) {
      throw new GrpcError(GRPC_STATUS.NOT_FOUND, `collection '${name}' is not defined on database '${database.dbId}'`);
    }
  }

  _registerDatabaseService() {
    const mtls = SECURITY_LEVELS.MTLS;
    const schemas = DATABASE_SCHEMAS;
    const service = this.options.serviceName;
    const self = this;

    // Every method is mTLS-gated by the transport. `requiresAuth` is deliberately NOT used:
    // the identity here comes from the certificate, not from a bearer token, so there is no
    // separate authenticator to run.
    const method = (name, kind = 'unary') => ({
      kind,
      minSecurityLevel: mtls,
      schemas,
      requestType: `${service}_${name}Req`,
      responseType: `${service}_${name}Res`,
    });

    const controller = {
      WhoAmI: {
        ...method('WhoAmI'),
        handler: async (req, call) => {
          const principal = self._principal(call);
          return {
            principal: principal.id,
            roles: principal.roles,
            permissions: principal.permissions,
            securityLevel: call.peer.securityLevel,
            certificateFingerprint: principal.fingerprint || '',
          };
        },
      },

      CreateDatabase: {
        ...method('CreateDatabase'),
        handler: async (req, call) => {
          const principal = self._principal(call);
          if (!req.name) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'name is required');
          const ownerId = req.ownerId || principal.id;
          if (ownerId !== principal.id && (principal.permissions & DB_PERMISSIONS.ADMIN) !== DB_PERMISSIONS.ADMIN) {
            throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'creating a database on behalf of another owner requires ADMIN');
          }

          const { dbId, clientSecret, db } = await self.manager.createDatabase({ ownerId, name: req.name });
          if (self.options.autoGrantOwner && ownerId !== principal.id) db.acl.grant(principal.id, DB_PERMISSIONS.ADMIN);
          self._secrets.set(dbId, { secret: Buffer.from(clientSecret, 'base64'), ownerId });
          self.emit('databaseCreated', { dbId, ownerId, by: principal.id });
          self._log.info({ principal: principal.id, dbId, name: req.name, ownerId, msg: 'database created' });

          // The only time this secret exists anywhere outside the caller's hands. It is not
          // written to disk, not logged, and cannot be recovered if the caller loses it.
          return { dbId, clientSecret, ownerId };
        },
      },

      OpenDatabase: {
        ...method('OpenDatabase'),
        handler: async (req, call) => {
          const principal = self._principal(call);
          if (!req.dbId) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'dbId is required');
          const database = await self._open({
            dbId: req.dbId, ownerId: req.ownerId, clientSecret: req.clientSecret, principal,
          });
          self._log.info({
            principal: principal.id, dbId: req.dbId,
            collections: database.listCollections(),
            msg: 'database opened',
          });
          return {
            message: `database '${database.name}' is open`,
            dbId: req.dbId,
            collections: database.listCollections(),
            sessionExpiresAt: BigInt(Date.now() + self.options.sessionTtlMs),
          };
        },
      },

      CloseDatabase: {
        ...method('CloseDatabase'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.ADMIN, 'close the database');
          await self.manager.closeDatabase(req.dbId);
          self._secrets.delete(req.dbId);
          return { message: `database '${req.dbId}' closed` };
        },
      },

      ListDatabases: {
        ...method('ListDatabases'),
        handler: async (req, call) => {
          const principal = self._principal(call);
          const ownerId = req.ownerId || principal.id;
          if (ownerId !== principal.id && (principal.permissions & DB_PERMISSIONS.ADMIN) !== DB_PERMISSIONS.ADMIN) {
            throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'listing another owner\'s databases requires ADMIN');
          }
          return { payloadJson: toJson(await self.manager.listDatabases(ownerId)) };
        },
      },

      DefineCollection: {
        ...method('DefineCollection'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.CREATE_COLLECTION, 'define a collection');

          let fields;
          try { fields = JSON.parse(req.fieldsJson || '[]'); }
          catch (err) { throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, `fieldsJson is not valid JSON: ${err.message}`); }
          if (!Array.isArray(fields) || fields.length === 0) {
            throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'fieldsJson must be a non-empty array of field definitions');
          }

          const dropFields = req.dropFields || [];

          if (req.dryRun) {
            const plan = database.inspectMigration(req.collection, fields, { dropFields, allowRetype: !!req.allowRetype });
            return {
              message: plan.exists
                ? (plan.applicable ? 'migration would apply' : 'migration would be refused')
                : 'collection would be created',
              created: !plan.exists,
              migrated: !!plan.changed,
              changesJson: toJson(plan.changes || []),
              indexesRebuilt: !!plan.needsRebuild,
              schemaVersion: 0,
              reserved: plan.newReserved || [],
            };
          }

          // applyCollectionSchema rather than defineCollectionAsync: it reports what THIS call
          // did. `collection.migration` describes whichever definition ran most recently, so
          // two clients applying the same migration at once could both claim it as theirs.
          let migration;
          try {
            ({ migration } = await database.applyCollectionSchema(req.collection, {
              fields,
              title: req.title || null,
              description: req.description || null,
              compress: !!req.compress,
              dropFields,
              allowRetype: !!req.allowRetype,
              ...(req.segmentMaxBytes ? { segmentMaxBytes: Number(req.segmentMaxBytes) } : {}),
            }));
          } catch (err) {
            // Both a malformed schema and a refused migration are "your schema is wrong",
            // not a server fault -- and the migration errors carry the remedy in their text.
            throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, err.message);
          }

          const created = !!migration.created;
          if (migration.changed) {
            self.emit('collectionMigrated', {
              dbId: req.dbId, collection: req.collection, by: principal.id, changes: migration.changes,
            });
            self._log.info({
              principal: principal.id, dbId: req.dbId, collection: req.collection,
              changes: migration.changes.map((c) => `${c.kind}(${c.field})`),
              indexesRebuilt: !!migration.rebuilt,
              schemaVersion: migration.schemaVersion,
              msg: 'collection migrated',
            });
          } else if (created) {
            self.emit('collectionDefined', { dbId: req.dbId, collection: req.collection, by: principal.id });
            self._log.info({
              principal: principal.id, dbId: req.dbId, collection: req.collection,
              fields: (req.fields || []).length || undefined,
              msg: 'collection defined',
            });
          }

          return {
            message: created ? `collection '${req.collection}' defined`
              : migration.changed ? `collection '${req.collection}' migrated`
                : `collection '${req.collection}' is already up to date`,
            created,
            migrated: !!migration.changed,
            changesJson: toJson(migration.changes || []),
            indexesRebuilt: !!migration.rebuilt,
            schemaVersion: migration.schemaVersion || database.manifest.collections[req.collection]?.schemaVersion || 1,
            reserved: migration.reserved || database.manifest.collections[req.collection]?.reserved || [],
          };
        },
      },

      DescribeCollection: {
        ...method('DescribeCollection'),
        handler: async (req, call) => {
          const { database } = await self._database(call, req.dbId);
          const collection = self._collection(database, req.collection);
          return {
            payloadJson: toJson({
              name: collection.name,
              title: collection.title,
              description: collection.description,
              // The full schema, so a client can switch to the binary payload form and knows
              // which fields are indexed (and therefore cheap to query).
              fields: collection.schema,
              count: collection.count(),
            }),
          };
        },
      },

      ListCollections: {
        ...method('ListCollections'),
        handler: async (req, call) => {
          const { database } = await self._database(call, req.dbId);
          return { payloadJson: toJson(database.listCollectionInfo()) };
        },
      },

      InsertRecord: {
        ...method('InsertRecord'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.WRITE, 'insert');
          const collection = self._collection(database, req.collection);
          const record = self._read(collection, req);
          const unique = Array.isArray(req.uniqueFields) ? req.uniqueFields.filter(Boolean) : [];
          try {
            const recordId = unique.length
              ? await collection.insertUnique(record, { unique })
              : await collection.insert(record);
            return { recordId };
          } catch (err) {
            // ALREADY_EXISTS rather than INVALID_ARGUMENT: the request was well formed, the
            // state refused it. A caller retrying on INVALID_ARGUMENT would loop forever.
            if (err.code === 'UNIQUE_CONSTRAINT') {
              throw new GrpcError(GRPC_STATUS.ALREADY_EXISTS, err.message);
            }
            throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, err.message);
          }
        },
      },

      GetRecord: {
        ...method('GetRecord'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.READ, 'read');
          const collection = self._collection(database, req.collection);
          const found = await collection.getWithVersion(req.recordId);
          if (!found) return { found: false, payloadJson: '', version: 0 };
          return { ...writePayload(collection.schema, found.value, { binary: req.binary }), version: found.version };
        },
      },

      UpdateRecord: {
        ...method('UpdateRecord'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.WRITE, 'update');
          const collection = self._collection(database, req.collection);

          const current = await collection.getWithVersion(req.recordId);
          if (!current) throw new GrpcError(GRPC_STATUS.NOT_FOUND, `no record '${req.recordId}'`);
          // Without this check, two concurrent read-modify-write clients silently lose one of
          // the writes; with it, the loser is told to re-read.
          if (req.expectedVersion && current.version !== req.expectedVersion) {
            throw new GrpcError(GRPC_STATUS.ABORTED,
              `record '${req.recordId}' is at version ${current.version}, not ${req.expectedVersion}`);
          }

          const patch = self._read(collection, req);
          await collection.update(req.recordId, patch);
          const updated = await collection.getWithVersion(req.recordId);
          return { message: 'record updated', version: updated ? updated.version : 0 };
        },
      },

      DeleteRecord: {
        ...method('DeleteRecord'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.DELETE, 'delete');
          const collection = self._collection(database, req.collection);
          const deleted = await collection.delete(req.recordId);
          return { message: deleted ? 'record deleted' : 'no such record', deleted };
        },
      },

      FindRecord: {
        ...method('FindRecord'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.READ, 'read');
          const collection = self._collection(database, req.collection);
          const limit = clamp(req.limit || self.options.maxFindLimit, 1, self.options.maxFindLimit);

          let records;
          if (req.field === '*' || !req.field) {
            // Full scan. Bounded, because an unbounded one on a large collection means
            // decrypting every record into memory to build one response message.
            records = [];
            for await (const record of collection.scan()) {
              records.push(record);
              if (records.length >= limit) break;
            }
          } else if (req.field === '_id') {
            const one = await collection.get(req.value);
            records = one ? [one] : [];
          } else {
            try { records = await collection.find(req.field, self._coerceQueryValue(collection, req.field, req.value)); }
            catch (err) { throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, err.message); }
            if (records.length > limit) records = records.slice(0, limit);
          }
          return { payloadJson: recordsToJson(collection.schema, records), count: records.length };
        },
      },

      FindRange: {
        ...method('FindRange'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.READ, 'read');
          const collection = self._collection(database, req.collection);
          const min = Number(req.min);
          const max = Number(req.max);
          if (!Number.isFinite(min) || !Number.isFinite(max)) {
            throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'min and max must be numeric');
          }
          const limit = clamp(req.limit || self.options.maxFindLimit, 1, self.options.maxFindLimit);
          try {
            const records = req.plain
              ? await collection.findRangePlain(req.field, min, max, { limit })
              : await collection.findRange(req.field, min, max, { limit });
            return { payloadJson: recordsToJson(collection.schema, records), count: records.length };
          } catch (err) {
            throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, err.message);
          }
        },
      },

      ScanRecords: {
        ...method('ScanRecords'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.READ, 'read');
          const collection = self._collection(database, req.collection);
          const limit = clamp(req.limit || 100, 1, self.options.maxScanLimit);
          const { records, nextCursor } = await collection.scanPage(req.afterId || null, limit);
          return {
            payloadJson: recordsToJson(collection.schema, records),
            nextCursor: nextCursor || '',
            count: records.length,
          };
        },
      },

      CountRecords: {
        ...method('CountRecords'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.READ, 'read');
          return { count: BigInt(self._collection(database, req.collection).count()) };
        },
      },

      Compact: {
        ...method('Compact'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.ADMIN, 'compact');
          const result = await self._collection(database, req.collection).compact();
          return { liveRecords: BigInt(result.liveRecords), segmentsReclaimed: result.segmentsReclaimed };
        },
      },

      WatchCollection: {
        ...method('WatchCollection', 'server_stream'),
        handler: (req, call) => self._watch(req, call),
      },

      IssueCapability: {
        ...method('IssueCapability'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.ISSUE_CAPABILITY, 'issue capability tokens');

          const ownMask = database.acl.effectiveMaskFor(principal.id);
          const scope = Number(req.scope || 0);
          if (!scope) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'scope must be a non-zero DB_PERMISSIONS bitmask');
          // A capability may only ever narrow authority. Without this, ISSUE_CAPABILITY would
          // be a privilege-escalation primitive rather than a delegation one.
          if ((ownMask & scope) !== scope) {
            throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED,
              `'${principal.id}' cannot delegate permissions it does not hold (has ${ownMask}, asked for ${scope})`);
          }

          let rowFilter = null;
          if (req.rowFilterJson) {
            try { rowFilter = JSON.parse(req.rowFilterJson); }
            catch (err) { throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, `rowFilterJson is not valid JSON: ${err.message}`); }
          }

          const ttlMs = clamp(req.ttlMs || 30000, 1000, self.options.capabilityMaxTtlMs);
          const token = self.capabilityTokens.issue({
            sub: req.subject || principal.id,
            dbId: req.dbId,
            collection: req.collection || '*',
            scope,
            ttlMs,
            singleUse: req.singleUse !== false,
            rowFilter,
          });
          return { token, expiresAt: BigInt(Date.now() + ttlMs) };
        },
      },

      GrantAccess: {
        ...method('GrantAccess'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.SHARE, 'share the database');
          if (!req.principal) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'principal is required');
          const ownMask = database.acl.effectiveMaskFor(principal.id);
          const mask = Number(req.mask || 0);
          if (!mask) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'mask must be a non-zero DB_PERMISSIONS bitmask');
          if ((ownMask & mask) !== mask) {
            throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, 'cannot grant permissions you do not hold');
          }
          database.acl.grant(req.principal, mask);
          await self._persistAcl(database);
          self.emit('accessGranted', { dbId: req.dbId, principal: req.principal, mask, by: principal.id });
          return { mask: database.acl.maskFor(req.principal) };
        },
      },

      RevokeAccess: {
        ...method('RevokeAccess'),
        handler: async (req, call) => {
          const { database, principal } = await self._database(call, req.dbId);
          requirePermission(database, principal, DB_PERMISSIONS.SHARE, 'share the database');
          if (!req.principal) throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, 'principal is required');
          database.acl.revoke(req.principal, Number(req.mask || 0));
          await self._persistAcl(database);
          self.emit('accessRevoked', { dbId: req.dbId, principal: req.principal, by: principal.id });
          return { mask: database.acl.maskFor(req.principal) };
        },
      },
    };

    this.app.registerController(service, this._instrument(controller));
    return this;
  }

  /**
   * Wraps every handler so one line describes each request: who asked, what for, on which
   * database and collection, how long it took, and how it ended.
   *
   * Done here rather than in each of the twenty-odd handlers because per-handler logging is
   * exactly the kind that gets added to three of them and forgotten everywhere else. This is
   * also the layer where a failure is still a GrpcError with its status code intact -- by the
   * time it reaches the transport it is a wire frame, and the reason is gone.
   *
   * Successful calls log at DEBUG (a busy server should not narrate itself at INFO), refusals
   * at WARN, and anything unexpected at ERROR with its stack.
   */
  _instrument(controller) {
    const log = this._log;
    if (!log || typeof log.debug !== 'function') return controller;

    const out = {};
    for (const [name, definition] of Object.entries(controller)) {
      if (typeof definition.handler !== 'function') { out[name] = definition; continue; }
      const inner = definition.handler;
      out[name] = {
        ...definition,
        handler: async (req, call) => {
          const startedAt = Date.now();
          // The principal may not resolve yet (WhoAmI on a half-set-up peer); never let
          // logging be the thing that fails a request.
          let who = '?';
          try { who = this._principal(call).id; } catch { /* leave unknown */ }
          const context = {
            rpc: name,
            principal: who,
            dbId: req?.dbId || undefined,
            collection: req?.collection || undefined,
          };
          try {
            const result = await inner(req, call);
            log.debug({ ...context, ms: Date.now() - startedAt, msg: 'rpc ok' });
            return result;
          } catch (err) {
            const ms = Date.now() - startedAt;
            if (err instanceof GrpcError) {
              // An expected refusal: wrong secret, no ACL entry, unknown collection, a
              // migration the caller's schema does not permit. The status code is the useful
              // part and it is only available here.
              log.warn({ ...context, ms, status: err.code, error: err.message, msg: 'rpc refused' });
            } else {
              log.error({ ...context, ms, error: err.message, stack: err.stack, msg: 'rpc failed' });
            }
            throw err;
          }
        },
      };
    }
    return out;
  }

  _read(collection, req) {
    try {
      return readPayload(collection.schema, req, { strict: this.options.strictFields });
    } catch (err) {
      throw new GrpcError(GRPC_STATUS.INVALID_ARGUMENT, err.message);
    }
  }

  // A query value arrives as a string; the index it is looked up in was built over the field's
  // real type, so 'age' => '30' has to become the number 30 or the lookup silently misses.
  _coerceQueryValue(collection, fieldName, value) {
    const field = collection.schema.find((f) => f.name === fieldName);
    if (!field) return value;
    if (field.type === 'int64' || field.type === 'uint64') return BigInt(value);
    if (['int32', 'uint32', 'float', 'double'].includes(field.type)) return Number(value);
    if (field.type === 'bool') return value === 'true' || value === '1';
    return value;
  }

  /**
   * The push alternative to polling, which is what makes an encrypted store usable for data
   * that has to stay current -- a DNS zone, a certificate cache. Polling would re-decrypt
   * unchanged records on every cycle, on both ends, forever.
   *
   * Order matters: subscribe FIRST, then snapshot. Doing it the other way round loses every
   * change that lands in between, and the client has no way to tell.
   */
  async _watch(req, call) {
    const { database, principal } = await this._database(call, req.dbId);
    requirePermission(database, principal, DB_PERMISSIONS.READ, 'watch');
    const collection = this._collection(database, req.collection);

    let buffered = [];
    let streaming = false;
    let dropped = false;

    const send = (payload) => { if (call.isActive()) return call.write({ payloadJson: toJson(payload) }); return false; };

    /**
     * Ships a snapshot as a sequence of bounded chunks rather than one message.
     *
     * A whole collection in a single message is fine right up to the transport's 4 MiB
     * per-message ceiling, past which the write fails with RESOURCE_EXHAUSTED, the stream
     * dies, and the client's watcher reconnects and asks for the same snapshot again -- a
     * loop that re-decrypts every record in the collection on every pass and never makes
     * progress. Chunking removes the ceiling entirely and lets the server yield between
     * batches so a large snapshot does not monopolise the process while other clients wait.
     *
     * `more: true` marks a continuation; the client accumulates until the chunk that omits it.
     */
    const sendSnapshot = async (snapshot) => {
      const size = Math.max(1, Number(this.options.watchSnapshotChunkSize) || 500);
      const total = snapshot.records.length;
      for (let offset = 0; offset < total || offset === 0; offset += size) {
        if (!call.isActive()) return;
        const slice = snapshot.records.slice(offset, offset + size);
        const accepted = send({
          type: WATCH_EVENTS.SNAPSHOT,
          records: slice.map((r) => recordToJsonObject(collection.schema, r)),
          lastSeq: snapshot.lastSeq,
          lastCollSeq: snapshot.lastCollSeq,
          more: offset + size < total,
        });
        // `false` means the socket's send buffer is full. There is no drain signal on this
        // call object, so this is a soft yield rather than true backpressure: it hands the
        // event loop back to everyone else instead of racing ahead and growing the buffer.
        await new Promise((resolve) => setTimeout(resolve, accepted === false ? 5 : 0));
        if (total === 0) return;
      }
    };

    const emit = (event) => {
      if (event.collection !== req.collection) return;
      const message = {
        type: WATCH_EVENTS.CHANGE,
        op: event.op,
        id: event.id,
        seq: event.seq,
        collSeq: event.collSeq,
        version: event.version,
        record: event.op === CHANGE_OPS.PUT ? recordToJsonObject(collection.schema, event.record) : null,
      };
      if (!streaming) {
        // A slow snapshot must not turn into unbounded memory growth. If the buffer overruns,
        // the client is told to re-snapshot rather than handed a stream with a hole in it.
        if (buffered.length >= this.options.watchBacklogLimit) { dropped = true; return; }
        buffered.push(message);
        return;
      }
      send(message);
    };

    const unsubscribe = database.watch(req.collection, emit);
    let ping = null;

    try {
      if (req.resumeSeq && Number(req.resumeSeq) > 0) {
        const replay = database.changes.replay(Number(req.resumeSeq), req.collection);
        if (replay.resumeLost) {
          send({ type: WATCH_EVENTS.RESET, reason: 'resume point is no longer in the change backlog' });
          await sendSnapshot(await database.snapshot(req.collection));
        } else {
          for (const event of replay.events) emit(event);
        }
      } else if (req.includeSnapshot !== false) {
        await sendSnapshot(await database.snapshot(req.collection));
      }

      if (dropped) {
        send({ type: WATCH_EVENTS.RESET, reason: 'change backlog overflowed while the snapshot was being produced' });
        buffered = [];
        dropped = false;
        await sendSnapshot(await database.snapshot(req.collection));
      }

      // Anything that landed during the snapshot and is not already covered by it.
      for (const message of buffered) send(message);
      buffered = [];
      streaming = true;

      // Idle streams get reaped by load balancers and NAT tables. A periodic ping keeps the
      // path open; the client discards these rather than treating them as changes.
      ping = setInterval(() => send({ type: WATCH_EVENTS.PING, at: Date.now() }), this.options.watchPingMs);
      ping.unref?.();

      await new Promise((resolve) => {
        // The stream may already be gone. Building a snapshot is not instantaneous, and a
        // client that disconnects while one is in progress has its 'cancelled' event emitted
        // before this listener exists -- waiting on an event that has already fired stranded
        // the handler permanently, and with it the change-stream subscription and this timer.
        // A watcher client reconnects on its own with backoff, so a flapping connection used
        // to leak one subscription and one interval per attempt, for the life of the process.
        if (!call.isActive()) return resolve();
        call.once('cancelled', resolve);
        call.once('error', resolve);
      });
    } finally {
      if (ping) clearInterval(ping);
      unsubscribe();
    }
  }

  // ---- lifecycle -------------------------------------------------------------------------------

  /**
   * @param {number} port
   * @param {object} [options] `tls`, `host`; anything GrpcServer#listen accepts.
   *
   * For a deployment that serves both the bootstrap and the mutual channel on one port, pass
   * `requestCert: true, rejectUnauthorized: false` -- unauthenticated peers then reach exactly
   * the methods that declare `minSecurityLevel: 'tls'` (the enrolment endpoints) and nothing
   * else. With `rejectUnauthorized: true` the refusal happens during the handshake instead,
   * which is stricter but leaves no way in for a peer that has not enrolled yet.
   */
  listen(port, options = {}) {
    if (!this._ownsApp) throw new Error('fitdb: this server is attached to an external application; call listen() on that instead');
    const tls = options.tls || this.options.tls;
    if (!tls) {
      throw new Error(
        'fitdb: refusing to serve without TLS. The client certificate is the only identity this '
        + 'server has, so a plaintext listener would authenticate nobody. Pass `tls` with at least '
        + '{ key, cert, ca, requestCert: true }.',
      );
    }
    const result = this.app.listen(port, { host: this.options.host || '0.0.0.0', ...options, tls });

    // What a reader of the log needs at startup: where it is listening, whether enrolment is
    // reachable at all, and where the data lives. Previously the server said nothing on its
    // own -- every startup line came from the example script.
    //
    // Deferred to the socket's own 'listening' event rather than logged straight after
    // listen() returns: bind is asynchronous, so address() is not populated yet and `port: 0`
    // (the "pick one for me" request, not the port actually chosen) is what gets printed.
    const announce = () => this._log.info({
      host: this.options.host || '0.0.0.0',
      port: this.address()?.port ?? port,
      baseDir: this.options.baseDir,
      enrolment: this._enrolmentEnabled ? 'enabled' : 'disabled',
      // The single most useful line when nothing can connect: a sealed server refuses every
      // principal by design, and that has to be visible at startup rather than inferred from a
      // wall of FAILED_PRECONDITION on the client side.
      admission: this.gate ? this.gate.state : 'not configured',
      principals: Object.keys(this.options.principals || {}),
      logLevel: getLevel(),
      msg: 'database server listening',
    });
    const socket = this.app.server?.server;
    if (socket && typeof socket.once === 'function' && typeof socket.listening === 'boolean') {
      if (socket.listening) announce();
      else socket.once('listening', announce);
    } else {
      announce();
    }
    return result;
  }

  /**
   * Swaps in a renewed server certificate without dropping connections -- the point of an
   * ACME-managed certificate is that renewal is routine, and a restart every 60 days is not.
   * Existing TLS sessions keep their old certificate until they reconnect, which is correct.
   */
  rotateServerCertificate({ key, cert, ca }) {
    const http2Server = this.app.server?.server;
    if (!http2Server?.setSecureContext) throw new Error('fitdb: the server is not listening on TLS');
    http2Server.setSecureContext({ key, cert, ca, requestCert: true, rejectUnauthorized: false });
    this.emit('certificateRotated', { at: Date.now() });
    return this;
  }

  address() { return this.app.address(); }

  async close(options) {
    // Released first: the hold timer holds a reference to this server, and a shutdown that
    // leaves it armed can fire a re-seal against an application that is already closing.
    this.gate?.close();
    if (this._ownsApp) await this.app.close(options);
    for (const dbId of [...this.manager.openDatabases.keys()]) await this.manager.closeDatabase(dbId);
    this._secrets.clear();
  }
}

function clamp(value, min, max) { return Math.min(max, Math.max(min, Number(value) || min)); }

function createDatabaseServer(options) { return new DatabaseServer(options); }

module.exports = { DatabaseServer, createDatabaseServer };
