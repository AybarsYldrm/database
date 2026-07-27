'use strict';

const crypto = require('node:crypto');
const { GRPC_STATUS, GrpcError, SECURITY_LEVELS } = require('@fitfak/grpc');
const { DB_PERMISSIONS, combine } = require('../rbac');

// Turning an authenticated TLS peer into a principal the database can make decisions about.
//
// The input is `call.peer.certificate`, which the transport populates ONLY when the chain
// validated -- so everything here is working from a verified identity, not from an asserted
// one. What remains is a policy question the transport cannot answer: which certificates map
// to which principals, and what may each principal do.
//
// Three layers, each optional and each narrowing the previous one:
//
//   1. subject extraction  - which field of the certificate names the principal
//   2. allow-list          - which principals may connect at all, and with what roles
//   3. permission mapping  - roles to a DB_PERMISSIONS bitmask
//
// Revocation deserves a note. This package has no CRL or OCSP client; the revocation
// mechanism at this layer is the allow-list -- removing a principal from it locks that
// certificate out on its next connection regardless of how long it remains cryptographically
// valid. That is a real mechanism for a closed set of known services and an inadequate one
// for anything larger, where the CA's own revocation infrastructure (which @fitfak/ssl
// implements) is what you actually want in front of this.

const ROLE_PERMISSIONS = Object.freeze({
  reader: DB_PERMISSIONS.READ,
  writer: combine(DB_PERMISSIONS.READ, DB_PERMISSIONS.WRITE),
  editor: combine(DB_PERMISSIONS.READ, DB_PERMISSIONS.WRITE, DB_PERMISSIONS.DELETE),
  schema: combine(DB_PERMISSIONS.READ, DB_PERMISSIONS.WRITE, DB_PERMISSIONS.CREATE_COLLECTION, DB_PERMISSIONS.DROP_COLLECTION),
  issuer: DB_PERMISSIONS.ISSUE_CAPABILITY,
  sharer: DB_PERMISSIONS.SHARE,
  admin: DB_PERMISSIONS.ADMIN,
});

/**
 * @param {object}   opts
 * @param {string}  [opts.subjectField='CN']  'CN' | 'OU' | 'O', or 'san:<prefix>' to read a SAN
 * @param {object}  [opts.principals]  { [principalId]: { roles: [], permissions?, databases?: [] } }
 *                                     When present, this is an allow-list: unknown principals
 *                                     are refused even with a perfectly valid certificate.
 * @param {string[]}[opts.defaultRoles] roles for a valid certificate not in `principals`
 * @param {function}[opts.resolve]     full override: (peer) => principal | null
 * @param {string[]}[opts.pinnedIssuers] accept only certificates whose issuer fingerprint is listed
 */
function createPrincipalResolver({
  subjectField = 'CN',
  principals = null,
  defaultRoles = null,
  resolve = null,
  pinnedIssuers = null,
  rolePermissions = ROLE_PERMISSIONS,
} = {}) {
  const registry = principals
    ? (principals instanceof Map ? principals : new Map(Object.entries(principals)))
    : null;

  function permissionsFor(entry, roles) {
    if (entry && entry.permissions !== undefined) return Number(entry.permissions);
    return roles.reduce((mask, role) => mask | (rolePermissions[role] || 0), 0);
  }

  return function resolvePrincipal(peer) {
    if (resolve) return resolve(peer);

    if (peer.securityLevel !== SECURITY_LEVELS.MTLS || !peer.certificate) {
      throw new GrpcError(GRPC_STATUS.UNAUTHENTICATED,
        'this operation requires a mutually authenticated connection with a valid client certificate');
    }

    if (pinnedIssuers && pinnedIssuers.length > 0) {
      const issuerCn = peer.certificate.issuer?.CN || '';
      if (!pinnedIssuers.includes(issuerCn)) {
        throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, `certificates issued by '${issuerCn}' are not accepted here`);
      }
    }

    const id = extractSubject(peer.certificate, subjectField);
    if (!id) {
      throw new GrpcError(GRPC_STATUS.UNAUTHENTICATED, `the client certificate has no '${subjectField}' to identify it by`);
    }

    if (registry) {
      const entry = registry.get(id);
      if (!entry) {
        // A certificate can be cryptographically perfect and still belong to a service that
        // has been decommissioned or revoked. The allow-list is the enforcement point.
        throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED, `'${id}' is not an authorised principal on this server`);
      }
      const roles = entry.roles || [];
      return {
        id,
        roles,
        permissions: permissionsFor(entry, roles),
        databases: entry.databases || null, // null = every database this principal's ACL allows
        certificate: peer.certificate,
        fingerprint: peer.certificate.fingerprint256,
      };
    }

    const roles = defaultRoles || ['reader'];
    return {
      id,
      roles,
      permissions: permissionsFor(null, roles),
      databases: null,
      certificate: peer.certificate,
      fingerprint: peer.certificate.fingerprint256,
    };
  };
}

function extractSubject(certificate, field) {
  if (field.startsWith('san:')) {
    const prefix = field.slice(4).toLowerCase();
    const match = certificate.altNames.find((name) => name.toLowerCase().startsWith(`${prefix}:`));
    return match ? match.slice(prefix.length + 1).trim() : null;
  }
  return certificate.subject?.[field] || null;
}

/**
 * Ensures a principal has an entry in a database's ACL. A certificate proves *who* a caller
 * is; the ACL decides what they may do with a particular database, and the two are separate
 * on purpose -- adding a new service should not require re-issuing anyone's certificate.
 */
function ensureAclEntry(database, principal) {
  if (database.acl.maskFor(principal.id) === 0 && principal.permissions > 0) {
    database.acl.grant(principal.id, principal.permissions);
  }
  return database.acl.maskFor(principal.id);
}

function requirePermission(database, principal, permission, operation) {
  const mask = database.acl.maskFor(principal.id);
  const allowed = (mask & permission) === permission || (mask & DB_PERMISSIONS.ADMIN) === DB_PERMISSIONS.ADMIN;
  if (!allowed) {
    throw new GrpcError(GRPC_STATUS.PERMISSION_DENIED,
      `'${principal.id}' is not permitted to ${operation} on database '${database.dbId}'`);
  }
}

/** Stable, non-reversible identifier for a certificate, for audit logs. */
function certificateThumbprint(certificate) {
  if (!certificate?.fingerprint256) return null;
  return crypto.createHash('sha256').update(certificate.fingerprint256).digest('hex').slice(0, 16);
}

module.exports = {
  createPrincipalResolver,
  ensureAclEntry,
  requirePermission,
  certificateThumbprint,
  extractSubject,
  ROLE_PERMISSIONS,
};
