'use strict';

// Generalizes the bitmask RBAC pattern already used in server.js (PERMISSIONS / ROLE_MASKS)
// into a reusable primitive, plus a per-resource ACL so every database can carry its own
// owner + shared-grant table instead of a single global role mask.

function defineBitmask(names) {
  const perms = {};
  names.forEach((name, i) => { perms[name] = 1 << i; });
  return Object.freeze(perms);
}

function combine(...masks) { return masks.reduce((a, b) => a | b, 0); }
function has(mask, required) { return (mask & required) === required; }
function hasAny(mask, required) { return (mask & required) !== 0; }

// Permission bits for database-level operations. Deliberately separate from the existing
// gRPC-facing PERMISSIONS in server.js (READ_DATA/WRITE_DATA/...) — that bitmask governs
// *edge-server route* access; this one governs *per-database* access and is what gets
// checked against a database's own ACL and embedded into capability token scopes.
const DB_PERMISSIONS = defineBitmask([
  'READ',               // 1
  'WRITE',              // 2
  'DELETE',             // 4
  'CREATE_COLLECTION',  // 8
  'DROP_COLLECTION',    // 16
  'ISSUE_CAPABILITY',   // 32  - allowed to mint scoped direct-access tokens for this db
  'SHARE',              // 64  - allowed to grant/revoke other users' access
  'ADMIN',              // 128 - full control, implies all of the above
]);

const OWNER_DEFAULT_MASK = combine(...Object.values(DB_PERMISSIONS));

class AccessControlList {
  constructor(ownerId, ownerMask = OWNER_DEFAULT_MASK) {
    this.entries = new Map();
    if (ownerId !== null && ownerId !== undefined) this.entries.set(String(ownerId), ownerMask);
  }

  grant(userId, mask) {
    const key = String(userId);
    this.entries.set(key, (this.entries.get(key) || 0) | mask);
  }

  revoke(userId, mask) {
    const key = String(userId);
    const cur = this.entries.get(key) || 0;
    const next = cur & ~mask;
    if (next === 0) this.entries.delete(key); else this.entries.set(key, next);
  }

  maskFor(userId) { return this.entries.get(String(userId)) || 0; }
  can(userId, required) { return has(this.maskFor(userId), required); }

  toJSON() { return Object.fromEntries(this.entries); }

  static fromJSON(obj) {
    const acl = new AccessControlList(null, 0);
    for (const [k, v] of Object.entries(obj || {})) acl.entries.set(k, Number(v));
    return acl;
  }
}

module.exports = { defineBitmask, combine, has, hasAny, AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK };
