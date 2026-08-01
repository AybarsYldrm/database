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

// ADMIN is documented above as "full control, implies all of the above", and identity.js's
// requirePermission() has always honoured that. AccessControlList.can() did not: it ran a
// plain subset test, so a principal granted exactly ADMIN failed `can(id, READ)` -- 128 & 1
// is 0 -- and DatabaseManager.openDatabase, which gates on can(), refused it outright. The
// two authorisation checks in the same request path therefore disagreed, and the practical
// effect was that GrantAccess(principal, ADMIN) produced a principal that could not open the
// database it had just been made an administrator of. Expanding the bit here, in the one
// place that owns the meaning of the mask, keeps every caller consistent.
function expandMask(mask) {
  return has(mask, DB_PERMISSIONS.ADMIN) ? OWNER_DEFAULT_MASK : mask;
}

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
    // Revoking ADMIN has to strip what ADMIN implied, not just clear the bit -- otherwise
    // `revoke(id, ADMIN)` on an entry that only ever held ADMIN leaves 0 (correct), while
    // revoking it from an entry that also holds explicit bits silently keeps full control.
    const next = expandMask(cur) & ~expandMask(mask);
    if (next === 0) this.entries.delete(key); else this.entries.set(key, next);
  }

  /** The grant exactly as stored -- what GrantAccess/RevokeAccess report back. */
  maskFor(userId) { return this.entries.get(String(userId)) || 0; }

  /** The grant with ADMIN expanded -- what every authorisation decision must be made on. */
  effectiveMaskFor(userId) { return expandMask(this.maskFor(userId)); }

  can(userId, required) { return has(this.effectiveMaskFor(userId), required); }

  toJSON() { return Object.fromEntries(this.entries); }

  static fromJSON(obj) {
    const acl = new AccessControlList(null, 0);
    for (const [k, v] of Object.entries(obj || {})) acl.entries.set(k, Number(v));
    return acl;
  }
}

module.exports = {
  defineBitmask, combine, has, hasAny, expandMask,
  AccessControlList, DB_PERMISSIONS, OWNER_DEFAULT_MASK,
};
