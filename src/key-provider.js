'use strict';

const crypto = require('node:crypto');
const { hkdf } = require('./crypto-core');

// The storage engine and DatabaseManager never care *how* a KEK was produced, only that
// they get 32 bytes back for a given database id. That decoupling is what lets key
// management evolve (single-secret today, MLS group tomorrow) without touching a single
// byte of the storage layer, exactly the layering principle the MLS design doc argues for
// ("storage encryption remains constant... only key management changes").
//
// A KeyProvider only has to implement:
//   async deriveKek(dbIdBuf) -> Buffer(32)
//
// --------------------------------------------------------------------------------------
// 1) ClientSecretKeyProvider — what fitdb uses out of the box today.
//
// KEK = HKDF-SHA256(ikm=clientSecret, salt=dbId, info="fitdb-kek-v1")
//
// Appropriate when there is exactly one credential-holder per database (a single operator
// across their own sessions/devices, or a simple bearer-token-per-database model). No group
// membership machinery, no epochs — just a 32-byte secret handed out once at creation time.
class ClientSecretKeyProvider {
  constructor(clientSecret) {
    if (!Buffer.isBuffer(clientSecret) || clientSecret.length < 32) {
      throw new Error('ClientSecretKeyProvider: clientSecret must be a >=32 byte Buffer');
    }
    this.clientSecret = clientSecret;
  }
  async deriveKek(dbIdBuf) {
    return hkdf(this.clientSecret, dbIdBuf, Buffer.from('fitdb-kek-v1'), 32);
  }
}

// --------------------------------------------------------------------------------------
// 2) MlsExportSecretKeyProvider — adapter for when the KEK should come from group key
//    agreement instead of a single static secret (RFC 9420 MLS, per the design doc pasted
//    into this conversation). This is deliberately an ADAPTER, not an MLS implementation:
//    fitdb does not implement MLS itself, it calls into a group object that already does.
//
// KEK = HKDF-SHA256(ikm = mlsGroup.exportSecret(label, context, 32), salt=dbId, info=...)
//
// Assumed interface (adjust the single call site below to match your actual MLS module —
// this is the only place that needs to change):
//   await mlsGroup.exportSecret(label: string, context: Buffer, length: number) -> Buffer
// which is the standard RFC 9420 §8.5 exporter shape (label/context/length), matching what
// the design doc calls exportSecret().
//
// What this buys you over ClientSecretKeyProvider: membership changes become O(1) key
// rotation — when the MLS group's epoch advances (member added/removed), exportSecret()
// changes, so the derived KEK changes, so you re-wrap the *same* DDK under the new KEK.
// No segment file, index, or record is touched. What it does NOT buy you automatically:
// "cryptographically blind" only covers the payload — if any field also uses blindIndex,
// the server still learns which records share an equal value for that field, same as
// before; MLS changes who can reach the KEK, not what the blind index leaks.
//
// For a genuinely single-operator database (one person, own devices/sessions — no other
// members ever), this is very likely more machinery than the problem needs: full epoch
// ratcheting exists to make *group* rekeying on join/leave cheap, which has no payoff with
// a group of one. It earns its keep specifically once RFC 0002's cross-user sharing
// scenario (User A <-> User B via a dedicated shared MLS group) is real. Recommendation:
// stay on ClientSecretKeyProvider for personal/single-owner databases, switch a given
// database to MlsExportSecretKeyProvider only once it actually has >1 legitimate member.
class MlsExportSecretKeyProvider {
  constructor(mlsGroup, { label = 'fitdb-kek', exportLength = 32 } = {}) {
    this.mlsGroup = mlsGroup;
    this.label = label;
    this.exportLength = exportLength;
  }
  async deriveKek(dbIdBuf) {
    // <-- adapt this single call to your MLS library's real exporter signature.
    const exportSecret = await this.mlsGroup.exportSecret(this.label, dbIdBuf, this.exportLength);
    const buf = Buffer.isBuffer(exportSecret) ? exportSecret : Buffer.from(exportSecret);
    return hkdf(buf, dbIdBuf, Buffer.from('fitdb-kek-v1'), 32);
  }
}

// --------------------------------------------------------------------------------------
// 3) StaticKeyProvider — for tests/tools only, wraps an already-known 32-byte KEK directly.
class StaticKeyProvider {
  constructor(kek) { this.kek = kek; }
  async deriveKek() { return this.kek; }
}

function randomClientSecret() { return crypto.randomBytes(32); }

module.exports = { ClientSecretKeyProvider, MlsExportSecretKeyProvider, StaticKeyProvider, randomClientSecret };
