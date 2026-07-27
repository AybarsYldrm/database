'use strict';

// Schema evolution.
//
// The failure this exists to prevent: `defineCollection` used to return the existing
// collection unchanged whenever one was already open, so calling it again with an extra field
// was a silent no-op. The new field was not in the in-memory schema, so the TLV encoder had no
// tag for it and dropped it on write, `get()` never returned it, and `find()` on it threw
// "no such field". Nothing anywhere reported a problem -- the data was simply gone. Adding a
// field to a schema registry and redeploying is a completely ordinary thing to do, and it has
// to either work or fail loudly.
//
// The wire format makes most of this safe if the rules are respected, and catastrophic if they
// are not. Field NUMBER is identity: it is what is written to disk, and the name only exists
// in the schema. So:
//
//   - Adding a number that has never been used is always safe. Records written before it
//     simply lack the field, which decodes as absent -- the same as protobuf.
//   - Reusing a number for a different type is never safe. Every record already on disk
//     carries bytes under that tag, and they will be decoded as whatever the new type says.
//     There is no version of this that produces correct data, so it is refused outright.
//   - Removing a number is safe on the wire but the number must then be RESERVED forever.
//     Handing it to a new field later is the "reuse" case above, arriving months later and
//     looking like a fresh addition.
//
// Anything that only changes how a field is indexed is recoverable by rebuilding the index
// from the records themselves, which costs one pass but is always correct.

const RESERVED_FIELD_NO = 1; // '_id', managed by the engine

const SAFETY = Object.freeze({
  SAFE: 'safe',           // no data touched, no index work
  REINDEX: 'reindex',     // records are fine; indexes must be rebuilt from them
  BREAKING: 'breaking',   // would misread or destroy data already on disk
});

class SchemaMigrationError extends Error {
  constructor(message, changes) {
    super(message);
    this.name = 'SchemaMigrationError';
    this.changes = changes;
  }
}

// Two fields with the same number describe the same bytes on disk. If the wire type differs,
// existing records decode as garbage; if only the JS representation differs (int32 -> int64
// changes Number to BigInt), callers silently start seeing a different type for old records.
// Neither is something to do implicitly.
const WIRE_GROUP = {
  bool: 'varint', int32: 'varint', int64: 'varint', uint32: 'varint', uint64: 'varint',
  double: 'fixed64', float: 'fixed32', string: 'len', bytes: 'len',
};

function indexShapeOf(field) {
  return JSON.stringify({
    index: !!field.index,
    blindIndex: !!field.blindIndex,
    rangeBucket: field.rangeBucket ? { width: field.rangeBucket.width } : null,
    diskBacked: !!field.diskBacked,
  });
}

function isIndexed(field) {
  return !!(field.index || field.blindIndex || field.rangeBucket);
}

/**
 * Compares two field lists (excluding the engine-managed `_id`) and classifies every
 * difference. Matching is by field NUMBER, because that is what identifies the bytes on disk;
 * matching by name would read a rename as a delete plus an add, which is exactly the
 * destructive interpretation.
 *
 * @param {Array}  oldFields
 * @param {Array}  newFields
 * @param {number[]} [reserved] numbers retired by a previous migration
 * @returns {{ changes, safety, reindexFields, breaking, reservedAdditions }}
 */
function diffSchemas(oldFields, newFields, reserved = []) {
  const oldByNo = new Map(oldFields.filter((f) => f.no !== RESERVED_FIELD_NO).map((f) => [f.no, f]));
  const newByNo = new Map(newFields.filter((f) => f.no !== RESERVED_FIELD_NO).map((f) => [f.no, f]));
  const reservedSet = new Set(reserved);

  const changes = [];
  const reindexFields = new Set();
  const reservedAdditions = [];

  for (const [no, next] of newByNo) {
    const previous = oldByNo.get(no);

    if (!previous) {
      if (reservedSet.has(no)) {
        // The number was used before and retired. Records written back then still carry bytes
        // under this tag, and they would now be read as this new field.
        changes.push({
          kind: 'reuse-reserved', no, field: next.name, safety: SAFETY.BREAKING,
          reason: `field number ${no} was previously used and retired; records still on disk carry bytes under that tag. `
            + `Pick an unused number for '${next.name}'.`,
        });
        continue;
      }
      changes.push({
        kind: 'add-field', no, field: next.name, safety: isIndexed(next) ? SAFETY.REINDEX : SAFETY.SAFE,
        reason: isIndexed(next)
          ? `new indexed field '${next.name}'; the index is built from existing records`
          : `new field '${next.name}'; records written before it simply lack it`,
      });
      if (isIndexed(next)) reindexFields.add(next.name);
      continue;
    }

    if (previous.type !== next.type) {
      const sameWire = WIRE_GROUP[previous.type] === WIRE_GROUP[next.type];
      changes.push({
        kind: 'retype-field', no, field: next.name, from: previous.type, to: next.type, safety: SAFETY.BREAKING,
        reason: sameWire
          ? `field ${no} ('${next.name}') changes from ${previous.type} to ${next.type}. The bytes are compatible but `
            + `every record already stored would start decoding as a different JavaScript type. Add a new field number instead.`
          : `field ${no} ('${next.name}') changes from ${previous.type} to ${next.type}, which is a different wire type. `
            + `Records already on disk would decode as garbage. Add a new field number instead.`,
      });
      continue;
    }

    if (previous.name !== next.name) {
      // Safe on the wire -- the number is unchanged -- but indexes and index snapshots are
      // keyed by name, so the old entries have to be discarded and rebuilt.
      changes.push({
        kind: 'rename-field', no, field: next.name, from: previous.name, to: next.name,
        safety: isIndexed(next) || isIndexed(previous) ? SAFETY.REINDEX : SAFETY.SAFE,
        reason: `field ${no} renamed from '${previous.name}' to '${next.name}'`,
      });
      if (isIndexed(next) || isIndexed(previous)) reindexFields.add(next.name);
    }

    if (indexShapeOf(previous) !== indexShapeOf(next)) {
      changes.push({
        kind: 'change-index', no, field: next.name, safety: SAFETY.REINDEX,
        from: JSON.parse(indexShapeOf(previous)), to: JSON.parse(indexShapeOf(next)),
        reason: `indexing changed on '${next.name}'; the index is rebuilt from existing records`,
      });
      reindexFields.add(next.name);
    }

    if (!previous.required && next.required) {
      // Validation runs on insert, not on records already stored, so this cannot corrupt
      // anything -- but a caller re-inserting an old record will now be rejected.
      changes.push({
        kind: 'add-required', no, field: next.name, safety: SAFETY.SAFE,
        reason: `'${next.name}' is now required; existing records are not revalidated, but new writes must supply it`,
      });
    }
  }

  for (const [no, previous] of oldByNo) {
    if (newByNo.has(no)) continue;
    changes.push({
      kind: 'remove-field', no, field: previous.name, safety: SAFETY.BREAKING,
      reason: `field ${no} ('${previous.name}') was removed. Its bytes remain in every record already written. `
        + `Pass dropFields: ['${previous.name}'] to retire it deliberately; the number is then reserved and can never be reused.`,
    });
    reservedAdditions.push(no);
  }

  const breaking = changes.filter((c) => c.safety === SAFETY.BREAKING);
  const safety = breaking.length ? SAFETY.BREAKING
    : changes.some((c) => c.safety === SAFETY.REINDEX) ? SAFETY.REINDEX
      : SAFETY.SAFE;

  return { changes, safety, reindexFields: [...reindexFields], breaking, reservedAdditions };
}

/**
 * Turns a diff into something the caller can act on, applying whatever the caller has
 * explicitly authorised.
 *
 * @param {object}   opts
 * @param {string[]} [opts.dropFields] names the caller accepts losing; their numbers are reserved
 * @param {boolean}  [opts.allowRetype] force a type change through. Almost always wrong: it
 *   does not rewrite anything, it just stops the refusal, so existing records still decode
 *   under the new type. Present because a collection with no records yet is a legitimate case.
 */
function planMigration(oldFields, newFields, { reserved = [], dropFields = [], allowRetype = false } = {}) {
  const diff = diffSchemas(oldFields, newFields, reserved);
  const dropped = new Set(dropFields);

  const remaining = diff.breaking.filter((change) => {
    if (change.kind === 'remove-field' && dropped.has(change.field)) return false;
    if (change.kind === 'retype-field' && allowRetype) return false;
    return true;
  });

  const authorisedDrops = diff.changes.filter((c) => c.kind === 'remove-field' && dropped.has(c.field));

  return {
    ...diff,
    blocked: remaining,
    // A dropped field's index entries have to go too, so any authorised removal forces a rebuild.
    needsRebuild: diff.reindexFields.length > 0 || authorisedDrops.length > 0,
    newReserved: [...new Set([...reserved, ...authorisedDrops.map((c) => c.no)])].sort((a, b) => a - b),
    applicable: remaining.length === 0,
    changed: diff.changes.length > 0,
  };
}

/** Renders a plan's blockers as a message that says what to do, not just what is wrong. */
function describeBlockers(collectionName, plan) {
  const lines = plan.blocked.map((c) => `  - ${c.reason}`);
  return `fitdb: cannot migrate collection '${collectionName}':\n${lines.join('\n')}`;
}

module.exports = {
  diffSchemas, planMigration, describeBlockers, SchemaMigrationError,
  SAFETY, isIndexed, indexShapeOf, WIRE_GROUP,
};
