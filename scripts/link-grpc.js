'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Links a side-by-side checkout of @fitfak/grpc into node_modules.
//
// @fitfak/database depends on @fitfak/grpc for its transport layer. Until that package is
// published to the registry, a developer working on both at once needs the local checkout
// wired in -- and `npm link` leaves global state behind that is easy to forget about and
// hard to notice when it goes stale. A symlink inside this project's own node_modules is
// scoped to this project and disappears with it.
//
//   node scripts/link-grpc.js [path-to-grpc-checkout]
//
// Default search order: ../grpc, ../fitfak-grpc, then $FITFAK_GRPC_PATH.

const candidates = [
  process.argv[2],
  process.env.FITFAK_GRPC_PATH,
  path.resolve(__dirname, '..', '..', 'grpc'),
  path.resolve(__dirname, '..', '..', 'fitfak-grpc'),
].filter(Boolean);

const source = candidates.find((candidate) => {
  try { return fs.existsSync(path.join(candidate, 'package.json')) && require(path.join(candidate, 'package.json')).name === '@fitfak/grpc'; }
  catch (_) { return false; }
});

if (!source) {
  console.error('Could not find a @fitfak/grpc checkout. Looked in:');
  for (const candidate of candidates) console.error(`  ${candidate}`);
  console.error('\nPass the path explicitly:  node scripts/link-grpc.js /path/to/grpc');
  process.exit(1);
}

const target = path.resolve(__dirname, '..', 'node_modules', '@fitfak', 'grpc');
fs.mkdirSync(path.dirname(target), { recursive: true });
// Replace whatever is there: a stale link to a moved checkout fails in ways that look like a
// broken dependency rather than a broken link.
try { fs.rmSync(target, { recursive: true, force: true }); } catch (_) {}
fs.symlinkSync(source, target, 'junction');

console.log(`linked @fitfak/grpc -> ${source}`);
