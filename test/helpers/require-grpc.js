'use strict';

// Resolving @fitfak/grpc with a message that says what to do.
//
// A bare MODULE_NOT_FOUND stack from four frames deep tells a reader that something is
// missing, not that the transport package needs linking, so every test that needs the
// transport goes through here instead of requiring it directly.

function requireGrpc() {
  try {
    return require('@fitfak/grpc');
  } catch (err) {
    if (err.code !== 'MODULE_NOT_FOUND') throw err;
    console.error(
      '\n@fitfak/grpc is not installed, so the transport tests cannot run.\n\n'
      + '  Side-by-side checkout:  npm run link:grpc\n'
      + '  Explicit path:          node scripts/link-grpc.js /path/to/grpc\n'
      + '  From the registry:      npm install @fitfak/grpc\n\n'
      + 'The engine itself has no dependencies: `npm run test:engine` runs regardless.\n',
    );
    process.exit(1);
  }
}

module.exports = { requireGrpc };
