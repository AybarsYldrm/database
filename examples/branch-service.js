'use strict';

// A branch application joining the system — the whole thing.
//
//   FITFAK_SERVICE_NAME=dns-resolver \
//   FITFAK_ENROLMENT_SECRET='<shown once in the admin panel>' \
//   node examples/branch-service.js
//
// This is what a tunnel, an SMTP relay or a DNS resolver needs in order to hold a SPIFFE
// identity and talk to the database. Compare it with examples/app-client.js, which shows the
// same thing expanded: that file is worth reading to understand what happens, and worth NOT
// copying into an application, because every copy is a place for one of its steps to be dropped.
//
// What `joinAsService` does that a hand-written version usually forgets:
//
//   * persists the certificate, so a restart resumes instead of spending the single-use
//     enrolment secret again
//   * renews before expiry, on a fresh key each time
//   * pins the ROOT, not the server certificate — the latter is regenerated on every boot by
//     design, so pinning it breaks daily
//   * finds the address and the trust anchor in the pairing directory, so neither is typed
//
// The retrying variant is used here because a long-running service should survive being started
// before the identity provider: the database refuses everyone until the IdP has provisioned it,
// and in this architecture that is an ordering, not a fault.

const { joinAsServiceWhenReady, createLogger } = require('..');

const log = createLogger(process.env.FITFAK_SERVICE_NAME || 'service');

async function main() {
  const service = await joinAsServiceWhenReady({
    serviceName: process.env.FITFAK_SERVICE_NAME || 'dns-resolver',
    // Roles are what this service asked to be granted; the database decides what it actually
    // gets, from what the admin panel registered.
    roles: ['reader', 'writer'],
    logger: log,
  }, { retryMs: 5000, logger: log });

  log.info({
    principal: service.principal,
    spiffeId: service.spiffeId,
    target: service.target,
    msg: 'joined — identity held, database open',
  });

  // From here it is an ordinary database handle. The identity underneath renews itself.
  const records = service.db.collection('records');
  await service.db.applySchemaRegistry({
    records: { fields: [{ no: 2, name: 'key', type: 'string', index: true }, { no: 3, name: 'value', type: 'string' }] },
  });

  const id = await records.insert({ key: 'hello', value: 'world' });
  log.info({ id, msg: 'wrote a record as this service' });

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      log.info({ signal, msg: 'shutting down' });
      await service.close();
      process.exit(0);
    });
  }
}

main().catch((err) => {
  // A failure here is almost always one of three things, and the message says which: no address
  // (pairing directory not shared), no trust anchor (the IdP has not provisioned the database
  // yet), or no credential (the application was never registered in the admin panel).
  log.error({ error: err.message, msg: 'could not join' });
  process.exit(1);
});
