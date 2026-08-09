'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

// Where the two processes leave each other the values they cannot compute alone.
//
// This file exists because manual configuration did not work. Connecting an identity provider to
// this database used to require: copy the control-plane secret out of this process's stdout, write
// down the target address, write down the bootstrap fingerprint, invent a registration-authority
// client id and secret, and enter them on BOTH sides. Five values, two processes, and every one of
// them producing an unreadable TLS error when mistyped.
//
// Now there is one directory. The database writes what it knows at boot, the IdP reads it; the IdP
// writes its half, the database reads that. The only thing left to configure is the directory, and
// it has a default.
//
//
// THIS IS NOT A SECRET STORE
//
// Two secrets travel through here: this database's control-plane secret and the registration
// authority's client secret. Both were ALREADY on disk before this existed — one in
// `.db-state/control-plane-secret`, the other in the IdP's environment — so this is not a new class
// of exposure. The gain is that nobody copies them out of a terminal any more.
//
// What it is not: a process that can read this directory can replace the database's server
// identity. Hence 0700 on the directory, 0600 on the files, and a permission check on every read
// that warns loudly rather than continuing quietly.
//
// THE ROOT CA KEY IS NEVER WRITTEN HERE. It lives in the encrypted vault and does not leave it; the
// only PKI material in this directory is the root's CERTIFICATE and its fingerprint, both public.
//
// The IdP half of this file is `../../idp/core/pairing.js`. The two must agree on the field names,
// so both are kept deliberately small and boring.

const DATABASE_FILE = 'database.json';
const IDP_FILE = 'idp.json';

/**
 * Where the pairing directory lives.
 *
 * Order: explicit argument, environment, system-wide path, home directory. The last is for
 * development and is the right answer on a single-user machine; in production the two services
 * usually run as different users and a shared directory is named explicitly.
 */
function pairingDir(explicit = null) {
  if (explicit) return explicit;
  if (process.env.FITFAK_PAIRING_DIR) return process.env.FITFAK_PAIRING_DIR;
  if (fs.existsSync('/var/lib/fitfak')) return '/var/lib/fitfak/pairing';
  return path.join(os.homedir(), '.fitfak', 'pairing');
}

async function ensureDir(dir) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  // mkdir's mode is masked by umask, so asking for 0700 is not getting 0700. A follow-up chmod is
  // the only reliable way.
  await fsp.chmod(dir, 0o700).catch(() => {});
  return dir;
}

/**
 * Checks permissions and warns when they are too open.
 *
 * Warning, not refusing. A deployment opening this directory to a shared group can be a legitimate
 * choice; accepting it silently cannot. The difference is whether an operator CHOSE it, and the
 * warning is what asks that question.
 */
async function checkPermissions(file, logger) {
  try {
    const stat = await fsp.stat(file);
    const mode = stat.mode & 0o777;
    if (mode & 0o077) {
      logger?.warn?.({
        file,
        mode: mode.toString(8),
        msg: 'pairing file is readable beyond its owner — a process that can read it can replace '
          + "this database's server identity",
      });
    }
  } catch (_) { /* a missing file is the reader's problem, and it will notice */ }
}

async function writeJson(dir, name, payload, logger) {
  await ensureDir(dir);
  const file = path.join(dir, name);
  const tmp = `${file}.tmp`;
  // 0600, temp file first, then rename. Writing in place leaves a half-written file when the
  // process dies mid-write, and the other side finds it as "present but corrupt".
  await fsp.writeFile(tmp, JSON.stringify({ ...payload, writtenAt: Date.now() }, null, 2), { mode: 0o600 });
  await fsp.chmod(tmp, 0o600).catch(() => {});
  await fsp.rename(tmp, file);
  logger?.debug?.({ file, msg: 'pairing file written' });
  return file;
}

async function readJson(dir, name, logger) {
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) return null;
  await checkPermissions(file, logger);
  try {
    return JSON.parse(await fsp.readFile(file, 'utf8'));
  } catch (err) {
    logger?.warn?.({ file, error: err.message, msg: 'pairing file could not be read' });
    return null;
  }
}

/** What this database publishes: where to reach it and the control plane's shared secret. */
async function publishDatabase({ dir, target, controlSecret, bootstrapFingerprint, trustDomain, logger }) {
  return writeJson(pairingDir(dir), DATABASE_FILE, {
    target,
    controlSecret: Buffer.isBuffer(controlSecret) ? controlSecret.toString('base64') : controlSecret,
    bootstrapFingerprint,
    trustDomain,
  }, logger);
}

async function readDatabase({ dir, logger } = {}) {
  const raw = await readJson(pairingDir(dir), DATABASE_FILE, logger);
  if (!raw) return null;
  return {
    ...raw,
    controlSecret: raw.controlSecret ? Buffer.from(raw.controlSecret, 'base64') : null,
  };
}

/**
 * What the IdP publishes: everything this database needs to act as a Registration Authority
 * against it, plus the trust anchor, plus the OAuth client the admin panel signs operators in with.
 */
async function readIdp({ dir, logger } = {}) {
  return readJson(pairingDir(dir), IDP_FILE, logger);
}

/**
 * Waits for the IdP's half to appear.
 *
 * The database starts before the IdP has ever run, so at first boot `idp.json` does not exist. That
 * is not an error and must not be treated as one: the enrolment path is unreachable until the IdP
 * provisions this process anyway, so there is nothing to be late for. Callers poll rather than
 * block startup.
 */
async function waitForIdp({ dir, logger, timeoutMs = 0, intervalMs = 2000 } = {}) {
  const deadline = timeoutMs > 0 ? Date.now() + timeoutMs : Infinity;
  for (;;) {
    const found = await readIdp({ dir, logger });
    if (found) return found;
    if (Date.now() >= deadline) return null;
    await new Promise((resolve) => { const t = setTimeout(resolve, intervalMs); t.unref?.(); });
  }
}

module.exports = {
  pairingDir,
  publishDatabase,
  readDatabase,
  readIdp,
  waitForIdp,
  DATABASE_FILE,
  IDP_FILE,
};
