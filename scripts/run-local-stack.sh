#!/usr/bin/env bash
#
# Brings the whole stack up on one machine and proves the sealed bootstrap completed.
#
#   scripts/run-local-stack.sh /path/to/idp
#
# This exists because "the tests pass" and "it starts" turned out to be different claims. Four
# faults sat between them, and none of them were visible to a unit test:
#
#   * the identity provider required a package that was never published, so it could not load
#   * the metrics collector read an HTTP/2 socket proxy after detach, which killed the database
#     on the first connection that closed
#   * the SPIFFE reader did not know the field name tls.getPeerCertificate() actually uses, so
#     every peer over a real connection presented "no identity"
#   * the admission gate asked the service registry about a principal that is deliberately not
#     in it, and refused the one peer that can open the database
#
# Each was invisible in isolation and fatal in composition. This script is the composition.
#
# It is a DEVELOPMENT harness, not a deployment: it puts both processes and the pairing directory
# under one temporary root, on loopback ports, with secrets generated once and written to a file.
# A real deployment uses systemd units, separate users and /var/lib/fitfak — see docs/ZERO-TRUST.md.

set -euo pipefail

IDP_DIR="${1:-../idp}"
ROOT="${FITFAK_LOCAL_ROOT:-$(mktemp -d /tmp/fitfak-stack-XXXXXX)}"
DB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$IDP_DIR/oauth-server.js" ]; then
  echo "usage: $0 /path/to/idp     (could not find oauth-server.js in '$IDP_DIR')" >&2
  exit 2
fi
IDP_DIR="$(cd "$IDP_DIR" && pwd)"

echo "  database : $DB_DIR"
echo "  idp      : $IDP_DIR"
echo "  state    : $ROOT"
echo

mkdir -p "$ROOT/pairing" "$ROOT/db" "$ROOT/idp"
chmod 700 "$ROOT/pairing"

# Secrets are generated ONCE and written down. Regenerating them per process would encrypt the CA
# store with one key and open it with another, and the failure ("unable to authenticate data")
# says nothing about which key was wrong.
node -e '
const fs = require("fs"); const crypto = require("crypto");
const root = process.argv[1];
fs.writeFileSync(root + "/env.sh", [
  "export FITFAK_PAIRING_DIR=" + root + "/pairing",
  "export FITFAK_TRUST_DOMAIN=fitfak.net",
  "export FITFAK_DB_STATE_DIR=" + root + "/db/.db-state",
  "export FITFAK_DB_DATA_DIR=" + root + "/db/fitdb",
  "export FITFAK_DB_HOST=127.0.0.1",
  "export FITFAK_DB_PORT=51572",
  "export FITFAK_DB_DNS=localhost",
  "export FITFAK_DB_IPS=127.0.0.1",
  "export FITFAK_DB_ADMIN_HOST=127.0.0.1",
  "export FITFAK_DB_ADMIN_PORT=8081",
  "export FITFAK_IDP_DB_SECRET=" + crypto.randomBytes(32).toString("base64"),
  "export FITFAK_IDP_REDIRECT_HANDLE_SECRET=" + crypto.randomBytes(32).toString("base64"),
  "export FITFAK_IDP_DATA_DIR=" + root + "/idp/data",
  "export FITFAK_IDP_KEY_DIR=" + root + "/idp/.keys",
  "export FITFAK_IDP_CA_STORE_DIR=" + root + "/idp/.ca-store",
  "export FITFAK_IDP_DB_TARGET=https://localhost:51572",
  "",
].join("\n"));
' "$ROOT"

# shellcheck disable=SC1090
set -a; . "$ROOT/env.sh"; set +a

cleanup() {
  [ -n "${DB_PID:-}" ] && kill "$DB_PID" 2>/dev/null || true
  [ -n "${IDP_PID:-}" ] && kill "$IDP_PID" 2>/dev/null || true
}
trap cleanup EXIT

# The database starts FIRST here only because something has to be first. It comes up sealed and
# waits; starting the identity provider first works equally well, which is the point of the
# staging buffer on that side.
( cd "$DB_DIR" && node bin/db-server.js > "$ROOT/db.log" 2>&1 ) &
DB_PID=$!
sleep 4

( cd "$IDP_DIR" && node oauth-server.js > "$ROOT/idp.log" 2>&1 ) &
IDP_PID=$!

# Wait for the handover rather than for a fixed delay: the interesting failure is "it never
# happened", and a sleep long enough to hide that is a sleep long enough to be useless.
echo "  waiting for the identity provider to unseal the database…"
for _ in $(seq 1 60); do
  if grep -q "database open to all principals" "$ROOT/db.log" 2>/dev/null; then
    OPENED=1
    break
  fi
  sleep 1
done

echo
if [ "${OPENED:-0}" = "1" ]; then
  echo "  OK — the database is open."
  grep -c . "$ROOT/idp.log" > /dev/null
  echo
  echo "  admin panel : http://127.0.0.1:8081/?token=$(cat "$ROOT/db/.db-state/admin-token")"
  echo "  logs        : $ROOT/db.log   $ROOT/idp.log"
  echo "  environment : $ROOT/env.sh   (source it to run a branch service)"
  echo
  echo "  Register an application and run one:"
  echo "    curl -s -X POST -H \"x-admin-token: \$(cat $ROOT/db/.db-state/admin-token)\" \\"
  echo "      -H 'content-type: application/json' -d '{\"name\":\"tunnel\",\"roles\":[\"reader\",\"writer\"]}' \\"
  echo "      http://127.0.0.1:8081/api/services"
  echo "    FITFAK_SERVICE_NAME=tunnel FITFAK_ENROLMENT_SECRET=<the secret> node examples/branch-service.js"
  echo
  echo "  Ctrl-C to stop both."
  wait
else
  echo "  FAILED — the database never opened." >&2
  echo >&2
  echo "  Last lines of the database log:" >&2
  tail -15 "$ROOT/db.log" >&2 || true
  echo >&2
  echo "  Last lines of the identity provider log:" >&2
  tail -15 "$ROOT/idp.log" >&2 || true
  exit 1
fi
