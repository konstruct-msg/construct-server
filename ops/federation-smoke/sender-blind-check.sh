#!/usr/bin/env bash
# A5 sender-blind assertion — verify a sealed-sender delivery left no sender trace
# on the RECEIVING node's logs. Run AFTER a real alice@a -> bob@b sealed delivery
# (step 3-4 of README.md). This scripts what that step described manually.
#
# Usage:
#   NODE_B_COMPOSE="-f ops/docker-compose.relay.yml -p nodeb" \
#   ALICE_UUID="<alice's user uuid>" \
#     ops/federation-smoke/sender-blind-check.sh
#
# Asserts, on node B:
#   1. the inbound sealed message was delivered locally (log marker present);
#   2. alice's UUID appears NOWHERE in node B's logs (sender-blind).
#
# Exit 0 = both hold; 1 = a check failed; 2 = usage error.
set -euo pipefail

COMPOSE="${NODE_B_COMPOSE:-}"
ALICE="${ALICE_UUID:-}"
MARKER="${DELIVER_MARKER:-Inbound sealed sender message delivered locally}"

if [[ -z "$COMPOSE" || -z "$ALICE" ]]; then
  echo "usage: NODE_B_COMPOSE='<docker compose selector>' ALICE_UUID=<uuid> $0" >&2
  echo "  e.g. NODE_B_COMPOSE='-f ops/docker-compose.relay.yml -p nodeb' ALICE_UUID=... $0" >&2
  exit 2
fi

# Prefer the messaging service's logs; fall back to the whole project.
logs="$(docker compose $COMPOSE logs --no-color messaging 2>/dev/null \
        || docker compose $COMPOSE logs --no-color 2>/dev/null || true)"

if [[ -z "$logs" ]]; then
  echo "❌ could not read logs for compose selector: $COMPOSE" >&2
  exit 1
fi

rc=0

if grep -qF -- "$MARKER" <<<"$logs"; then
  echo "✅ delivery: found '$MARKER' in node B logs"
else
  echo "❌ delivery: marker not found — did the sealed message actually arrive?"
  rc=1
fi

if grep -qF -- "$ALICE" <<<"$logs"; then
  echo "❌ sender-blind: alice's UUID ($ALICE) LEAKED into node B logs:"
  grep -nF -- "$ALICE" <<<"$logs" | head -5 >&2
  rc=1
else
  echo "✅ sender-blind: alice's UUID absent from node B logs"
fi

exit $rc
