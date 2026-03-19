#!/usr/bin/env bash
# =============================================================================
# Construct Server — Smoke Test Script
# =============================================================================
#
# Runs against a locally running docker-compose.smoke.yml stack.
# Tests that key gRPC endpoints respond correctly and without hanging.
#
# Usage:
#   ./scripts/smoke-test.sh [auth_host] [messaging_host] [gateway_host]
#
# Defaults to localhost with standard smoke ports.
# Exits with non-zero on any failure.
#
# Dependencies: grpcurl, curl, jq (all installed in CI)
# =============================================================================

set -euo pipefail

AUTH_HOST="${1:-localhost:50051}"
MSG_HOST="${2:-localhost:50052}"
GW_HOST="${3:-localhost:8080}"
PROTO_DIR="shared/proto"
TIMEOUT_S=5  # max seconds any single RPC is allowed to take

PASS=0
FAIL=0

_ok()   { echo "  ✅ $1"; ((PASS++)) || true; }
_fail() { echo "  ❌ $1"; ((FAIL++)) || true; }

# Run a command with a timeout; fail if it takes longer than TIMEOUT_S seconds
_timed() {
  local label="$1"; shift
  local start elapsed
  start=$(date +%s%3N)
  if timeout "$TIMEOUT_S" "$@" > /dev/null 2>&1; then
    elapsed=$(( $(date +%s%3N) - start ))
    _ok "$label (${elapsed}ms)"
  else
    _fail "$label — timed out or error after ${TIMEOUT_S}s"
  fi
}

echo ""
echo "=== Construct Smoke Tests ==="
echo "Auth:      $AUTH_HOST"
echo "Messaging: $MSG_HOST"
echo "Gateway:   $GW_HOST"
echo ""

# ── 1. Gateway health ────────────────────────────────────────────────────────
echo "--- Gateway ---"
_timed "GET /health" curl -sf "http://$GW_HOST/health"
_timed "GET /health/ready" curl -sf "http://$GW_HOST/health/ready"

# ── 2. Auth service reachability ─────────────────────────────────────────────
echo ""
echo "--- Auth Service ---"
# GetPowChallenge doesn't require auth — simple liveness check
_timed "GetPowChallenge (unauthenticated)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/auth_service.proto \
  -d '{}' \
  "$AUTH_HOST" \
  construct.auth.v1.AuthService/GetPowChallenge

# ── 3. Messaging service: basic response time ─────────────────────────────────
echo ""
echo "--- Messaging Service ---"

# GetPendingMessages with no auth → must return UNAUTHENTICATED quickly (not hang)
_timed "GetPendingMessages (no auth → UNAUTHENTICATED fast)" \
  bash -c "grpcurl \
    -plaintext \
    -import-path '$PROTO_DIR' \
    -proto services/messaging_service.proto \
    -d '{}' \
    '$MSG_HOST' \
    construct.messaging.v1.MessagingService/GetPendingMessages 2>&1 | grep -q 'Unauthenticated\|unauthenticated\|Missing authentication'"

# ── 4. Concurrency test: 8 parallel GetPendingMessages ───────────────────────
# Critical: this is a regression test for the queue Mutex deadlock bug.
# Even unauthenticated calls must ALL return within TIMEOUT_S seconds.
# If the Mutex is held indefinitely, some calls would hang here.
echo ""
echo "--- Concurrency test (8 parallel GetPendingMessages) ---"

PIDS=()
RESULTS=()
START=$(date +%s%3N)

for i in $(seq 1 8); do
  (grpcurl \
    -plaintext \
    -import-path "$PROTO_DIR" \
    -proto services/messaging_service.proto \
    -d '{}' \
    "$MSG_HOST" \
    construct.messaging.v1.MessagingService/GetPendingMessages 2>&1 \
    | grep -q 'Unauthenticated\|unauthenticated\|Missing authentication' \
    && echo "OK" || echo "UNEXPECTED") &
  PIDS+=($!)
done

ALL_OK=true
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    ALL_OK=false
  fi
done

ELAPSED=$(( $(date +%s%3N) - START ))
if $ALL_OK && [ "$ELAPSED" -lt $(( TIMEOUT_S * 1000 )) ]; then
  _ok "8 concurrent GetPendingMessages all returned within ${ELAPSED}ms"
else
  _fail "Concurrent GetPendingMessages test failed (elapsed: ${ELAPSED}ms, ok: $ALL_OK)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
