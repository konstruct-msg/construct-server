#!/usr/bin/env bash
# =============================================================================
# Construct Server — Smoke Test Script
# =============================================================================
#
# Runs against a locally running docker-compose.smoke.yml stack.
# Tests that key gRPC endpoints respond correctly and without hanging.
#
# Usage:
#   ./scripts/smoke-test.sh [auth_host] [msg_host] [key_host] [gateway_host]
#
# Defaults to localhost with standard smoke ports.
# Exits with non-zero on any failure.
#
# Dependencies: grpcurl, curl, jq (all installed in CI)
# =============================================================================

set -euo pipefail

AUTH_HOST="${1:-localhost:50051}"
MSG_HOST="${2:-localhost:50052}"
KEY_HOST="${3:-localhost:50057}"
GW_HOST="${4:-localhost:8080}"
PROTO_DIR="shared/proto"
TIMEOUT_S=5   # max seconds any single RPC is allowed to take
WARN_MS=2000  # warn (but don't fail) if an RPC is slower than this

PASS=0
FAIL=0
WARN=0

_ok()   { echo "  ✅ $1"; ((PASS++)) || true; }
_warn() { echo "  ⚠️  $1"; ((WARN++)) || true; }
_fail() { echo "  ❌ $1"; ((FAIL++)) || true; }

# _timed: runs a command that must SUCCEED within TIMEOUT_S.
# Warns (but passes) if elapsed > WARN_MS.
_timed() {
  local label="$1"; shift
  local start elapsed exit_code=0
  start=$(date +%s%3N)
  timeout "$TIMEOUT_S" "$@" > /dev/null 2>&1 || exit_code=$?
  elapsed=$(( $(date +%s%3N) - start ))
  if [ "$exit_code" -eq 124 ]; then
    _fail "$label — hung (timed out after ${TIMEOUT_S}s)"
  elif [ "$exit_code" -ne 0 ]; then
    _fail "$label — failed (exit $exit_code, ${elapsed}ms)"
  else
    _ok "$label (${elapsed}ms)"
    if [ "$elapsed" -gt "$WARN_MS" ]; then
      _warn "$label — slow: ${elapsed}ms > ${WARN_MS}ms threshold"
    fi
  fi
}

# _timed_err: runs a command that must FAIL (e.g. return UNAUTHENTICATED) quickly.
# Passes if the command returns a non-zero exit within TIMEOUT_S.
# Fails if it hangs (timeout), succeeds unexpectedly, or hits connection refused.
_timed_err() {
  local label="$1"; shift
  local start elapsed exit_code=0 output
  start=$(date +%s%3N)
  output=$(timeout "$TIMEOUT_S" "$@" 2>&1) || exit_code=$?
  elapsed=$(( $(date +%s%3N) - start ))
  if [ "$exit_code" -eq 124 ]; then
    _fail "$label — hung (timed out after ${TIMEOUT_S}s)"
  elif [ "$exit_code" -eq 0 ]; then
    _fail "$label — expected rejection but got success"
  elif echo "$output" | grep -qi "connection refused\|no such host\|dial tcp\|i/o timeout"; then
    _fail "$label — cannot connect to server (${elapsed}ms)"
  else
    _ok "$label (${elapsed}ms, rejected as expected)"
    if [ "$elapsed" -gt "$WARN_MS" ]; then
      _warn "$label — slow rejection: ${elapsed}ms > ${WARN_MS}ms"
    fi
  fi
}

echo ""
echo "=== Construct Smoke Tests ==="
echo "Auth:        $AUTH_HOST"
echo "Messaging:   $MSG_HOST"
echo "Key service: $KEY_HOST"
echo "Gateway:     $GW_HOST"
echo ""

# ── 1. Gateway health ────────────────────────────────────────────────────────
echo "--- Gateway ---"
_timed "GET /health" curl -sf "http://$GW_HOST/health"
_timed "GET /health/ready" curl -sf "http://$GW_HOST/health/ready"

# ── 2. Auth service ───────────────────────────────────────────────────────────
echo ""
echo "--- Auth Service ---"

# GetPowChallenge: unauthenticated liveness check — must succeed quickly
_timed "GetPowChallenge (liveness)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/auth_service.proto \
  -d '{}' \
  "$AUTH_HOST" \
  construct.auth.v1.AuthService/GetPowChallenge

# VerifyToken with a fake JWT: tests JWT validation path, not just missing-auth.
# A real deadlock or blocking middleware would hang here too.
FAKE_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbW9rZS10ZXN0IiwiZXhwIjoxfQ.ZmFrZXNpZ25hdHVyZQ"
_timed_err "VerifyToken (invalid JWT → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/auth_service.proto \
  -d "{\"access_token\": \"$FAKE_JWT\"}" \
  "$AUTH_HOST" \
  construct.auth.v1.AuthService/VerifyToken

# ── 3. Messaging service ──────────────────────────────────────────────────────
echo ""
echo "--- Messaging Service ---"

# No auth → must return UNAUTHENTICATED quickly (not hang).
# This is the primary regression test for the getPendingMessages deadlock bug.
_timed_err "GetPendingMessages (no auth → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -d '{}' \
  "$MSG_HOST" \
  construct.messaging.v1.MessagingService/GetPendingMessages

# With a fake Bearer token → JWT middleware runs, must reject quickly.
# Catches hangs in auth middleware that only trigger when Authorization header is present.
_timed_err "GetPendingMessages (fake JWT → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -H "Authorization: Bearer $FAKE_JWT" \
  -d '{}' \
  "$MSG_HOST" \
  construct.messaging.v1.MessagingService/GetPendingMessages

# ── 4. Key service ────────────────────────────────────────────────────────────
echo ""
echo "--- Key Service ---"

# GetPreKeyBundle with no auth → must reject quickly (not hang).
# Key service is on the session-init critical path; a hang here blocks new chats.
_timed_err "GetPreKeyBundle (no auth → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/key_service.proto \
  -d '{"user_id": "00000000-0000-0000-0000-000000000000"}' \
  "$KEY_HOST" \
  construct.key.v1.KeyService/GetPreKeyBundle

# GetPreKeyBundle with fake JWT → tests auth middleware under the key service.
_timed_err "GetPreKeyBundle (fake JWT → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/key_service.proto \
  -H "Authorization: Bearer $FAKE_JWT" \
  -d '{"user_id": "00000000-0000-0000-0000-000000000000"}' \
  "$KEY_HOST" \
  construct.key.v1.KeyService/GetPreKeyBundle

# ── 5. Concurrency: deadlock regression test ──────────────────────────────────
# 8 parallel GetPendingMessages calls — ALL must complete within TIMEOUT_S seconds.
# If the Mutex is held indefinitely, some calls will hang and we'll exceed the timeout.
echo ""
echo "--- Concurrency test (8 × GetPendingMessages in parallel) ---"

TMPDIR_SMOKE=$(mktemp -d)
trap 'rm -rf "$TMPDIR_SMOKE"' EXIT

PIDS=()
CONC_START=$(date +%s%3N)

for i in $(seq 1 8); do
  (
    grpcurl \
      -plaintext \
      -import-path "$PROTO_DIR" \
      -proto services/messaging_service.proto \
      -d '{}' \
      "$MSG_HOST" \
      construct.messaging.v1.MessagingService/GetPendingMessages \
      > "$TMPDIR_SMOKE/out_$i" 2>&1
    echo $? > "$TMPDIR_SMOKE/rc_$i"
  ) &
  PIDS+=($!)
done

TIMED_OUT=false
for pid in "${PIDS[@]}"; do
  if ! timeout "$TIMEOUT_S" tail --pid="$pid" -f /dev/null 2>/dev/null; then
    TIMED_OUT=true
    kill "$pid" 2>/dev/null || true
  fi
done

CONC_ELAPSED=$(( $(date +%s%3N) - CONC_START ))

# Wait for any remaining subshells to settle
wait 2>/dev/null || true

if $TIMED_OUT; then
  _fail "Concurrency test — at least one call hung (total: ${CONC_ELAPSED}ms)"
elif [ "$CONC_ELAPSED" -gt $(( TIMEOUT_S * 1000 )) ]; then
  _fail "Concurrency test — total wall time exceeded ${TIMEOUT_S}s (${CONC_ELAPSED}ms)"
else
  # Verify each call got a proper gRPC error (not connection refused or garbled output)
  CONC_OK=true
  for i in $(seq 1 8); do
    rc=$(cat "$TMPDIR_SMOKE/rc_$i" 2>/dev/null || echo "missing")
    out=$(cat "$TMPDIR_SMOKE/out_$i" 2>/dev/null || echo "")
    if [ "$rc" = "missing" ]; then
      CONC_OK=false
      break
    fi
    # Connection refused = server crashed under load
    if echo "$out" | grep -qi "connection refused\|no such host"; then
      CONC_OK=false
      break
    fi
  done
  if $CONC_OK; then
    _ok "8 concurrent calls all returned in ${CONC_ELAPSED}ms"
    if [ "$CONC_ELAPSED" -gt "$WARN_MS" ]; then
      _warn "Concurrency test — slow: ${CONC_ELAPSED}ms > ${WARN_MS}ms"
    fi
  else
    _fail "Concurrency test — a call hit connection refused (server crashed under load?)"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
