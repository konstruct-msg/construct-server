#!/usr/bin/env bash
# =============================================================================
# Construct Server — Smoke Test Script
# =============================================================================
#
# Runs against a locally running docker-compose.smoke.yml stack.
# Tests that key gRPC endpoints respond correctly and without hanging.
#
# Usage:
#   ./scripts/smoke-test.sh [auth_host] [msg_host] [key_host] [gateway_host] [signaling_host]
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
SIG_HOST="${5:-localhost:50060}"
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

# _timed_err_unauthenticated: like _timed_err, but additionally verifies the error
# is UNAUTHENTICATED (not UNIMPLEMENTED). Catches stale-binary regression where a
# missing RPC returns gRPC status 12 (Unimplemented) instead of status 16.
_timed_err_unauthenticated() {
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
  elif echo "$output" | grep -qi "Unimplemented\|unimplemented"; then
    _fail "$label — got UNIMPLEMENTED (stale binary? method not registered)"
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
echo "Signaling:   $SIG_HOST"
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
  shared.proto.services.v1.AuthService/GetPowChallenge

# VerifyToken with a fake JWT: VerifyToken always returns gRPC OK — it responds
# with {valid: false} for bad tokens rather than an error status.
# Test that it responds quickly (liveness + non-hanging, not rejection).
FAKE_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbW9rZS10ZXN0IiwiZXhwIjoxfQ.ZmFrZXNpZ25hdHVyZQ"
_timed "VerifyToken (invalid JWT → valid:false fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/auth_service.proto \
  -d "{\"access_token\": \"$FAKE_JWT\"}" \
  "$AUTH_HOST" \
  shared.proto.services.v1.AuthService/VerifyToken

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
  shared.proto.services.v1.MessagingService/GetPendingMessages

# With a fake Bearer token → JWT middleware runs, must reject quickly.
# Catches hangs in auth middleware that only trigger when Authorization header is present.
_timed_err "GetPendingMessages (fake JWT → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -H "Authorization: Bearer $FAKE_JWT" \
  -d '{}' \
  "$MSG_HOST" \
  shared.proto.services.v1.MessagingService/GetPendingMessages

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
  shared.proto.services.v1.KeyService/GetPreKeyBundle

# GetPreKeyBundle with fake JWT → tests auth middleware under the key service.
_timed_err "GetPreKeyBundle (fake JWT → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/key_service.proto \
  -H "Authorization: Bearer $FAKE_JWT" \
  -d '{"user_id": "00000000-0000-0000-0000-000000000000"}' \
  "$KEY_HOST" \
  shared.proto.services.v1.KeyService/GetPreKeyBundle


# ── 5. Signaling service ──────────────────────────────────────────────────────
echo ""
echo "--- Signaling Service ---"

# InitiateCall without x-user-id header → must return UNAUTHENTICATED.
# CRITICAL REGRESSION TEST: if binary is stale (pre-InitiateCall), this returns
# UNIMPLEMENTED (gRPC status 12) instead and the test fails, alerting us of a
# Docker build cache issue before we deploy to production.
_timed_err_unauthenticated "InitiateCall (no auth → UNAUTHENTICATED, not UNIMPLEMENTED)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/signaling_service.proto \
  -d '{"call_id":"smoke","callee_user_id":"00000000-0000-0000-0000-000000000000","has_video":false}' \
  "$SIG_HOST" \
  shared.proto.signaling.v1.SignalingService/InitiateCall

# GetTurnCredentials without x-user-id → must also reject quickly (liveness).
_timed_err "GetTurnCredentials (no auth → rejected fast)" grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/signaling_service.proto \
  -d '{}' \
  "$SIG_HOST" \
  shared.proto.signaling.v1.SignalingService/GetTurnCredentials


# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
