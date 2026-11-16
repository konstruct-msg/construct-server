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

_now_ms() {
  python3 -c 'import time; print(time.time_ns() // 1_000_000)'
}

# _timed: runs a command that must SUCCEED within TIMEOUT_S.
# Warns (but passes) if elapsed > WARN_MS.
_timed() {
  local label="$1"; shift
  local start end elapsed exit_code=0
  start=$(_now_ms)
  timeout "$TIMEOUT_S" "$@" > /dev/null 2>&1 || exit_code=$?
  end=$(_now_ms)
  elapsed=$((end - start))
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

# A gRPC refusal proves only the expected contract when its exact status is named.
# "Any non-zero" also passes INTERNAL, INVALID_ARGUMENT and a stale method, which made
# several old smoke labels stronger than their assertions.
_timed_grpc_error() {
  local label="$1" expected="$2"; shift 2
  local start end elapsed exit_code=0 output actual
  start=$(_now_ms)
  output=$(timeout "$TIMEOUT_S" "$@" 2>&1) || exit_code=$?
  end=$(_now_ms)
  elapsed=$((end - start))
  actual=$(printf '%s\n' "$output" | sed -nE 's/^[[:space:]]*Code:[[:space:]]*([^[:space:]]+)[[:space:]]*$/\1/p' | head -n1)
  if [ "$exit_code" -eq 124 ]; then
    _fail "$label — hung (timed out after ${TIMEOUT_S}s)"
  elif [ "$exit_code" -eq 0 ]; then
    _fail "$label — expected gRPC $expected but got success"
  elif echo "$output" | grep -qi "connection refused\|no such host\|dial tcp\|i/o timeout"; then
    _fail "$label — cannot connect to server (${elapsed}ms)"
  elif [ "$actual" != "$expected" ]; then
    _fail "$label — expected gRPC $expected, got ${actual:-no grpc code} (${elapsed}ms)"
  else
    _ok "$label (${elapsed}ms, gRPC $expected)"
    if [ "$elapsed" -gt "$WARN_MS" ]; then
      _warn "$label — slow rejection: ${elapsed}ms > ${WARN_MS}ms"
    fi
  fi
}

# Run a successful command and prove a predicate over the JSON it actually returned.
_timed_json() {
  local label="$1" predicate="$2"; shift 2
  local start end elapsed exit_code=0 output
  start=$(_now_ms)
  output=$(timeout "$TIMEOUT_S" "$@" 2>&1) || exit_code=$?
  end=$(_now_ms)
  elapsed=$((end - start))
  if [ "$exit_code" -eq 124 ]; then
    _fail "$label — hung (timed out after ${TIMEOUT_S}s)"
  elif [ "$exit_code" -ne 0 ]; then
    _fail "$label — failed (exit $exit_code, ${elapsed}ms)"
  elif ! printf '%s\n' "$output" | jq -e "$predicate" >/dev/null 2>&1; then
    _fail "$label — response did not satisfy: $predicate"
  else
    _ok "$label (${elapsed}ms, response verified)"
    if [ "$elapsed" -gt "$WARN_MS" ]; then
      _warn "$label — slow: ${elapsed}ms > ${WARN_MS}ms threshold"
    fi
  fi
}

main() {
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

# VerifyToken with a fake token: VerifyToken always returns gRPC OK — it responds
# with {valid: false} for bad tokens rather than an error status.
# Test both prompt completion and the response body; gRPC OK alone proves neither.
FAKE_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzbW9rZS10ZXN0IiwiZXhwIjoxfQ.ZmFrZXNpZ25hdHVyZQ"
_timed_json "VerifyToken (invalid token → valid:false fast)" '.valid == false' grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/auth_service.proto \
  -d "{\"access_token\": \"$FAKE_TOKEN\"}" \
  "$AUTH_HOST" \
  shared.proto.services.v1.AuthService/VerifyToken

# ── 3. Messaging service ──────────────────────────────────────────────────────
echo ""
echo "--- Messaging Service ---"

# No auth → must return UNAUTHENTICATED quickly (not hang).
# This is the primary regression test for the getPendingMessages deadlock bug.
_timed_grpc_error "GetPendingMessages (no auth → UNAUTHENTICATED fast)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -d '{}' \
  "$MSG_HOST" \
  shared.proto.services.v1.MessagingService/GetPendingMessages

# With a fake Bearer token → auth middleware runs, must reject quickly.
# Catches hangs in auth middleware that only trigger when Authorization header is present.
_timed_grpc_error "GetPendingMessages (fake token → UNAUTHENTICATED fast)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -H "Authorization: Bearer $FAKE_TOKEN" \
  -d '{}' \
  "$MSG_HOST" \
  shared.proto.services.v1.MessagingService/GetPendingMessages

# P0-A regression: client-supplied x-user-id alone must NOT authenticate.
# Caddy does not inject identity headers — services require Bearer.
_timed_grpc_error "GetPendingMessages (x-user-id spoof only → UNAUTHENTICATED)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -H "x-user-id: 00000000-0000-0000-0000-000000000001" \
  -d '{}' \
  "$MSG_HOST" \
  shared.proto.services.v1.MessagingService/GetPendingMessages

# Spoof guard: Bearer present but x-user-id mismatches claims → reject.
_timed_grpc_error "GetPendingMessages (fake token + mismatched x-user-id → UNAUTHENTICATED)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/messaging_service.proto \
  -H "Authorization: Bearer $FAKE_TOKEN" \
  -H "x-user-id: 00000000-0000-0000-0000-000000000001" \
  -d '{}' \
  "$MSG_HOST" \
  shared.proto.services.v1.MessagingService/GetPendingMessages

# ── 3b. Auth logout / revocation ──────────────────────────────────────────────
echo ""
echo "--- Auth Logout ---"

# Logout requires access_token in request body; empty → INVALID_ARGUMENT (not hang).
_timed_grpc_error "Logout (empty access_token → INVALID_ARGUMENT fast)" InvalidArgument grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/auth_service.proto \
  -d '{"access_token": ""}' \
  "$AUTH_HOST" \
  shared.proto.services.v1.AuthService/Logout

# ── 4. Key service ────────────────────────────────────────────────────────────
echo ""
echo "--- Key Service ---"

# GetPreKeyBundle with no auth → must reject quickly (not hang).
# Key service is on the session-init critical path; a hang here blocks new chats.
_timed_grpc_error "GetPreKeyBundle (no auth → UNAUTHENTICATED fast)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/key_service.proto \
  -d '{"user_id": "00000000-0000-0000-0000-000000000000"}' \
  "$KEY_HOST" \
  shared.proto.services.v1.KeyService/GetPreKeyBundle

# GetPreKeyBundle with fake token → tests auth middleware under the key service.
_timed_grpc_error "GetPreKeyBundle (fake token → UNAUTHENTICATED fast)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/key_service.proto \
  -H "Authorization: Bearer $FAKE_TOKEN" \
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
_timed_grpc_error "InitiateCall (no auth → UNAUTHENTICATED, not UNIMPLEMENTED)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/signaling_service.proto \
  -d '{"call_id":"smoke","callee_user_id":"00000000-0000-0000-0000-000000000000","has_video":false}' \
  "$SIG_HOST" \
  shared.proto.signaling.v1.SignalingService/InitiateCall

# GetTurnCredentials without auth → must also reject quickly (liveness).
_timed_grpc_error "GetTurnCredentials (no auth → UNAUTHENTICATED fast)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/signaling_service.proto \
  -d '{}' \
  "$SIG_HOST" \
  shared.proto.signaling.v1.SignalingService/GetTurnCredentials

# P0-A: x-user-id alone must not authorize calls.
_timed_grpc_error "InitiateCall (x-user-id spoof only → UNAUTHENTICATED)" Unauthenticated grpcurl \
  -plaintext \
  -import-path "$PROTO_DIR" \
  -proto services/signaling_service.proto \
  -H "x-user-id: 00000000-0000-0000-0000-000000000001" \
  -d '{"call_id":"smoke-spoof","callee_user_id":"00000000-0000-0000-0000-000000000002","has_video":false}' \
  "$SIG_HOST" \
  shared.proto.signaling.v1.SignalingService/InitiateCall


# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
echo ""
echo "Checks covered: exact auth refusals, x-user-id spoof rejection,"
echo "  logout empty-token validation, signaling auth, and VerifyToken body."
echo ""

if [ "$FAIL" -gt 0 ]; then
  return 1
fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
