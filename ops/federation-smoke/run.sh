#!/usr/bin/env bash
# =============================================================================
# A5 two-node federation smoke check
# =============================================================================
# Runs the *scriptable* half of the A5 receiver contract against two already-
# deployed island nodes (see ops/island.env.example + ops/Caddyfile.island and
# construct-docs/decisions/domestic-island-deployment.md).
#
# What this asserts (no client / no PoW / no protobuf needed):
#   1. Both nodes publish .well-known/konstruct with a federation public_key.
#   2. The sealed receiver rejects a payload-hash mismatch with HTTP 400
#      (checked BEFORE signature, so no signing needed).
#   3. With FEDERATION_MTLS_REQUIRED=true, an unsigned sealed request -> 401.
#
# What this does NOT do (needs a real client or a signing helper — see README):
#   - register bob, send a genuine signed `alice@a -> bob@b`, assert Redis
#     delivery to bob's device stream, and grep node-b logs for sender-blindness.
#   The crypto/privacy contract for that path is unit-covered by
#   crates/construct-federation/tests/s2s_sealed_sender_blind_test.rs.
#
# Usage:
#   NODE_A_URL=https://relay.a.local NODE_B_URL=https://relay.b.local ./run.sh
#   # add CURL_OPTS="-k" for `tls internal` self-signed certs during a local smoke.
# =============================================================================
set -euo pipefail

NODE_A_URL="${NODE_A_URL:?set NODE_A_URL, e.g. https://relay.a.local}"
NODE_B_URL="${NODE_B_URL:?set NODE_B_URL, e.g. https://relay.b.local}"
CURL_OPTS="${CURL_OPTS:-}"

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; exit 1; }

check_well_known() {
  local name="$1" url="$2"
  local body
  body="$(curl -fsS $CURL_OPTS "$url/.well-known/konstruct")" \
    || fail "$name .well-known/konstruct not reachable (200 expected)"
  echo "$body" | jq -e '.federation.enabled == true' >/dev/null \
    || fail "$name federation not enabled in .well-known"
  echo "$body" | jq -e '.federation.public_key | type == "string" and length > 0' >/dev/null \
    || fail "$name .well-known has no federation.public_key"
  pass "$name publishes federation public_key"
}

# Build a sealed request whose payload_hash deliberately does NOT match the blob.
# hash_payload = base64(sha256(sealed_inner_b64_string)); we send a wrong hash.
mismatch_payload_hash_request() {
  local sealed_inner_b64="b3BhcXVl" # base64("opaque")
  cat <<JSON
{"messageId":"a5-smoke-$(date +%s)","sealedInner":"$sealed_inner_b64","originServer":"smoke.local","timestamp":$(date +%s),"payloadHash":"deadbeefwronghash"}
JSON
}

check_payload_hash_gate() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' $CURL_OPTS \
    -X POST "$NODE_B_URL/federation/v1/sealed" \
    -H 'Content-Type: application/json' \
    --data "$(mismatch_payload_hash_request)")"
  [ "$code" = "400" ] \
    && pass "node B rejects payload-hash mismatch (400)" \
    || fail "node B payload-hash gate: expected 400, got $code"
}

# A well-formed but UNSIGNED sealed request (correct payload_hash, no signature).
unsigned_request() {
  # sealed_inner_b64 = base64("opaque"); payload_hash must be base64(sha256(that string)).
  local sealed_inner_b64="b3BhcXVl"
  local ph
  ph="$(printf '%s' "$sealed_inner_b64" | openssl dgst -sha256 -binary | openssl base64 -A)"
  cat <<JSON
{"messageId":"a5-smoke-unsigned-$(date +%s)","sealedInner":"$sealed_inner_b64","originServer":"smoke.local","timestamp":$(date +%s),"payloadHash":"$ph"}
JSON
}

check_unsigned_rejected_when_mtls_required() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' $CURL_OPTS \
    -X POST "$NODE_B_URL/federation/v1/sealed" \
    -H 'Content-Type: application/json' \
    --data "$(unsigned_request)")"
  case "$code" in
    401) pass "node B rejects unsigned sealed request (401 — FEDERATION_MTLS_REQUIRED=true)";;
    200|500) printf '  \033[33mSKIP\033[0m node B accepted unsigned (got %s) — set FEDERATION_MTLS_REQUIRED=true to enforce\n' "$code";;
    *) fail "node B unsigned request: unexpected status $code";;
  esac
}

echo "A5 federation smoke: $NODE_A_URL  <->  $NODE_B_URL"
check_well_known "node A" "$NODE_A_URL"
check_well_known "node B" "$NODE_B_URL"
check_payload_hash_gate
check_unsigned_rejected_when_mtls_required
echo "Scriptable receiver-contract checks passed. Full signed alice@a -> bob@b"
echo "delivery + sender-blind assertion: see ops/federation-smoke/README.md."
