#!/usr/bin/env bash
# Pure contracts for scripts/smoke-test.sh: no Docker, ports, credentials or services.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=smoke-test.sh
source "$ROOT/scripts/smoke-test.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
TIMEOUT_S=2
WARN_MS=10000
# Expected-negative cases should not look like CI failures; preserve only counters.
_ok() { ((PASS++)) || true; }
_warn() { ((WARN++)) || true; }
_fail() { ((FAIL++)) || true; }

fake() {
  local name="$1" body="$2" code="$3"
  cat > "$TMP/$name" <<EOF
#!/usr/bin/env bash
printf '%s\n' '$body'
exit $code
EOF
  chmod +x "$TMP/$name"
}

fake ok-json '{"valid":false}' 0
fake wrong-json '{"valid":true}' 0
fake unauth 'ERROR:
  Code: Unauthenticated
  Message: missing bearer' 1
fake wrong-code 'ERROR:
  Code: PermissionDenied
  Message: wrong refusal' 1
fake no-code 'plain failure' 1
fake connection 'dial tcp 127.0.0.1:50051: connection refused' 1
cat > "$TMP/hang" <<'EOF'
#!/usr/bin/env bash
sleep 5
EOF
chmod +x "$TMP/hang"

reset_counts() { PASS=0; FAIL=0; WARN=0; }
expect_counts() {
  local pass="$1" fail="$2" warn="$3"
  test "$PASS" -eq "$pass"
  test "$FAIL" -eq "$fail"
  test "$WARN" -eq "$warn"
}

reset_counts
_timed_json valid-false '.valid == false' "$TMP/ok-json"
expect_counts 1 0 0

reset_counts
_timed_json wrong-value '.valid == false' "$TMP/wrong-json"
expect_counts 0 1 0

reset_counts
_timed_grpc_error exact-code Unauthenticated "$TMP/unauth"
expect_counts 1 0 0

# The old helper accepted any non-zero exit here. Exact status is the decision.
reset_counts
_timed_grpc_error wrong-code Unauthenticated "$TMP/wrong-code"
expect_counts 0 1 0

reset_counts
_timed_grpc_error missing-code Unauthenticated "$TMP/no-code"
expect_counts 0 1 0

reset_counts
_timed_grpc_error transport-failure Unauthenticated "$TMP/connection"
expect_counts 0 1 0

reset_counts
_timed command-timeout "$TMP/hang"
expect_counts 0 1 0

# Exercise the whole script against a fake grpcurl contract. This catches drift in
# request JSON and in the exact status named at each endpoint without opening ports.
cat > "$TMP/grpcurl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
method="${!#}"
payload=''
previous=''
for argument in "$@"; do
  if [ "$previous" = -d ]; then payload="$argument"; fi
  previous="$argument"
done
case "$method" in
  */GetPowChallenge) printf '{}\n' ;;
  */VerifyToken) printf '{}\n' ;; # proto3 omits the default false field
  */GetPendingMessages)
    printf 'ERROR:\n  Code: Unauthenticated\n  Message: missing bearer\n' >&2
    exit 1
    ;;
  */Logout)
    printf 'ERROR:\n  Code: InvalidArgument\n  Message: access_token is required\n' >&2
    exit 1
    ;;
  */GetPreKeyBundle)
    printf 'ERROR:\n  Code: NotFound\n  Message: User or device not found\n' >&2
    exit 1
    ;;
  */InitiateCall)
    if ! printf '%s\n' "$payload" | jq -e '
      type == "object"
      and (.call_id | type == "string")
      and (.callee_user_id | type == "string")
      and (.call_type == "CALL_TYPE_AUDIO")
      and ([keys[] | select(
        . != "call_id"
        and . != "callee_user_id"
        and . != "call_type"
        and . != "caller_name"
        and . != "caller_avatar"
      )] | length == 0)
    ' >/dev/null; then
      printf 'Error invoking method: request does not match InitiateCall proto\n' >&2
      exit 1
    fi
    printf 'ERROR:\n  Code: Unauthenticated\n  Message: missing bearer\n' >&2
    exit 1
    ;;
  */GetTurnCredentials)
    printf 'ERROR:\n  Code: Unauthenticated\n  Message: missing bearer\n' >&2
    exit 1
    ;;
  *)
    printf 'unexpected method: %s\n' "$method" >&2
    exit 2
    ;;
esac
EOF
cat > "$TMP/curl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$TMP/grpcurl" "$TMP/curl"

reset_counts
AUTH_HOST=fake-auth
MSG_HOST=fake-messaging
KEY_HOST=fake-key
GW_HOST=fake-gateway
SIG_HOST=fake-signaling
if ! PATH="$TMP:$PATH" main > "$TMP/main.out"; then
  cat "$TMP/main.out"
  exit 1
fi
expect_counts 14 0 0

# Sourcing the file reached here without opening sockets: main is execution-only.
printf 'smoke harness contracts: ok\n'
