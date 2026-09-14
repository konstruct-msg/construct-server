#!/usr/bin/env bash
# Tests for scripts/split-secrets.sh. Asserts key *names* in generated slices,
# never that values match production. Run from repo root or via CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPLIT="$ROOT/scripts/split-secrets.sh"
FIXTURE="$ROOT/scripts/testdata/secret-split/app.env"
fail=0

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }

assert() {
  local desc="$1"
  shift
  if "$@"; then
    grn "  ok  $desc"
  else
    red "  FAIL $desc"
    fail=$((fail + 1))
  fi
}

slice_has()   { grep -qE "^[[:space:]]*$2=" "$OUT/$1.env"; }
slice_lacks() { ! grep -qE "^[[:space:]]*$2=" "$OUT/$1.env"; }
keys_of() {
  grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' "$OUT/$1.env" \
    | sed -E 's/=.*//; s/^[[:space:]]*//' | sort || true
}

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

chmod +x "$SPLIT"
"$SPLIT" "$FIXTURE" "$OUT" >/dev/null

echo "split-secrets fixture → $OUT"

assert "identity has PASETO_PRIVATE_KEY"          slice_has   identity  PASETO_PRIVATE_KEY
assert "messaging lacks PASETO_PRIVATE_KEY"       slice_lacks messaging PASETO_PRIVATE_KEY
assert "media lacks PASETO_PRIVATE_KEY"           slice_lacks media     PASETO_PRIVATE_KEY
assert "gateway lacks PASETO_PRIVATE_KEY"         slice_lacks gateway   PASETO_PRIVATE_KEY
assert "quic lacks PASETO_PRIVATE_KEY"            slice_lacks quic      PASETO_PRIVATE_KEY

assert "identity has JWT_PRIVATE_KEY"             slice_has   identity  JWT_PRIVATE_KEY
assert "messaging lacks JWT_PRIVATE_KEY"          slice_lacks messaging JWT_PRIVATE_KEY
assert "media lacks JWT_PRIVATE_KEY"              slice_lacks media     JWT_PRIVATE_KEY

assert "identity has TOKEN_ISSUER_KEY"            slice_has   identity  TOKEN_ISSUER_KEY
assert "messaging has TOKEN_ISSUER_KEY"           slice_has   messaging TOKEN_ISSUER_KEY
assert "gateway has TOKEN_ISSUER_KEY"             slice_has   gateway   TOKEN_ISSUER_KEY
assert "media lacks TOKEN_ISSUER_KEY"             slice_lacks media     TOKEN_ISSUER_KEY
assert "key lacks TOKEN_ISSUER_KEY"               slice_lacks key       TOKEN_ISSUER_KEY
assert "group lacks TOKEN_ISSUER_KEY"             slice_lacks group     TOKEN_ISSUER_KEY
assert "signaling lacks TOKEN_ISSUER_KEY"         slice_lacks signaling TOKEN_ISSUER_KEY
assert "veil lacks TOKEN_ISSUER_KEY"              slice_lacks veil      TOKEN_ISSUER_KEY
assert "quic lacks TOKEN_ISSUER_KEY"              slice_lacks quic      TOKEN_ISSUER_KEY

assert "identity has SERVER_SIGNING_KEY"          slice_has   identity  SERVER_SIGNING_KEY
assert "messaging has SERVER_SIGNING_KEY"         slice_has   messaging SERVER_SIGNING_KEY
assert "gateway has SERVER_SIGNING_KEY"           slice_has   gateway   SERVER_SIGNING_KEY
assert "media lacks SERVER_SIGNING_KEY"           slice_lacks media     SERVER_SIGNING_KEY
assert "quic lacks SERVER_SIGNING_KEY"            slice_lacks quic      SERVER_SIGNING_KEY

assert "veil has VEIL_ISSUER_SEED"                slice_has   veil      VEIL_ISSUER_SEED
assert "identity lacks VEIL_ISSUER_SEED"          slice_lacks identity  VEIL_ISSUER_SEED
assert "gateway lacks VEIL_ISSUER_SEED"           slice_lacks gateway   VEIL_ISSUER_SEED

assert "gateway has ICE_SERVER_KEY"               slice_has   gateway   ICE_SERVER_KEY
assert "identity lacks ICE_SERVER_KEY"            slice_lacks identity  ICE_SERVER_KEY

assert "signaling has TURN_SECRET"                slice_has   signaling TURN_SECRET
assert "messaging lacks TURN_SECRET"              slice_lacks messaging TURN_SECRET

assert "messaging has APNS_KEY_PATH"              slice_has   messaging APNS_KEY_PATH
assert "identity lacks APNS_KEY_PATH"             slice_lacks identity  APNS_KEY_PATH
assert "media lacks APNS_KEY_PATH"                slice_lacks media     APNS_KEY_PATH

assert "media has MEDIA_HMAC_SECRET"              slice_has   media     MEDIA_HMAC_SECRET
assert "identity lacks MEDIA_HMAC_SECRET"         slice_lacks identity  MEDIA_HMAC_SECRET
assert "messaging lacks MEDIA_HMAC_SECRET"        slice_lacks messaging MEDIA_HMAC_SECRET

assert "masque has MASQUE_AUTH_TOKEN"             slice_has   masque    MASQUE_AUTH_TOKEN
assert "gateway lacks MASQUE_AUTH_TOKEN"          slice_lacks gateway   MASQUE_AUTH_TOKEN

unlisted=0
for f in "$OUT"/*.env; do
  if grep -q 'SOME_UNLISTED_SECRET' "$f"; then
    unlisted=1
    break
  fi
done
assert "unlisted keys stay out of every slice" test "$unlisted" -eq 0

assert "media still gets DATABASE_URL" slice_has media DATABASE_URL
assert "media lacks USERNAME_HMAC_SECRET" slice_lacks media USERNAME_HMAC_SECRET
assert "media lacks CONTACT_HMAC_SECRET" slice_lacks media CONTACT_HMAC_SECRET
assert "media lacks REQUEST_ENVELOPE_KEY" slice_lacks media REQUEST_ENVELOPE_KEY
assert "media lacks LOG_HASH_SALT" slice_lacks media LOG_HASH_SALT
assert "media lacks REDIS_URL" slice_lacks media REDIS_URL
assert "gateway lacks DATABASE_URL" slice_lacks gateway DATABASE_URL
assert "gateway lacks USERNAME_HMAC_SECRET" slice_lacks gateway USERNAME_HMAC_SECRET
assert "gateway lacks REDIS_URL" slice_lacks gateway REDIS_URL
assert "identity has USERNAME_HMAC_SECRET" slice_has identity USERNAME_HMAC_SECRET
assert "identity has REQUEST_ENVELOPE_KEY" slice_has identity REQUEST_ENVELOPE_KEY
assert "messaging has LOG_HASH_SALT" slice_has messaging LOG_HASH_SALT
assert "signaling has CONTACT_HMAC_SECRET" slice_has signaling CONTACT_HMAC_SECRET
assert "quic does not inherit config_common" slice_lacks quic DATABASE_URL
assert "quic slice has no assignments" test -z "$(keys_of quic)"

id_tok="$(grep -E '^TOKEN_ISSUER_KEY=' "$OUT/identity.env" | sed 's/^TOKEN_ISSUER_KEY=//')"
msg_tok="$(grep -E '^TOKEN_ISSUER_KEY=' "$OUT/messaging.env" | sed 's/^TOKEN_ISSUER_KEY=//')"
assert "TOKEN_ISSUER_KEY identical on identity and messaging" test "$id_tok" = "$msg_tok"

check_log="$(mktemp)"
trap 'rm -rf "$OUT" "$check_log"' EXIT
"$SPLIT" --check-only "$FIXTURE" >"$check_log"
assert "--check-only exits 0 on the fixture" test -s "$check_log"
assert "--check-only does not write testdata/secret-split/slices" \
  test ! -d "$ROOT/scripts/testdata/secret-split/slices"

bad_allow="$(mktemp)"
trap 'rm -rf "$OUT" "$check_log" "$bad_allow"' EXIT
cp "$ROOT/ops/secrets-allowlist.ini" "$bad_allow"
printf '\n[media]\nPASETO_PRIVATE_KEY\n' >>"$bad_allow"
if SPLIT_SECRETS_ALLOWLIST="$bad_allow" "$SPLIT" --check-only "$FIXTURE" >/dev/null 2>&1; then
  red "  FAIL allowlist leak of PASETO_PRIVATE_KEY into media is a hard error"
  fail=$((fail + 1))
else
  grn "  ok  allowlist leak of PASETO_PRIVATE_KEY into media is a hard error"
fi

echo
if [[ "$fail" -gt 0 ]]; then
  red "test-split-secrets: $fail failure(s)"
  exit 1
fi
grn "test-split-secrets: all passed"
