#!/usr/bin/env bash
# =============================================================================
# Construct Server — Secret preflight check
# =============================================================================
#
# Validate a secrets env file BEFORE deploy, so a misconfigured value fails here
# (loud, on your terminal) instead of in a service that starts "successfully" and
# then silently corrupts or drops traffic.
#
# Mirrors the runtime check in `construct-config::secret_hygiene` — keep the two in
# sync. See construct-docs decisions/key-rotation-and-secret-hygiene.md and
# deployment/stealth-token-keys-runbook.md §6.
#
# Usage:
#   ./scripts/preflight-secrets.sh [path/to/app.env]   # default: /opt/construct/secrets/app.env
#
# Exit codes: 0 = ok (warnings allowed), 1 = at least one hard error.
set -uo pipefail

FILE="${1:-/opt/construct/secrets/app.env}"
ERRORS=0
WARNINGS=0

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

err()  { red  "  ✗ $*"; ERRORS=$((ERRORS + 1)); }
warn() { ylw  "  ! $*"; WARNINGS=$((WARNINGS + 1)); }

if [[ ! -f "$FILE" ]]; then
  red "Secrets file not found: $FILE"
  exit 1
fi

echo "Preflight: $FILE"

# --- helpers ----------------------------------------------------------------

# Read a KEY=value line's raw value (everything after the first '='), no shell eval
# (never source an untrusted secrets file). Returns empty if key absent.
raw_value() {
  local key="$1"
  # last matching assignment wins; strip the "KEY=" prefix only
  grep -E "^[[:space:]]*${key}=" "$FILE" | tail -n1 | sed -E "s/^[[:space:]]*${key}=//"
}

present() { [[ -n "$(raw_value "$1")" ]]; }

check_no_quotes() {
  local key="$1" v; v="$(raw_value "$key")"
  [[ -z "$v" ]] && return 0
  if [[ "$v" =~ ^\".*\"$ || "$v" =~ ^\'.*\'$ ]]; then
    err "$key has surrounding quotes — env_file passes them literally. Write ${key}=value, not ${key}=\"value\"."
  fi
}

check_base64_len() {
  local key="$1" want="$2" v n
  v="$(raw_value "$key")"; [[ -z "$v" ]] && return 0
  # strip a trailing CR (CRLF files) and whitespace
  v="$(printf '%s' "$v" | tr -d '\r' | xargs 2>/dev/null || printf '%s' "$v")"
  if ! n=$(printf '%s' "$v" | base64 -d 2>/dev/null | wc -c | tr -d ' '); then
    err "$key is not valid base64."; return 0
  fi
  if [[ "$n" != "$want" ]]; then
    err "$key must decode to exactly $want bytes (got $n). If you used 'openssl rand -hex $want', that is the wrong encoding — use 'openssl rand -base64 $want'."
  fi
}

check_hex_len() {
  local key="$1" bytes="$2" v want; v="$(raw_value "$key")"
  [[ -z "$v" ]] && return 0
  v="$(printf '%s' "$v" | tr -d '\r' | xargs 2>/dev/null || printf '%s' "$v")"
  want=$((bytes * 2))
  if [[ ! "$v" =~ ^[0-9a-fA-F]{$want}$ ]]; then
    err "$key must be exactly $want hex chars ($bytes bytes) — generate with 'openssl rand -hex $bytes'."
  fi
}

# --- 1. no surrounding quotes on any secret ---------------------------------
echo "[1/3] quote check"
for k in SERVER_SIGNING_KEY TOKEN_ISSUER_KEY BUNDLE_SIGNING_KEY BUNDLE_SIGNING_PUBLIC_KEY \
         APNS_DEVICE_TOKEN_ENCRYPTION_KEY USERNAME_HMAC_SECRET CONTACT_HMAC_SECRET \
         MEDIA_HMAC_SECRET CSRF_SECRET DELIVERY_SECRET_KEY LOG_HASH_SALT TURN_SECRET; do
  check_no_quotes "$k"
done

# --- 2. format / length for keyed secrets (only if present) -----------------
echo "[2/3] format/length check"
check_base64_len SERVER_SIGNING_KEY 32
check_base64_len BUNDLE_SIGNING_KEY 32
check_base64_len BUNDLE_SIGNING_PUBLIC_KEY 32
check_hex_len    TOKEN_ISSUER_KEY 32
check_hex_len    APNS_DEVICE_TOKEN_ENCRYPTION_KEY 32

# --- 3. presence advisories (soft — a service may legitimately not need one) -
echo "[3/3] presence advisories"
present SERVER_SIGNING_KEY || warn "SERVER_SIGNING_KEY absent — federation + token-encryption (sealed sender) disabled."
present TOKEN_ISSUER_KEY   || warn "TOKEN_ISSUER_KEY absent — Privacy Pass issuance + redemption disabled."
present BUNDLE_SIGNING_KEY || warn "BUNDLE_SIGNING_KEY absent — sender certs fall back to the federation signer."
for k in USERNAME_HMAC_SECRET CONTACT_HMAC_SECRET; do
  present "$k" || warn "$k absent — service falls back to an INSECURE default HMAC (privacy weakened)."
done

# --- consistency reminders (cannot verify across hosts from one file) --------
echo
echo "Reminders (not checkable from a single file):"
echo "  • TOKEN_ISSUER_KEY must be identical on identity-service and messaging-service."
echo "  • SERVER_SIGNING_KEY must match across gateway/identity/messaging (+ any federation peer's pin)."
echo "  • After changing this file: 'docker compose … up -d --force-recreate' (restart won't re-read env_file)."

echo
if [[ "$ERRORS" -gt 0 ]]; then
  red "PREFLIGHT FAILED: $ERRORS error(s), $WARNINGS warning(s)."
  exit 1
fi
grn "Preflight OK: 0 errors, $WARNINGS warning(s)."
