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

# --- 1. no key assigned twice -----------------------------------------------
# `raw_value` above says "last matching assignment wins", which is dotenv's rule and
# also the whole problem: a key assigned twice loses one value in silence. On
# 2026-09-09 TOKEN_ISSUER_KEY was in this file twice. Nothing anywhere reported it —
# `secret_hygiene.rs` validates `env::var`, which is the already-collapsed result, so
# it cannot see a duplicate by construction.
#
# It happened to be harmless: the surviving value was the one whose commitment the
# client pins. Had the other line been last, `serverPubkey != pinnedK` would have made
# every client reject every issued batch, wallets would have stayed empty behind a
# full-hour back-off, and no server-side error would have been raised at all —
# TOKEN_ISSUER_KEY_VERSION defaults to 1, so the client's rollout-safety escape (skip
# verification for an unpinned version) would not have fired either.
#
# So the check is here, at the level of the file, which is the only level where the
# fact still exists.
echo "[1/4] duplicate-key check"
dup_keys="$(grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=' "$FILE" \
            | sed -E 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=.*/\1/' \
            | sort | uniq -d)"
if [[ -n "$dup_keys" ]]; then
  while IFS= read -r k; do
    [[ -z "$k" ]] && continue
    n="$(grep -cE "^[[:space:]]*${k}=" "$FILE")"
    err "$k is assigned $n times — dotenv keeps the LAST one and drops the rest silently. Delete the ones that are not live (check with: docker compose exec <service> printenv $k)."
  done <<< "$dup_keys"
fi

# --- 2. no surrounding quotes on any secret ---------------------------------
echo "[2/4] quote check"
for k in SERVER_SIGNING_KEY TOKEN_ISSUER_KEY BUNDLE_SIGNING_KEY BUNDLE_SIGNING_PUBLIC_KEY \
         APNS_DEVICE_TOKEN_ENCRYPTION_KEY USERNAME_HMAC_SECRET CONTACT_HMAC_SECRET \
         MEDIA_HMAC_SECRET CSRF_SECRET LOG_HASH_SALT TURN_SECRET; do
  check_no_quotes "$k"
done

# --- 3. format / length for keyed secrets (only if present) -----------------
echo "[3/4] format/length check"
check_base64_len SERVER_SIGNING_KEY 32
check_base64_len BUNDLE_SIGNING_KEY 32
check_base64_len BUNDLE_SIGNING_PUBLIC_KEY 32
check_hex_len    TOKEN_ISSUER_KEY 32
check_hex_len    APNS_DEVICE_TOKEN_ENCRYPTION_KEY 32

# --- 4. presence + known-bad values -----------------------------------------
echo "[4/4] presence + known-insecure checks"
present SERVER_SIGNING_KEY || warn "SERVER_SIGNING_KEY absent — federation + token-encryption (sealed sender) disabled."
present TOKEN_ISSUER_KEY   || warn "TOKEN_ISSUER_KEY absent — Privacy Pass issuance + redemption disabled."
present BUNDLE_SIGNING_KEY || warn "BUNDLE_SIGNING_KEY absent — sender certs fall back to the federation signer."

# Privacy HMAC/envelope secrets: required for production boots (runtime fails without
# ALLOW_INSECURE_SECRETS). Preflight hard-errors on missing or known insecure values.
for k in USERNAME_HMAC_SECRET CONTACT_HMAC_SECRET REQUEST_ENVELOPE_KEY; do
  if ! present "$k"; then
    err "$k absent — required in production (openssl rand -hex 32). Runtime will fail-boot unless ALLOW_INSECURE_SECRETS=true."
  else
    check_hex_len "$k" 32
  fi
done

turn="$(raw_value TURN_SECRET)"
if [[ -z "$turn" || "$turn" == "changeme" ]]; then
  err "TURN_SECRET absent or set to 'changeme' — required for signaling (openssl rand -hex 32)."
fi

masque="$(raw_value MASQUE_AUTH_TOKEN)"
if [[ -z "$masque" ]]; then
  warn "MASQUE_AUTH_TOKEN absent — masque-service will fail-boot in production (open relay)."
fi

# --- alerting path -----------------------------------------------------------
# Alert rules existed for months and never evaluated, because prometheus.yml had
# no rule_files and there was no Alertmanager. Now that both exist, the next way
# to end up with silent alerting is a receiver nobody finished wiring — so the
# half-configured state is an error rather than a surprise at 03:00.
AM_DIR="$(dirname "$0")/../ops/alertmanager"

if [[ -f "$AM_DIR/alertmanager.yml" ]]; then
  if grep -qE '^[[:space:]]*chat_id:[[:space:]]*0[[:space:]]*$' "$AM_DIR/alertmanager.yml"; then
    err "Alertmanager chat_id is still 0 — alerts will fire and reach nobody. Set it in ops/alertmanager/alertmanager.yml."
  fi
  if [[ ! -s "$AM_DIR/telegram_token" ]]; then
    err "ops/alertmanager/telegram_token is missing or empty — Alertmanager cannot authenticate (see telegram_token.example)."
  elif grep -q "PUT_YOUR_BOT_TOKEN_HERE" "$AM_DIR/telegram_token" 2>/dev/null; then
    err "ops/alertmanager/telegram_token still holds the placeholder."
  else
    # The check above says the token EXISTS. It says nothing about whether the process
    # that needs it can open it, and on 2026-09-10 that was the whole difference: the
    # file was present, non-placeholder, the config loaded, `chat_id` was right, and
    # every notification failed with
    #     could not read /etc/alertmanager/telegram_token: permission denied
    # because the file was root-owned 0600 and the container runs as nobody. Alertmanager
    # reads it at SEND time, not at config load, so nothing complained until the first
    # real alert — and the metrics read as "1 notification, 0 failures" while the retry
    # loop spun, because only `notification_requests_failed_total` moves until the retries
    # are exhausted. Present is not readable, and readable is what matters.
    am_uid="${ALERTMANAGER_UID:-}"
    if [[ -z "$am_uid" ]] && command -v docker >/dev/null 2>&1; then
      am_uid="$(docker inspect -f '{{.Config.User}}' construct-alertmanager 2>/dev/null | cut -d: -f1)"
      [[ "$am_uid" == "nobody" ]] && am_uid=65534
    fi
    # 65534 is `nobody` in the busybox base prom/alertmanager ships; the image sets
    # USER nobody. Override with ALERTMANAGER_UID if that ever changes.
    [[ "$am_uid" =~ ^[0-9]+$ ]] || am_uid=65534

    # GNU stat on the server, BSD stat on a developer's Mac — same three numbers.
    tok_stat="$(stat -c '%u %g %a' "$AM_DIR/telegram_token" 2>/dev/null \
             || stat -f '%u %g %Lp' "$AM_DIR/telegram_token" 2>/dev/null || true)"
    if [[ -z "$tok_stat" ]]; then
      warn "could not stat ops/alertmanager/telegram_token — skipping the readability check."
    else
      read -r tok_uid tok_gid tok_mode <<< "$tok_stat"
      # Zero-pad so ${mode:0:1} is really the owner digit for a 3-digit mode like 600.
      while [[ "${#tok_mode}" -lt 3 ]]; do tok_mode="0$tok_mode"; done
      m_owner="${tok_mode: -3:1}"; m_group="${tok_mode: -2:1}"; m_other="${tok_mode: -1}"
      readable=0
      [[ "$tok_uid" == "$am_uid" && $(( m_owner & 4 )) -ne 0 ]] && readable=1
      [[ "$tok_gid" == "$am_uid" && $(( m_group & 4 )) -ne 0 ]] && readable=1
      [[ $(( m_other & 4 )) -ne 0 ]] && readable=1
      if [[ "$readable" -eq 0 ]]; then
        err "ops/alertmanager/telegram_token is not readable by uid $am_uid (owner=$tok_uid group=$tok_gid mode=$tok_mode) — Alertmanager will fail every notification with 'permission denied'. Fix: sudo chown $am_uid:$am_uid ops/alertmanager/telegram_token && sudo chmod 400 ops/alertmanager/telegram_token"
      fi
      # The mount is a directory; an unsearchable one fails the open just as flatly.
      dir_stat="$(stat -c '%u %g %a' "$AM_DIR" 2>/dev/null \
               || stat -f '%u %g %Lp' "$AM_DIR" 2>/dev/null || true)"
      if [[ -n "$dir_stat" ]]; then
        read -r d_uid d_gid d_mode <<< "$dir_stat"
        while [[ "${#d_mode}" -lt 3 ]]; do d_mode="0$d_mode"; done
        d_other="${d_mode: -1}"
        if [[ "$d_uid" != "$am_uid" && "$d_gid" != "$am_uid" && $(( d_other & 1 )) -eq 0 ]]; then
          err "ops/alertmanager/ is not searchable by uid $am_uid (owner=$d_uid group=$d_gid mode=$d_mode) — the token cannot be opened whatever its own mode says. Fix: sudo chmod o+x ops/alertmanager"
        fi
      fi
    fi
  fi
fi

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
