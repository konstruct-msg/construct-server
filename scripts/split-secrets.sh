#!/usr/bin/env bash
# =============================================================================
# Split /opt/construct/secrets/app.env into per-service slices.
# =============================================================================
#
# Humans edit one file. Containers must not all see it. This script intersects
# app.env with ops/secrets-allowlist.ini and writes slices/<service>.env
# (mode 0600). Compose will point env_file at those slices after the cutover;
# until then this is what preflight runs so a bad allowlist fails on a laptop
# instead of at recreate.
#
# Never prints secret values. Never sources app.env (no eval).
#
# Usage:
#   ./scripts/split-secrets.sh [app.env] [slices-dir]
#   ./scripts/split-secrets.sh --check-only [app.env]
#
# Defaults: /opt/construct/secrets/app.env
#           <dir-of-app.env>/slices
#
# --check-only writes to a temp dir, validates, deletes. Exit 0/1 only.
# See construct-docs decisions/secrets-are-sliced-not-shared.md
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ALLOWLIST="${SPLIT_SECRETS_ALLOWLIST:-$ROOT/ops/secrets-allowlist.ini}"

CHECK_ONLY=0
if [[ "${1:-}" == "--check-only" ]]; then
  CHECK_ONLY=1
  shift
fi

SRC="${1:-/opt/construct/secrets/app.env}"
OUT_DEFAULT="$(cd "$(dirname "$SRC")" 2>/dev/null && pwd)/slices"
OUT="${2:-$OUT_DEFAULT}"

ERRORS=0
red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
err()  { red  "  ✗ $*"; ERRORS=$((ERRORS + 1)); }

if [[ ! -f "$SRC" ]]; then
  red "secrets file not found: $SRC"
  exit 1
fi
if [[ ! -f "$ALLOWLIST" ]]; then
  red "allowlist not found: $ALLOWLIST"
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/sec" "$WORK/priv"

# --- parse allowlist --------------------------------------------------------
# Writes:
#   $WORK/sec/<section>   one key or service name per line
#   $WORK/priv/<KEY>      comma-separated allowed services (one line)
section=""
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
  if [[ "$line" =~ ^\[([A-Za-z0-9_-]+)\][[:space:]]*$ ]]; then
    section="${BASH_REMATCH[1]}"
    : >"$WORK/sec/$section"
    continue
  fi
  if [[ -z "$section" ]]; then
    err "allowlist line outside a section: $line"
    continue
  fi
  if [[ "$section" == "private" ]]; then
    key="${line%%=*}"
    rest="${line#*=}"
    if [[ "$key" == "$line" || -z "$rest" ]]; then
      err "private entry must be KEY=svc,svc — got: $line"
      continue
    fi
    printf '%s\n' "$rest" >"$WORK/priv/$key"
  else
    printf '%s\n' "$line" >>"$WORK/sec/$section"
  fi
done <"$ALLOWLIST"

[[ "$ERRORS" -eq 0 ]] || exit 1

inherit_file="$WORK/sec/inherit_config_common"
common_file="$WORK/sec/config_common"
services=()
if [[ -f "$inherit_file" ]]; then
  while IFS= read -r s; do
    [[ -n "$s" ]] && services+=("$s")
  done <"$inherit_file"
fi
# Services that have a section but do not inherit config_common (quic, masque).
for f in "$WORK/sec/"*; do
  [[ -f "$f" ]] || continue
  name="$(basename "$f")"
  case "$name" in
    config_common|inherit_config_common|private) continue ;;
  esac
  already=0
  for s in "${services[@]+"${services[@]}"}"; do
    [[ "$s" == "$name" ]] && already=1 && break
  done
  [[ "$already" -eq 0 ]] && services+=("$name")
done

if [[ "${#services[@]}" -eq 0 ]]; then
  red "allowlist lists no services"
  exit 1
fi

# Keys a service may receive, de-duplicated, stable order.
keys_for() {
  local svc="$1"
  local tmp="$WORK/keys-$svc"
  : >"$tmp"
  if [[ -f "$inherit_file" ]] && grep -qx "$svc" "$inherit_file" 2>/dev/null; then
    [[ -f "$common_file" ]] && cat "$common_file" >>"$tmp"
  fi
  [[ -f "$WORK/sec/$svc" ]] && cat "$WORK/sec/$svc" >>"$tmp"
  # unique, preserve first-seen order
  awk 'NF && !seen[$0]++' "$tmp"
}

# Allowlist self-check: a [private] key must not be listed for a service
# outside its allowed set. Catches a mistaken extra line in a service section.
for privf in "$WORK/priv/"*; do
  [[ -f "$privf" ]] || continue
  key="$(basename "$privf")"
  allowed="$(tr -d ' ' <"$privf")"
  IFS=',' read -r -a allowed_svcs <<<"$allowed"
  for svc in "${services[@]}"; do
    if keys_for "$svc" | grep -qx "$key"; then
      ok=0
      for a in "${allowed_svcs[@]}"; do
        [[ "$a" == "$svc" ]] && ok=1 && break
      done
      if [[ "$ok" -eq 0 ]]; then
        err "allowlist: $key is listed for $svc but [private] allows only $allowed"
      fi
    fi
  done
done

# --- parse app.env (last assignment wins; no eval) --------------------------
# $WORK/val/<KEY> holds the raw value (may be empty).
mkdir -p "$WORK/val"
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue
  if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
    printf '%s' "${BASH_REMATCH[2]}" >"$WORK/val/${BASH_REMATCH[1]}"
  fi
done <"$SRC"

raw_value() {
  local f="$WORK/val/$1"
  [[ -f "$f" ]] && cat "$f" || true
}

# --- write slices -----------------------------------------------------------
if [[ "$CHECK_ONLY" -eq 1 ]]; then
  DEST="$WORK/out"
else
  DEST="$OUT"
fi
mkdir -p "$DEST"
chmod 700 "$DEST" 2>/dev/null || true

for svc in "${services[@]}"; do
  slice="$DEST/$svc.env"
  : >"$slice"
  chmod 600 "$slice" 2>/dev/null || true
  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    [[ -f "$WORK/val/$key" ]] || continue
    val="$(raw_value "$key")"
    # Skip empty: keep the var unset rather than set-to-empty (empty overrides
    # a later default the same way compose ${VAR} already did).
    [[ -z "$val" ]] && continue
    # KEY=value — value copied verbatim from app.env, no quoting added.
    printf '%s=%s\n' "$key" "$val" >>"$slice"
  done < <(keys_for "$svc")
done

# --- denylist on generated slices -------------------------------------------
for privf in "$WORK/priv/"*; do
  [[ -f "$privf" ]] || continue
  key="$(basename "$privf")"
  allowed="$(tr -d ' ' <"$privf")"
  IFS=',' read -r -a allowed_svcs <<<"$allowed"
  for svc in "${services[@]}"; do
    slice="$DEST/$svc.env"
    [[ -f "$slice" ]] || continue
    if grep -qE "^[[:space:]]*${key}=" "$slice"; then
      ok=0
      for a in "${allowed_svcs[@]}"; do
        [[ "$a" == "$svc" ]] && ok=1 && break
      done
      if [[ "$ok" -eq 0 ]]; then
        err "$key leaked into slices/$svc.env (allowed: $allowed)"
      fi
    fi
  done
done

# TOKEN_ISSUER_KEY identity ↔ messaging must match when both present.
id_tok="$(grep -E '^[[:space:]]*TOKEN_ISSUER_KEY=' "$DEST/identity.env" 2>/dev/null | tail -n1 | sed -E 's/^[[:space:]]*TOKEN_ISSUER_KEY=//' || true)"
msg_tok="$(grep -E '^[[:space:]]*TOKEN_ISSUER_KEY=' "$DEST/messaging.env" 2>/dev/null | tail -n1 | sed -E 's/^[[:space:]]*TOKEN_ISSUER_KEY=//' || true)"
if [[ -n "$id_tok" && -n "$msg_tok" && "$id_tok" != "$msg_tok" ]]; then
  err "TOKEN_ISSUER_KEY differs between identity and messaging slices"
fi

if [[ "$ERRORS" -gt 0 ]]; then
  red "split-secrets FAILED: $ERRORS error(s)."
  exit 1
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  grn "split-secrets check OK ($(printf '%s' "${services[*]}" | wc -w | tr -d ' ') slices, no private-key leaks)."
else
  grn "split-secrets wrote $DEST ($(printf '%s ' "${services[@]}"))"
fi
