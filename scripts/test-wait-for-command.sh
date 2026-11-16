#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/eventually" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [ -f "$ATTEMPT_FILE" ]; then count=$(cat "$ATTEMPT_FILE"); fi
count=$((count + 1))
printf '%s\n' "$count" > "$ATTEMPT_FILE"
test "$count" -ge "${SUCCEED_AT:-999}"
EOF
chmod +x "$TMP/eventually"

ATTEMPT_FILE="$TMP/success-count" SUCCEED_AT=3 \
  "$ROOT/scripts/wait-for-command.sh" eventual 5 0 "$TMP/eventually"
test "$(cat "$TMP/success-count")" -eq 3

set +e
ATTEMPT_FILE="$TMP/failure-count" SUCCEED_AT=999 \
  "$ROOT/scripts/wait-for-command.sh" exhausted 3 0 "$TMP/eventually" \
  >"$TMP/exhausted.out" 2>&1
status=$?
set -e
test "$status" -eq 1
test "$(cat "$TMP/failure-count")" -eq 3
grep -q 'did not become ready after 3 attempts' "$TMP/exhausted.out"

printf 'readiness harness contracts: ok\n'
