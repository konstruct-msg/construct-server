#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Git exports GIT_DIR and related variables while running hooks. A nested fixture
# must not inherit them or `git -C "$REPO" add` will alter the caller's index.
for variable in $(git rev-parse --local-env-vars); do
  unset "$variable"
done
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
REPO="$TMP/repo"
mkdir -p "$REPO/scripts" "$REPO/src" "$TMP/bin"
cp "$ROOT/scripts/mutate-package.sh" "$REPO/scripts/"
printf 'pub fn answer() -> u8 { 42 }\n' > "$REPO/src/lib.rs"
git -C "$REPO" init -q
git -C "$REPO" add scripts/mutate-package.sh src/lib.rs

cat > "$TMP/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = mutants ] && [ "${2:-}" = --version ]; then
  echo 'cargo-mutants fake'
  exit 0
fi
if [ "${1:-}" != mutants ]; then
  exit 64
fi
cp src/lib.rs "$FAKE_ORIGINAL"
printf 'pub fn answer() -> u8 { 0 }\n' > src/lib.rs
if [ "${FAKE_MUTATION_MODE:-restore}" = restore ]; then
  cp "$FAKE_ORIGINAL" src/lib.rs
fi
exit "${FAKE_CARGO_EXIT:-0}"
EOF
chmod +x "$TMP/bin/cargo" "$REPO/scripts/mutate-package.sh"
TEST_PATH="$TMP/bin:/usr/bin:/bin"

set +e
(
  cd "$REPO"
  CARGO_TARGET_DIR="$TMP/shared-target" PATH="$TEST_PATH" \
    scripts/mutate-package.sh fake-package
) >"$TMP/shared.out" 2>&1
status=$?
set -e
test "$status" -eq 64
grep -q 'refusing shared CARGO_TARGET_DIR' "$TMP/shared.out"

set +e
(
  cd "$REPO"
  env -u CARGO_TARGET_DIR PATH="$TEST_PATH" FAKE_ORIGINAL="$TMP/original.rs" \
    FAKE_MUTATION_MODE=restore FAKE_CARGO_EXIT=2 MUTANTS_OUTPUT="$TMP/restored-output" \
    scripts/mutate-package.sh fake-package
) >"$TMP/restored.out" 2>&1
status=$?
set -e
test "$status" -eq 2
grep -q 'restored byte-for-byte' "$TMP/restored.out"
grep -q '42' "$REPO/src/lib.rs"

set +e
(
  cd "$REPO"
  env -u CARGO_TARGET_DIR PATH="$TEST_PATH" FAKE_ORIGINAL="$TMP/original.rs" \
    FAKE_MUTATION_MODE=leave-mutated FAKE_CARGO_EXIT=0 MUTANTS_OUTPUT="$TMP/dirty-output" \
    scripts/mutate-package.sh fake-package
) >"$TMP/dirty.out" 2>&1
status=$?
set -e
test "$status" -eq 70
grep -q 'did not restore tracked Rust sources' "$TMP/dirty.out"
grep -q '0' "$REPO/src/lib.rs"

printf 'mutation harness contracts: ok\n'
