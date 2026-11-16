#!/usr/bin/env bash
# Run package-local mutation tests without a shared Cargo target and prove that
# cargo-mutants restored every tracked Rust source byte before returning.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/mutate-package.sh <cargo-package> [cargo-mutants arguments...]

CARGO_TARGET_DIR must be unset. The wrapper uses --in-place, stores output outside
the repository, and verifies SHA-256 for every tracked *.rs file after the run.
A cargo-mutants exit status is preserved only after restoration succeeds.
EOF
}

if [ "$#" -lt 1 ]; then
  usage >&2
  exit 64
fi
if [ "${CARGO_TARGET_DIR+x}" = x ]; then
  echo "refusing shared CARGO_TARGET_DIR; unset it before mutation testing" >&2
  exit 64
fi
if ! command -v cargo-mutants >/dev/null 2>&1 && ! cargo mutants --version >/dev/null 2>&1; then
  echo "cargo-mutants is not installed: cargo install cargo-mutants --locked" >&2
  exit 69
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
PACKAGE="$1"
shift
SNAPSHOT="$(mktemp "${TMPDIR:-/tmp}/construct-mutants-sources.XXXXXX")"
OUTPUT="${MUTANTS_OUTPUT:-$(mktemp -d "${TMPDIR:-/tmp}/construct-mutants-output.XXXXXX")}"
trap 'rm -f "$SNAPSHOT"' EXIT

git ls-files -z -- '*.rs' | xargs -0 shasum -a 256 > "$SNAPSHOT"
if [ ! -s "$SNAPSHOT" ]; then
  echo "no tracked Rust sources found" >&2
  exit 66
fi

printf 'mutation output: %s\n' "$OUTPUT"
set +e
cargo mutants -p "$PACKAGE" --in-place --output "$OUTPUT" "$@"
RESULT=$?
set -e

if ! shasum -a 256 -c "$SNAPSHOT" >/dev/null; then
  echo "FATAL: cargo-mutants did not restore tracked Rust sources" >&2
  shasum -a 256 -c "$SNAPSHOT" >&2 || true
  exit 70
fi

printf 'tracked Rust sources restored byte-for-byte\n'
exit "$RESULT"
