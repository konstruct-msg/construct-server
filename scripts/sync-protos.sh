#!/usr/bin/env bash
#
# Vendor shared/proto/ from construct-protos.
#
# ## Which copy is the truth
#
# `construct-protos` is, and this directory is a vendored artifact of it. Not a preference — it is
# what the rest of the ecosystem already does:
#
#   • construct-protos declares itself the shared definitions for every consumer, and is the only
#     one of the two carrying `buf.yaml`, `buf lint` and the `generated/` outputs.
#   • construct-messenger generates directly from it — `generate_grpc_swift.sh` defaults
#     `PROTOS_DIR=$HOME/Code/construct-protos`. construct-android does the same.
#   • This server was the only consumer with a private copy.
#
# ## Why it drifted, and in both directions
#
# Measured 2026-08-21, before this script existed:
#
#   core/envelope.proto      server ahead  — the sentence binding a token spend unit to
#                                            `recipient_user_id`, absent from the file every
#                                            client generates from
#   messaging/content.proto  protos ahead  — `timestamp_ms = 4`, while this copy still said
#                                            `reserved 4 to 10` for a field the client writes
#
# Nothing was enforcing agreement, so two people edited two files and neither edit was wrong.
#
# ## Why a script and a CI check rather than a submodule
#
# A submodule cannot drift, which is the better guarantee, and it was rejected on the failure it
# would add rather than the one it removes. `shared/proto` is compiled by `shared/build.rs` and
# copied into the image by `COPY shared ./shared`, so an uninitialised submodule is an empty
# directory and a build that fails at proto compilation — in CI, in `docker build`, and in the
# pre-push hook. Making that safe means `submodules: recursive` on all seven `actions/checkout`
# steps, and one missed step is a job compiling against no protos.
#
# This repo has already lost three deploys to a mechanical CI failure (see .githooks/pre-push). The
# check below gives the same practical guarantee — a divergence cannot reach main — without putting
# a new way to break the deploy path on the deploy path.
#
# ## Usage
#
#   scripts/sync-protos.sh              # vendor origin/main
#   scripts/sync-protos.sh <ref>        # vendor a specific ref or sha
#   scripts/sync-protos.sh --check      # verify only; non-zero and a file list on divergence
#
set -euo pipefail

UPSTREAM_REPO="https://github.com/konstruct-msg/construct-protos.git"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$REPO_ROOT/shared/proto"
STAMP="$DEST/.upstream"

CHECK_ONLY=0
REF="main"
case "${1:-}" in
  --check) CHECK_ONLY=1 ;;
  "")      ;;
  *)       REF="$1" ;;
esac

# In --check mode the ref is whatever the vendored copy claims, not main. Comparing against a
# moving HEAD would redden this repo's CI for a commit made in another repository, which is a
# failure nobody here can act on.
if [ "$CHECK_ONLY" -eq 1 ]; then
  [ -f "$STAMP" ] || { echo "✗ $STAMP is missing — run scripts/sync-protos.sh to vendor" >&2; exit 1; }
  REF="$(awk -F= '/^commit=/{print $2}' "$STAMP")"
  [ -n "$REF" ] || { echo "✗ no commit= line in $STAMP" >&2; exit 1; }
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --quiet --no-checkout "$UPSTREAM_REPO" "$WORK/protos"
git -C "$WORK/protos" fetch --quiet origin "$REF" 2>/dev/null || git -C "$WORK/protos" fetch --quiet origin
git -C "$WORK/protos" checkout --quiet "$REF"
RESOLVED="$(git -C "$WORK/protos" rev-parse HEAD)"

# Only the .proto tree. buf.yaml, generated/, licences and the repo's own docs belong upstream —
# vendoring them would make this copy look like a fork rather than an artifact.
mkdir -p "$WORK/staged"
(cd "$WORK/protos" && find . -name "*.proto" -not -path "./generated/*" -print0 \
  | while IFS= read -r -d '' f; do
      mkdir -p "$WORK/staged/$(dirname "$f")"
      cp "$f" "$WORK/staged/$f"
    done)

if [ "$CHECK_ONLY" -eq 1 ]; then
  # Compare the .proto tree only, in both directions: a file deleted upstream must not survive here.
  if diff -r -x '.*' "$WORK/staged" "$DEST" > "$WORK/diff.txt" 2>&1; then
    echo "✓ shared/proto matches construct-protos @ ${RESOLVED:0:12}"
    exit 0
  fi
  echo "✗ shared/proto has drifted from construct-protos @ ${RESOLVED:0:12}" >&2
  echo >&2
  sed 's/^/  /' "$WORK/diff.txt" >&2
  echo >&2
  echo "  Fix upstream first — construct-protos is the source of truth — then:" >&2
  echo "    scripts/sync-protos.sh <new-sha>" >&2
  exit 1
fi

find "$DEST" -name "*.proto" -delete
(cd "$WORK/staged" && find . -name "*.proto" -print0 \
  | while IFS= read -r -d '' f; do
      mkdir -p "$DEST/$(dirname "$f")"
      cp "$f" "$DEST/$f"
    done)
find "$DEST" -type d -empty -delete 2>/dev/null || true

cat > "$STAMP" <<EOF
# Provenance of shared/proto — written by scripts/sync-protos.sh. Do not edit by hand.
#
# The .proto files in this directory are vendored from construct-protos and are NOT the source of
# truth. Editing one here is the drift this file exists to make visible: CI re-vendors this commit
# and fails on any difference.
repo=$UPSTREAM_REPO
commit=$RESOLVED
EOF

echo "✓ vendored construct-protos @ ${RESOLVED:0:12} into shared/proto"
git -C "$REPO_ROOT" --no-pager diff --stat -- shared/proto || true
