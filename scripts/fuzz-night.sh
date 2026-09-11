#!/usr/bin/env bash
# Overnight fuzz driver for the pre-authentication surface.
#
# Runs every libFuzzer target in construct-server and construct-core
# concurrently for a fixed wall-clock budget, keeps the corpus between runs, and
# leaves one log per target plus a summary that says what to look at first.
#
# Runbook (what a crash means, what to do with it, what this does NOT cover):
#   ~/Code/construct-docs/security/fuzzing-runbook.md
#
# Usage:
#   scripts/fuzz-night.sh                 # 8 hours, all targets
#   scripts/fuzz-night.sh 3600            # one hour
#   scripts/fuzz-night.sh 3600 fuzz_sealed_inner fuzz_sealed_door
#
# Env:
#   CONSTRUCT_CORE_DIR   default ~/Code/construct-core
#   FUZZ_MAX_LEN         default 65536  (a realistic sealed envelope, not 4 KB)
#   FUZZ_OUT             default ~/fuzz-runs/<timestamp>
#
# Written for the bash macOS actually ships (3.2): no mapfile, no negative array
# indices, no `set -u` around arrays. `set -e` is deliberately absent — a
# crashing target is the point of the exercise and must not end the night for
# the other seven.

set -o pipefail

SECONDS_BUDGET="${1:-28800}"
if [ $# -gt 0 ]; then shift; fi
WANTED=" $* "

SERVER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="${CONSTRUCT_CORE_DIR:-$HOME/Code/construct-core}"
MAX_LEN="${FUZZ_MAX_LEN:-65536}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${FUZZ_OUT:-$HOME/fuzz-runs/$STAMP}"

# target:repo — one row per fuzz binary. Adding a target means adding it here,
# or it silently never runs, which is the failure mode this file exists inside.
TARGETS="
fuzz_sealed_inner:$SERVER_DIR/fuzz
fuzz_sealed_door:$SERVER_DIR/fuzz
fuzz_sealed_token_open:$SERVER_DIR/fuzz
fuzz_privacy_pass_verify:$SERVER_DIR/fuzz
fuzz_wire_payload:$CORE_DIR/fuzz
fuzz_wire_payload_roundtrip:$CORE_DIR/fuzz
fuzz_cfe_envelope:$CORE_DIR/fuzz
fuzz_cfe_roundtrip:$CORE_DIR/fuzz
"

die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }
say() { printf '\033[36m%s\033[0m\n' "$*"; }

command -v cargo-fuzz >/dev/null || die "cargo-fuzz not installed: cargo install cargo-fuzz"
rustup toolchain list 2>/dev/null | grep -q '^nightly' \
  || die "no nightly toolchain: rustup toolchain install nightly (libFuzzer needs -Zsanitizer)"
[ -d "$CORE_DIR/fuzz" ] || die "construct-core fuzz dir not found at $CORE_DIR/fuzz (set CONSTRUCT_CORE_DIR)"

mkdir -p "$OUT"

# ── Build first, all of it, before committing to the night ───────────────────
# A target that does not compile is indistinguishable from a target that finds
# nothing. construct-core's fuzz crate sat in exactly that state — pack() grew
# two parameters and the round-trip target stopped building — because nothing
# built it and the directory is not in git.
for dir in "$SERVER_DIR/fuzz" "$CORE_DIR/fuzz"; do
  repo="$(basename "$(dirname "$dir")")"
  say "building $repo fuzz targets…"
  ( cd "$dir" && SQLX_OFFLINE=true cargo +nightly fuzz build ) >"$OUT/build-$repo.log" 2>&1 \
    || die "fuzz build failed — see $OUT/build-$repo.log"
done

# ── Launch ───────────────────────────────────────────────────────────────────
PIDS=""
STARTED=""
for row in $TARGETS; do
  target="${row%%:*}"
  dir="${row#*:}"

  case "$WANTED" in
    "  ") ;;                                  # no filter: run everything
    *" $target "*) ;;                         # explicitly asked for
    *) continue ;;
  esac

  # Snapshot the artifact dir so the summary reports *new* crashes, not ones
  # already triaged. Old artifacts stay: they are the regression corpus.
  mkdir -p "$dir/artifacts/$target" "$dir/corpus/$target"
  find "$dir/artifacts/$target" -type f 2>/dev/null | sort > "$OUT/$target.before"

  (
    cd "$dir" || exit 1
    SQLX_OFFLINE=true cargo +nightly fuzz run "$target" -- \
      -max_total_time="$SECONDS_BUDGET" \
      -max_len="$MAX_LEN" \
      -rss_limit_mb=4096 \
      -timeout=25 \
      -print_final_stats=1
  ) >"$OUT/$target.log" 2>&1 &

  pid=$!
  PIDS="$PIDS $pid"
  STARTED="$STARTED $target"
  say "  started $target (pid $pid)"
done

[ -n "$PIDS" ] || die "no targets selected"

{
  echo "started      $(date +%Y-%m-%dT%H:%M:%S%z)"
  echo "budget       ${SECONDS_BUDGET}s"
  echo "max_len      $MAX_LEN"
  echo "targets     $STARTED"
  echo "server       $SERVER_DIR ($(git -C "$SERVER_DIR" rev-parse --short HEAD 2>/dev/null || echo '?'))"
  echo "core         $CORE_DIR ($(git -C "$CORE_DIR" rev-parse --short HEAD 2>/dev/null || echo '?'))"
} > "$OUT/run.txt"

say ""
say "running for ${SECONDS_BUDGET}s — logs in $OUT"
say "morning report:  $OUT/SUMMARY.txt"
say ""

# Hold the machine awake for the duration. -i is idle-sleep only: the display
# still sleeps and closing the lid still suspends, so this is not a promise the
# run survives a closed laptop.
caffeinate -i -w $$ &

for pid in $PIDS; do wait "$pid"; done

# ── Morning report ───────────────────────────────────────────────────────────
stat_of() { grep -o "stat::$2: *[0-9]*" "$1" 2>/dev/null | tail -1 | grep -o '[0-9]*$'; }

{
  echo "fuzz run $STAMP — ${SECONDS_BUDGET}s budget"
  echo "================================================================"
  cat "$OUT/run.txt"
  echo
  printf '%-32s %13s %9s %10s %8s\n' TARGET EXECS EXEC/S NEW-UNITS CRASHES

  total_crashes=0
  for row in $TARGETS; do
    target="${row%%:*}"; dir="${row#*:}"
    log="$OUT/$target.log"
    [ -f "$log" ] || continue

    execs=$(stat_of "$log" number_of_executed_units)
    rate=$(stat_of "$log" average_exec_per_sec)
    new=$(stat_of "$log" new_units_added)

    find "$dir/artifacts/$target" -type f 2>/dev/null | sort > "$OUT/$target.after"
    # slow-unit-* is a performance note, not a crash. Counting one as the other
    # is how a fuzz report stops being read.
    comm -13 "$OUT/$target.before" "$OUT/$target.after" \
      | grep -v '/slow-unit-' > "$OUT/$target.new-crashes"
    # `grep -c` prints 0 and exits 1 on no match; a `|| echo 0` here appends a
    # second line and the arithmetic below dies on it.
    crashes=$(grep -c . "$OUT/$target.new-crashes" 2>/dev/null)
    case "$crashes" in ''|*[!0-9]*) crashes=0 ;; esac
    total_crashes=$((total_crashes + crashes))

    printf '%-32s %13s %9s %10s %8s\n' \
      "$target" "${execs:-—}" "${rate:-—}" "${new:-—}" "$crashes"
  done

  echo
  if [ "$total_crashes" -gt 0 ]; then
    echo "NEW CRASHES: $total_crashes — reproduce before anything else:"
    for row in $TARGETS; do
      target="${row%%:*}"; dir="${row#*:}"
      [ -s "$OUT/$target.new-crashes" ] || continue
      while read -r f; do
        [ -n "$f" ] && echo "  (cd $dir && cargo +nightly fuzz run $target '$f')"
      done < "$OUT/$target.new-crashes"
    done
  else
    echo "No new crashes."
    echo
    echo "That is a statement about these targets at this budget and nothing"
    echo "wider. What is still unfuzzed is listed in the runbook under"
    echo "\"What this run does not cover\" — read it before quoting this line."
  fi
} | tee "$OUT/SUMMARY.txt"
