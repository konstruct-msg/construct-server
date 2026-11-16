#!/usr/bin/env bash
# Bounded readiness loop. Exhausting attempts is an error, not a fall-through.
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: $0 <label> <attempts> <delay-seconds> <command> [args...]" >&2
  exit 64
fi
LABEL="$1"
ATTEMPTS="$2"
DELAY="$3"
shift 3

case "$ATTEMPTS" in ''|*[!0-9]*) exit 64 ;; esac
if [ "$ATTEMPTS" -lt 1 ]; then exit 64; fi

echo "Waiting for $LABEL..."
for i in $(seq 1 "$ATTEMPTS"); do
  if "$@" >/dev/null 2>&1; then
    echo "✅ $LABEL ready"
    exit 0
  fi
  echo "  attempt $i/$ATTEMPTS..."
  if [ "$i" -lt "$ATTEMPTS" ]; then
    sleep "$DELAY"
  fi
done

echo "❌ $LABEL did not become ready after $ATTEMPTS attempts" >&2
exit 1
