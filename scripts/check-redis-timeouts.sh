#!/bin/sh
#
# Every Redis connection in this server must come from `construct_redis::connect`.
#
# Why a check and not a convention: on 2026-09-13 the sealed-sender door was given a
# circuit breaker — on a Redis outage the per-IP window degrades to a per-instance counter
# and the Privacy Pass check is skipped rather than failed. That breaker trips on ERRORS,
# and the worst way Redis fails is not refusal but silence. A connection built without a
# response timeout produces no error, so the breaker never opens and every send hangs
# instead: worse than either failing open or failing closed.
#
# Four sites built connections bare before that, inheriting whatever redis-rs defaults to.
# It happened to be 500 ms. "Happened to be" is the thing this check removes: one more bare
# constructor is one line, changes no behaviour any test can see, and quietly unhooks the
# breaker on whichever path it is on.
#
# Run:  scripts/check-redis-timeouts.sh   (also run by .githooks/pre-push)

cd "$(git rev-parse --show-toplevel)" || exit 1

# The one file allowed to construct a manager directly — it is where the timeouts live.
ALLOWED='crates/construct-redis/src/connect.rs'

hits=$(grep -rn --include='*.rs' \
         -e 'ConnectionManager::new(' \
         -e 'get_connection_manager(' \
         crates */src 2>/dev/null | grep -v "^$ALLOWED:")

if [ -n "$hits" ]; then
    printf '\n[redis-timeouts] Redis connection built without the shared timeouts:\n\n'
    printf '%s\n' "$hits" | sed 's/^/  /'
    cat <<'EOF'

  Use construct_redis::manager_for(client) or construct_redis::connect(url).

  A connection with no response timeout cannot fail, only hang — and the sealed-sender
  circuit breaker only opens on failures. See crates/construct-redis/src/connect.rs.

EOF
    exit 1
fi

echo "[redis-timeouts] все соединения с общими таймаутами"
