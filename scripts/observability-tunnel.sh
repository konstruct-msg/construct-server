#!/usr/bin/env bash
#
# One command to look at production metrics.
#
# Prometheus, Alertmanager and Grafana all bind to 127.0.0.1 on the server, on purpose
# (ops/docker-compose.prod.yml: "a public grafana.<domain> would be an attack surface on the host
# that runs the messaging server"). Reaching them therefore means an SSH tunnel, and doing that by
# hand has a failure mode worth naming: **a dead tunnel and a missing metric return the same
# thing** — nothing. On 2026-08-21 a tunnel died between two queries and `curl` came back empty,
# which is indistinguishable from "that series does not exist" unless you happen to check.
#
# So this script does not just open ports. It proves each service answered, and says which of the
# two failures it is when one does not.
#
# Usage:
#   scripts/observability-tunnel.sh              # bring up, verify, print URLs
#   scripts/observability-tunnel.sh --open       # …and open Grafana in a browser
#   scripts/observability-tunnel.sh status       # is it up, and does each service answer
#   scripts/observability-tunnel.sh down         # close it
#
# Host comes from the environment, never from this file — the repository is public and the
# server's address is not something to publish in it:
#
#   export CONSTRUCT_OBS_SSH=user@host           # or put it in ~/.construct/observability.env
#
set -euo pipefail

CONFIG="${CONSTRUCT_OBS_CONFIG:-$HOME/.construct/observability.env}"
# shellcheck disable=SC1090
[ -f "$CONFIG" ] && . "$CONFIG"

SSH_TARGET="${CONSTRUCT_OBS_SSH:-}"
PROM_PORT="${CONSTRUCT_OBS_PROM_PORT:-9090}"
ALERT_PORT="${CONSTRUCT_OBS_ALERT_PORT:-9093}"
GRAFANA_PORT="${CONSTRUCT_OBS_GRAFANA_PORT:-3001}"

# One multiplexed connection for all three forwards. `-O check` / `-O exit` then manage it by name,
# which is what makes "is it up" answerable — pgrep over a command line is not, and neither is
# "something is listening on 9090", which a local Prometheus would also satisfy.
CONTROL="${TMPDIR:-/tmp}/construct-obs-tunnel.sock"

c_red()  { printf '\033[31m%s\033[0m\n' "$*"; }
c_grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
c_dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

require_target() {
    if [ -z "$SSH_TARGET" ]; then
        c_red "CONSTRUCT_OBS_SSH is not set."
        echo
        echo "  export CONSTRUCT_OBS_SSH=user@host"
        echo "or, to keep it out of your shell history:"
        echo "  mkdir -p ~/.construct && echo 'CONSTRUCT_OBS_SSH=user@host' > $CONFIG"
        exit 2
    fi
}

tunnel_is_up() {
    ssh -O check -S "$CONTROL" placeholder >/dev/null 2>&1
}

# Ask one service whether it is alive. Three outcomes, and they are deliberately distinct:
#   0 — answered
#   1 — connected, but the service did not answer as expected (it is broken, the tunnel is not)
#   2 — nothing listening (the tunnel is down, or was never up)
probe() {
    local port="$1" path="$2" name="$3" code
    # `-w '%{http_code}'` already prints 000 when the connection fails, and curl also exits
    # non-zero — so `|| echo 000` appends a second one and yields "000000", which matches no case
    # below and lands in the "service is broken" branch. That is the one distinction this whole
    # script exists to make, so it is worth the two lines: take curl's output, and substitute only
    # when there is none.
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${port}${path}" 2>/dev/null) || true
    [ -z "$code" ] && code="000"
    case "$code" in
        200) c_grn "  ✓ ${name} — http://127.0.0.1:${port}"; return 0 ;;
        000) c_red "  ✗ ${name} — nothing listening on ${port} (tunnel down)"; return 2 ;;
        *)   c_red "  ✗ ${name} — reachable but returned HTTP ${code} (service, not tunnel)"; return 1 ;;
    esac
}

probe_all() {
    local rc=0
    probe "$PROM_PORT"    "/-/ready"     "Prometheus  " || rc=$?
    probe "$ALERT_PORT"   "/-/ready"     "Alertmanager" || rc=$?
    probe "$GRAFANA_PORT" "/api/health"  "Grafana     " || rc=$?
    return $rc
}

cmd_up() {
    require_target
    if tunnel_is_up; then
        c_dim "tunnel already open — reusing it"
    else
        # Ports are bound one at a time by ssh; if one is already taken locally it fails the whole
        # connection, which is the honest outcome: a half-open tunnel is how you end up reading a
        # local Prometheus and believing it is production.
        ssh -f -N -M -S "$CONTROL" \
            -o ExitOnForwardFailure=yes \
            -o ServerAliveInterval=30 \
            -o ServerAliveCountMax=3 \
            -L "${PROM_PORT}:127.0.0.1:9090" \
            -L "${ALERT_PORT}:127.0.0.1:9093" \
            -L "${GRAFANA_PORT}:127.0.0.1:3000" \
            "$SSH_TARGET"
        c_dim "tunnel opened to ${SSH_TARGET}"
    fi

    echo
    probe_all || true
    echo
    c_dim "close it with: $0 down"

    if [ "${1:-}" = "--open" ]; then
        command -v open >/dev/null 2>&1 && open "http://127.0.0.1:${GRAFANA_PORT}"
    fi
}

cmd_status() {
    if tunnel_is_up; then
        c_grn "tunnel: open"
    else
        c_red "tunnel: closed"
    fi
    echo
    probe_all
}

cmd_down() {
    if tunnel_is_up; then
        ssh -O exit -S "$CONTROL" placeholder >/dev/null 2>&1 || true
        c_dim "tunnel closed"
    else
        c_dim "no tunnel to close"
    fi
}

case "${1:-up}" in
    up|--open) cmd_up "${1:-}" ;;
    status)    cmd_status ;;
    down|stop|--stop) cmd_down ;;
    # The header block is the help text, so it cannot drift from it. Bounded by where the comments
    # stop rather than by a line number — a hardcoded range printed `set -euo pipefail` and the
    # config lines the moment the header grew.
    -h|--help) awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0" ;;
    *) c_red "unknown command: $1"; echo "try: up | status | down"; exit 2 ;;
esac
