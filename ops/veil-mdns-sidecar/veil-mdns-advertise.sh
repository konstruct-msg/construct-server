#!/usr/bin/env sh
#
# veil-mdns-advertise.sh — EntryDirectory Source 3 island advertiser.
#
# Advertises the local island relay on the LAN as a Bonjour/mDNS service so a
# Construct client in the censored/island regime can DISCOVER it (reachability,
# never trust — the client accepts it only if the advertised SPKI matches an
# already-trusted identity; see the client's VeilLocalDiscovery + the decision
# doc entry-directory-source3-local-discovery.md).
#
# It publishes `_construct-veil._tcp` on port 443 with a TXT record carrying the
# relay's live cert SPKI pin, its SNI, an optional WebTunnel path, and the advert
# schema version. Because it re-derives the SPKI from the *live* cert and
# re-publishes on change, it self-corrects when the relay rotates its cert — a
# stale SPKI would make every client reject the relay (pin mismatch) and silently
# kill Source 3, so freshness is the load-bearing property.
#
# Runs next to the relay (Caddy `tls internal`, see ops/Caddyfile.island). mDNS is
# multicast (224.0.0.251:5353), which does NOT cross Docker's bridge network, so
# this must run on the host or in a host-networked container. See README.md.
#
# POSIX sh. Requires: avahi-utils (avahi-publish-service), openssl.
#
# Config (environment):
#   VEIL_MDNS_SNI           required. The SNI / INSTANCE_DOMAIN the relay's cert
#                           is issued for and the client must present, e.g. relay.a.local
#   VEIL_MDNS_PROBE         optional. host:port to read the live cert from.
#                           Default: 127.0.0.1:443 (sidecar sits next to the relay).
#   VEIL_MDNS_PORT          optional. Port advertised to clients. Default: 443.
#   VEIL_MDNS_WT            optional. WebTunnel WebSocket path (e.g. /api/stream).
#                           Omit for a plain-TLS island relay (the common case).
#   VEIL_MDNS_INSTANCE      optional. Bonjour instance name. Default: construct-veil-<hostname>.
#   VEIL_MDNS_RECHECK_SECS  optional. Re-probe interval seconds. Default: 3600.
#   VEIL_MDNS_RETRY_SECS    optional. Backoff when the relay TLS is not yet up. Default: 10.
#

set -u

SNI="${VEIL_MDNS_SNI:-}"
PROBE="${VEIL_MDNS_PROBE:-127.0.0.1:443}"
PORT="${VEIL_MDNS_PORT:-443}"
WT="${VEIL_MDNS_WT:-}"
INSTANCE="${VEIL_MDNS_INSTANCE:-construct-veil-$(hostname 2>/dev/null || echo relay)}"
RECHECK_SECS="${VEIL_MDNS_RECHECK_SECS:-3600}"
RETRY_SECS="${VEIL_MDNS_RETRY_SECS:-10}"
SERVICE_TYPE="_construct-veil._tcp"

log() { printf '%s veil-mdns: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

[ -n "$SNI" ] || die "VEIL_MDNS_SNI is required (the relay's INSTANCE_DOMAIN / cert SNI)"
command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v avahi-publish-service >/dev/null 2>&1 || die "avahi-publish-service not found (install avahi-utils)"

# Derive the SHA-256 SPKI pin (lowercase hex) from the relay's LIVE TLS cert.
# This is byte-for-byte the fingerprint the client pins: sha256 over the cert's
# SubjectPublicKeyInfo DER. Same pipeline documented in ops/island.env.example
# for FEDERATION_PINNED_CERTS, so encoding cannot drift between server and client.
# Prints the hex on success; prints nothing and returns non-zero on failure.
compute_spki() {
    host="${PROBE%:*}"
    _spki="$(
        openssl s_client -connect "$PROBE" -servername "$SNI" </dev/null 2>/dev/null \
            | openssl x509 -pubkey -noout 2>/dev/null \
            | openssl pkey -pubin -outform der 2>/dev/null \
            | openssl dgst -sha256 -hex 2>/dev/null \
            | awk '{print $NF}'
    )"
    # A valid SHA-256 hex is exactly 64 hex chars.
    case "$_spki" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
            [ "${#_spki}" -eq 64 ] && { printf '%s' "$_spki"; return 0; } ;;
    esac
    return 1
}

PUB_PID=""
kill_publisher() {
    if [ -n "$PUB_PID" ] && kill -0 "$PUB_PID" 2>/dev/null; then
        kill "$PUB_PID" 2>/dev/null
        wait "$PUB_PID" 2>/dev/null
    fi
    PUB_PID=""
}

cleanup() { kill_publisher; log "stopped"; exit 0; }
trap cleanup INT TERM

# (Re)publish the service with the given SPKI. avahi-publish-service holds the
# mDNS record for as long as it runs, so we keep it as a background child and
# replace it when the SPKI changes.
publish() {
    _spki="$1"
    kill_publisher
    # shellcheck disable=SC2086 # $wt_txt is an intentional optional argument
    wt_txt=""
    [ -n "$WT" ] && wt_txt="wt=$WT"
    avahi-publish-service "$INSTANCE" "$SERVICE_TYPE" "$PORT" \
        "spki=$_spki" "sni=$SNI" $wt_txt "v=1" &
    PUB_PID=$!
    log "advertising $INSTANCE $SERVICE_TYPE:$PORT sni=$SNI${WT:+ wt=$WT} spki=$(printf '%s' "$_spki" | cut -c1-8)…"
}

log "starting; probing $PROBE for cert (sni=$SNI)"

CURRENT_SPKI=""
while :; do
    if NEW_SPKI="$(compute_spki)"; then
        if [ "$NEW_SPKI" != "$CURRENT_SPKI" ]; then
            [ -n "$CURRENT_SPKI" ] && log "cert SPKI changed — republishing"
            CURRENT_SPKI="$NEW_SPKI"
            publish "$CURRENT_SPKI"
        elif [ -z "$PUB_PID" ] || ! kill -0 "$PUB_PID" 2>/dev/null; then
            # publisher died (e.g. avahi restart) but SPKI unchanged — respawn it.
            log "publisher not running — respawning"
            publish "$CURRENT_SPKI"
        fi
        sleep "$RECHECK_SECS"
    else
        log "relay TLS not reachable at $PROBE yet — retrying in ${RETRY_SECS}s"
        sleep "$RETRY_SECS"
    fi
done
