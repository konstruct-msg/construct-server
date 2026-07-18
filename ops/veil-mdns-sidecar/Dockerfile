# EntryDirectory Source 3 — island mDNS advertiser.
#
# NOTE: mDNS is multicast and does NOT cross Docker's default bridge network.
# This image MUST be run with host networking AND talk to the HOST's
# avahi-daemon (it does not run its own). See README.md:
#
#   docker run --rm --network host \
#     -v /var/run/dbus:/var/run/dbus \
#     -v /var/run/avahi-daemon/socket:/var/run/avahi-daemon/socket \
#     -e VEIL_MDNS_SNI=relay.a.local \
#     construct-veil-mdns
#
# Prefer the systemd unit (veil-mdns.service) on the relay host where possible —
# it avoids the D-Bus/host-networking plumbing entirely.
FROM alpine:3.20

RUN apk add --no-cache avahi-tools openssl coreutils

COPY veil-mdns-advertise.sh /usr/local/bin/veil-mdns-advertise.sh
RUN chmod +x /usr/local/bin/veil-mdns-advertise.sh

ENTRYPOINT ["/usr/local/bin/veil-mdns-advertise.sh"]
