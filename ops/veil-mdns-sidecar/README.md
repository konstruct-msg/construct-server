# VEIL island mDNS advertiser — EntryDirectory Source 3

A tiny sidecar that advertises the local island relay on the LAN so a Construct
client in the censored/island regime can **discover** it. It is the server half of
[EntryDirectory Source 3](../../../construct-docs/decisions/entry-directory-source3-local-discovery.md);
the client half (`VeilLocalDiscovery`, `DiscoveredRelayStore`) already ships.

## What it does

Every relay host runs this next to Caddy (`ops/Caddyfile.island`, `tls internal`).
The advertiser:

1. Reads the relay's **live** TLS cert on `:443` and computes its SPKI SHA-256 pin
   (the exact fingerprint the client pins — same `openssl` pipeline used for
   `FEDERATION_PINNED_CERTS` in `ops/island.env.example`).
2. Publishes a Bonjour/mDNS service `_construct-veil._tcp` on port 443 with a TXT
   record, and re-publishes if the cert rotates.

## The trust model (why this is safe to broadcast)

Discovery gives **reachability, never trust.** The advert is public and unauthenticated
— anyone on the LAN can broadcast one. The client accepts a discovered relay **only if
its advertised `spki` matches an identity it already trusts** (a bundled seed pin or a
pin in the Ed25519-signed relay manifest), and then the TLS pin check on connect is the
real enforcement. So a spoofed advert with a foreign key is ignored, and one with a real
key but a different cert fails the pin check. Publishing the SPKI leaks nothing: it is a
public-key fingerprint, already in the client binary / signed manifest.

## TXT record (advert contract)

| Key | Required | Meaning |
|-----|----------|---------|
| `spki` | yes | hex SHA-256 of the cert's SubjectPublicKeyInfo (the trust key) |
| `sni`  | yes | the SNI the client must present (`INSTANCE_DOMAIN`; LAN IPs can't be SNI) |
| `wt`   | no  | WebTunnel WebSocket path (e.g. `/api/stream`); omit for plain-TLS |
| `v`    | yes | advert schema version (`1`) |

## Configuration (environment)

| Var | Default | Meaning |
|-----|---------|---------|
| `VEIL_MDNS_SNI` | — (**required**) | relay's `INSTANCE_DOMAIN` / cert SNI, e.g. `relay.a.local` |
| `VEIL_MDNS_PROBE` | `127.0.0.1:443` | `host:port` to read the live cert from |
| `VEIL_MDNS_PORT` | `443` | port advertised to clients |
| `VEIL_MDNS_WT` | (unset) | WebTunnel path; omit for plain-TLS island relays |
| `VEIL_MDNS_INSTANCE` | `construct-veil-<hostname>` | Bonjour instance name |
| `VEIL_MDNS_RECHECK_SECS` | `3600` | cert re-probe interval (self-corrects on rotation) |
| `VEIL_MDNS_RETRY_SECS` | `10` | backoff while the relay TLS is not yet up |

## Deploy — systemd on the host (recommended)

mDNS is multicast (`224.0.0.251:5353`) and needs LAN reach, so running on the host is
the simplest correct option (no Docker networking to fight).

```sh
apk add avahi avahi-tools openssl      # Alpine;  Debian/Ubuntu: apt install avahi-daemon avahi-utils openssl
rc-service avahi-daemon start          # or: systemctl enable --now avahi-daemon

install -Dm755 veil-mdns-advertise.sh /opt/construct/ops/veil-mdns-sidecar/veil-mdns-advertise.sh
install -Dm644 veil-mdns.service /etc/systemd/system/veil-mdns.service
# edit VEIL_MDNS_SNI in the unit to this node's INSTANCE_DOMAIN
systemctl daemon-reload
systemctl enable --now veil-mdns
```

## Deploy — container (host network + host avahi-daemon)

A bridge-networked container CANNOT do mDNS. It must use `--network host` and talk to
the **host's** avahi-daemon over D-Bus (it does not run its own):

```sh
docker build -t construct-veil-mdns ops/veil-mdns-sidecar
docker run -d --name veil-mdns --restart unless-stopped \
  --network host \
  -v /var/run/dbus:/var/run/dbus \
  -v /var/run/avahi-daemon/socket:/var/run/avahi-daemon/socket \
  -e VEIL_MDNS_SNI=relay.a.local \
  construct-veil-mdns
```

Do not add this to `docker-compose.relay.yml` as a normal service — host networking +
D-Bus mounts are a deliberate per-host choice, kept out of the shared bridge compose.

## Verify it's visible on the LAN

From any host on the same LAN with avahi-utils:

```sh
avahi-browse -rt _construct-veil._tcp
# look for: hostname, port 443, txt = ["spki=…","sni=relay.a.local","v=1"]
```

Cross-check the advertised SPKI equals the relay's real cert:

```sh
openssl s_client -connect relay.a.local:443 -servername relay.a.local </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -hex | awk '{print $NF}'
```

## Scope

mDNS/LAN only — the buildable-now rung of Source 3. Domestic DHT (island I3) and the
offline Reticulum mesh are separate, gated efforts; see the decision doc. When the
client is next to a live advertiser, this closes the loop for a true end-to-end Source 3
test.
