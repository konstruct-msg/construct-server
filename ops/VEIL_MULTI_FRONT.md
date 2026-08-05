# VEIL multi-front ops — auto first-issue + EntryDirectory alternates

Enable automatic capability issuance and (optionally) failover to a second front.

**Code status (2026-08-05):**
- Client: `VeilCapabilityProvisioner` first-issues over any live transport after login.
- Server: `veil-service` `IssueVeilCapability` + `issue_bundle` (K=3 alternates when N>1).
- Failover is **inert until N≥2 fronts** are in `VEIL_RELAYS` *and* trusted by the client
  (seed pin and/or signed relay manifest).

---

## 0. Live inventory (probe before you edit app.env)

```sh
# SPKI pin (must match client seed / VEIL_RELAYS / signed manifest)
spki() {
  local host="$1"
  echo | openssl s_client -connect "${host}:443" -servername "${host}" 2>/dev/null \
    | openssl x509 -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}'
}

spki api.divany-kresla.uk
# expected (2026-08-05 live): 5621e47a745614de08efb054b01388f3bcf32c763ecf5f0aeaeb6b0785ff6861
```

| Front | Role today | Live TLS (2026-08-05) |
|---|---|---|
| `api.divany-kresla.uk` | **Primary** RU veil-front | OK — SPKI matches iOS `ruRelayPinnedSPKI` |
| `veil.ams.konstruct.cc` | Listed in `tools/relays.json` as `ams-het-1` | **No usable cert** (handshake/empty) — not a second front until redeployed |
| `ice.ams.konstruct.cc` | Retired obfs4 | Do not re-use (`retiredRelayHosts` on client) |

---

## 1. Minimum ops (single front — auto first-issue only)

Enough for: login over clearnet → server issues B2 (+ B1 after bootstrap) without QR paste.

On the **home server** (`/opt/construct/secrets/app.env`):

```bash
# 32-byte Ed25519 seed, hex — private half of client relayConfigSigningKey
# and of every veil-front --issuer-pubkey / ISSUER_PUBKEY
VEIL_ISSUER_SEED=<64 hex chars>

# Single front (legacy form is fine)
VEIL_RELAY_ADDRESS=api.divany-kresla.uk:443
VEIL_RELAY_SCOPE=ru
VEIL_RELAY_SPKI=5621e47a745614de08efb054b01388f3bcf32c763ecf5f0aeaeb6b0785ff6861
VEIL_RELAY_SNI=api.divany-kresla.uk
```

Then:

```bash
# Do NOT use bare `restart` — env_file secrets need recreate
docker compose -f ops/docker-compose.prod.yml up -d --force-recreate veil

# Confirm boot
docker logs construct-veil-1 2>&1 | tail -40
# expect: Issuer pubkey (relays pin this): 8a0ee71c…
# expect: Configured VEIL fronts  count=1
```

**Issuer pubkey must equal** `8a0ee71cd95f86a9f6877211accefaff6bb97f3051b3b2141f1c71690b9a2dcf`
(iOS `VEILConfig.relayConfigSigningKey`). If not, wrong seed — clients reject blobs.

Smoke:

1. Fresh install / clear VEIL Keychain ticket.
2. Register + login on clearnet.
3. Logs: `VEIL provision: first capability stored…`
4. Settings / network: ticket present; optional VEIL probe succeeds.

---

## 2. Multi-front (failover when primary is blocked)

Requires **three** places to agree on the same set of fronts:

| Place | What |
|---|---|
| A. `veil-service` `VEIL_RELAYS` | Server issues caps for each front |
| B. Signed `.well-known/construct-server` manifest | Client Option-C trust (anti-redirection) |
| C. Client `VEILConfig.seedRelays` (recommended) | Cold-start pins if manifest fetch fails |

### 2a. Choose a second front

See **§3** below. Do **not** list a front in `VEIL_RELAYS` until it:
- Serves TLS on `:443` with a stable SPKI (`certbot --reuse-key` recommended),
- Runs construct-veil-relay with the **same** `ISSUER_PUBKEY`,
- Proxies to the home backend (`--backend-tls` / `--backend-sni`),
- Has a hostname the client can resolve (or a pinned IP + SNI).

### 2b. Home-server `app.env`

```bash
VEIL_ISSUER_SEED=<same as §1>

# Multi-front form (preferred). Semicolon-separated:
#   address,scope,spki,sni
VEIL_RELAYS=api.divany-kresla.uk:443,ru,5621e47a745614de08efb054b01388f3bcf32c763ecf5f0aeaeb6b0785ff6861,api.divany-kresla.uk;<SECOND_HOST>:443,<scope>,<64hex-spki>,<sni>
```

`docker compose … up -d --force-recreate veil`  
Boot log should show `count=2` (or more).

### 2c. Signed relay manifest

Source of truth in repo: `tools/relays.json`. After adding the second front + live SPKI:

```bash
cd tools
# Private key: tools/relay_signing_key.hex (NEVER on a VPS)
python3 sign_relay_manifest.py sign relays.json --key relay_signing_key.hex
# Deploy signed output to konstruct.cc/.well-known/construct-server (and mirrors)
```

Client accepts alternates only if `{addr, spki}` matches seed **or** this signed manifest
(`VeilAlternatesCache` Option C).

### 2d. Client seed pool (app release)

In `construct-messenger` `VEILConfig.seedRelays`, append:

```swift
VEILSeedRelay(
  address: "<second>:443",
  sni: "<sni>",
  spki: "<live spki>",
  wtPath: nil  // or path if WebTunnel
),
```

Without this, a device that never successfully fetched the manifest may reject
server-handed alternates even when `VEIL_RELAYS` is correct.

### 2e. Failover smoke

1. Login → first-issue → confirm `VEIL provision: cached N/M alternate front(s)` with N≥1.
2. Block primary (DNS sinkhole / firewall) or force selector away from it.
3. Client should dial the alternate **without** re-calling IssueVeilCapability on the dead front.

---

## 3. Second-front options (decision guide)

### Option A — Revive / re-home `veil.ams.konstruct.cc` (fastest if infra exists)

**Pros:** domain already in `tools/relays.json` (`ams-het-1`); NL/Hetzner diversity vs RU primary; same issuer model.

**Cons (2026-08-05):** live TLS probe failed — the name is not a working veil-front right now. Client also retired **obfs4** AMS (`ice.ams…`); a **new** veil-front hostname is fine, do not resurrect obfs4.

**Work:**
1. Deploy `construct-veil` prod stack on a reachable AMS VPS (`deploy/docker-compose.prod.yml`).
2. `DOMAIN=veil.ams.konstruct.cc` (or a fresh subdomain), LE cert with `--reuse-key`.
3. `ISSUER_PUBKEY=8a0ee71c…`, backend `ams.konstruct.cc:443` (or current home).
4. DNS A/AAAA → VPS; `spki` into `VEIL_RELAYS` + `relays.json` + client seed.

### Option B — New VPS, new domain (recommended for real resilience)

**Pros:** clean ASN/geo split; no baggage from retired AMS paths; can pick co-tenancy-friendly hosting.

**Checklist:**
1. VPS outside RU DPI (e.g. EU commercial VPS — not the same AS as primary if possible).
2. Domain that looks like ordinary HTTPS — **do not re-use divany-kresla branding**.
3. Cover image: **`construct-veil/deploy/cover-site-weather/`** (NearSky — IP weather + Open-Meteo + SSE). Primary stays on furniture `cover-site/`.
4. Relay: same `construct-veil` stack (`--site cover:8080`, same `ISSUER_PUBKEY`).
5. Wire into A/B/C trust set (§2).

**Budget note:** one cheap VPS + domain is enough for EntryDirectory v1 (K=1 alternate). More fronts improve enumeration resistance and block survival later.

### Option C — CDN / co-tenancy front (strongest vs IP blocks; more work)

Cloudflare/Workers-style or shared CDN hostname. Highest collateral cost for a censor, but needs a front design that still terminates veil-TLS / WebTunnel correctly. **Not** required for v1 multi-front — do after A or B is live.

### What not to do

- Do **not** put the home API (`ams.konstruct.cc` plain Caddy) into `VEIL_RELAYS` unless it actually runs the veil-front protocol with issuer verify.
- Do **not** reuse `ice.ams.konstruct.cc` (client hard-retired).
- Do **not** ship a shared capability in the binary (rejected by EntryDirectory design).

---

## 4. Suggested sequence

| Step | Action | Unlocks |
|---|---|---|
| 1 | §1 single-front `app.env` + recreate `veil` | Auto first-issue in production |
| 2 | On-device smoke (no QR) | Confidence |
| 3 | Stand up second front (A or B) | Real alternate endpoint |
| 4 | `VEIL_RELAYS` N=2 + recreate | Server issues alternates |
| 5 | Sign+deploy manifest + client seed | Client accepts alternates |
| 6 | Failover smoke | Full EntryDirectory Source 1 |

---

## 5. Related

- `ops/secrets.example.env` — env var comments
- `veil-service/src/core.rs` — `parse_relays_spec`, `issue_bundle`
- `construct-veil/deploy/` — front stack
- `construct-docs/decisions/entry-directory-design.md`
- `construct-docs/decisions/veil-ticket-provisioning-system.md`
- Client: `VeilCapabilityProvisioner`, `VeilAlternatesCache`
