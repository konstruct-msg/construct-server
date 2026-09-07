# VEIL multi-front ops — auto first-issue + EntryDirectory alternates

Enable automatic capability issuance and (optionally) failover to a second front.

**If the new VPS already serves its cover site in a browser, skip the VPS runbook and go to [§2f](#2f-cover-already-up--attach-to-home-and-test).** Home does not auto-detect the box — see construct-docs `decisions/relay-enrollment-is-admission.md`.

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

spki <primary-front>
# compare against the pin held in private ops
```

| Front | Role today | Live TLS |
|---|---|---|
| `<primary-front>` | **Primary** veil-front | Probe with `spki` above; pin must match the client seed |
| `<second-front>` | Second front | Probe before listing it anywhere |
| `<retired-front>` | **Retired** — moved to `deprecated_ids` | Kept only so clients rotate off it |

> **Never commit live front hostnames or SPKI pins to this repository.** It is public.
> A censor that can read the inventory gets every access point for free. Real
> hostnames, pins and the `VEIL_RELAYS` value live in private ops only.

---

## 1. Minimum ops (single front — auto first-issue only)

Enough for: login over clearnet → server issues B2 (+ B1 after bootstrap) without QR paste.

On the **home server** (`/opt/construct/secrets/app.env`):

```bash
# 32-byte Ed25519 seed, hex — private half of client relayConfigSigningKey
# and of every veil-front --issuer-pubkey / ISSUER_PUBKEY
VEIL_ISSUER_SEED=<64 hex chars>

# Single front (legacy form is fine)
VEIL_RELAY_ADDRESS=<primary-front>:443
VEIL_RELAY_SCOPE=ru
VEIL_RELAY_SPKI=<64hex-spki>
VEIL_RELAY_SNI=<primary-front>
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
VEIL_RELAYS=<primary-front>:443,ru,<64hex-spki>,<primary-front>;<SECOND_HOST>:443,<scope>,<64hex-spki>,<sni>
```

`docker compose … up -d --force-recreate veil`  
Boot log should show `count=2` (or more).

### 2c. Signed relay manifest

Relay inventory in repo: `tools/relays.json`. The **published** artifact is not that
file — see §2f-C for the procedure. In short: `sign` is the wrong verb for the live
manifest; hand-edit the merged manifest and `resign` it.

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

### 2f. Cover already up — attach to home and test

Use this when the VPS runbook is done (`https://$DOMAIN/` is the cover, not Construct) and you need the **home** side plus a real tunnel.

VPS-side checklist (already true if the cover opens): construct-docs `manuals&instructions/veil-front-new-vps-runbook.md` §6–7. Authenticated path is **not** “open the cover”; the relay will look identical to a browser unless the client presents a capability.

#### A. Pin the live SPKI (laptop, not the VPS)

```sh
DOMAIN=<the-new-front-hostname>
echo | openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" 2>/dev/null \
  | openssl x509 -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | openssl dgst -sha256 -r 2>/dev/null | awk '{print $1}'
```

This hex must match `VEIL_RELAYS`, `tools/relays.json`, and the client seed/manifest. Do not copy an old pin from `relays.json` if the cert was re-issued without `--reuse-key`.

Confirm on the VPS that `ISSUER_PUBKEY` is the public half of home `VEIL_ISSUER_SEED` (`8a0ee71c…` for the production issuer). Wrong pubkey → cover still opens, AUTH never leaves cover.

#### B. Tell home (the only “discovery”)

On the **home** server `/opt/construct/secrets/app.env`, set `VEIL_RELAYS` to **both** fronts (`address,scope,spki,sni` records, `;`-separated) — §2b. Then:

```bash
docker compose -f ops/docker-compose.prod.yml up -d --force-recreate veil
docker logs construct-veil-1 2>&1 | tail -40
# expect: Configured VEIL fronts  count=2
# expect: both host:port keys listed
```

`restart` is not enough (env_file). `count=1` → malformed record or recreate skipped. Do **not** list `ams.konstruct.cc` (plain Caddy) here.

#### C. Signed manifest (client trust)

Without an entry in the signed manifest (or a `seedRelays` append in an app release), a stock client **rejects** the new `{addr, spki}` even if `IssueVeilCapability` returns it.

**Do not run `sign_relay_manifest.py sign` against the live manifest.** `sign` emits a
relay-only document, and what is published is the *merged discovery manifest*, which also
carries `grpc_endpoint`, `signaling_endpoint`, `token_encryption_key`, `capabilities`,
`services` and `bundle_signing_key`. Deploying `sign` output drops all of that. It also
writes `version` and `signed_at` as integers, while the client decodes both as `String?`
(`VeilCertFetcher.ConstructServerWellKnown`) — so the file would not merely be thin, it
would fail to parse at all. `resign` exists for exactly this file: it re-computes the
signature over the current content, leaving every field alone.

Procedure — edit `construct-landing/.well-known/construct-server` (source of truth per
`.well-known/README.md`), then mirror the **signed bytes**:

```bash
LANDING=~/Code/construct-landing/.well-known/construct-server
PUB=8a0ee71cd95f86a9f6877211accefaff6bb97f3051b3b2141f1c71690b9a2dcf

# 1. Hand-edit $LANDING: veil.relays[] from tools/relays.json, veil.primary to a LIVE
#    front, veil.deprecated_ids for retired ids. Bump "version" (string) and set
#    "signed_at" (ISO-8601 UTC). Touch nothing else.

# 2. Re-sign in place — signing key stays on the laptop, never on a VPS.
cd ~/Code/construct-server
python3 tools/sign_relay_manifest.py resign "$LANDING" --key tools/relay_signing_key.hex
python3 tools/sign_relay_manifest.py verify  "$LANDING" --pubkey "$PUB"
# expect: Relays: N  and  ✅ Signature VALID

# 3. Mirror the signed file byte-for-byte, keep tools/relays.json in step.
cp "$LANDING" .well-known/construct-server
```

**Both mirrors must be pushed, close together.** The client races them and takes the first
response that verifies (`VeilCertFetcher.fetchAndCacheRelayConfig`):

| Mirror | Served from |
|---|---|
| `https://konstruct.cc/.well-known/construct-server` | `construct-landing` |
| `https://raw.githubusercontent.com/konstruct-msg/construct-server/main/.well-known/construct-server` | this repo, branch `main` |

A stale mirror is **not** harmless just because the old file is validly signed.
`RelayManifestFreshness.verdict` compares a candidate against the device's **cache**, not
against the other mirror — and with no cache it returns `.accept` unconditionally. A fresh
install that wins the race against the stale mirror therefore latches the old manifest:
dead `primary`, empty `relays`. That is precisely the new-user path this whole runbook
exists to serve. `raw.githubusercontent.com` also caches for ~5 min; confirm the new
`version` on both URLs before calling the deploy done.

#### D. Test 1 — logged-in phone, first front still reachable (in-band alternate)

1. Device already has a session and a live tunnel to the **primary**.
2. Force a capability refresh (relaunch / wait for renew) so `IssueVeilCapability` runs against N=2.
3. Logs: `VEIL provision: cached N/M alternate front(s)` with N≥1.
4. Then Test 2.

#### E. Test 2 — failover (this is “traffic through the new relay”)

On the test network, make the **primary** unusable (DNS sinkhole, `/etc/hosts` → `127.0.0.1`, Little Snitch). Leave the new front alone.

Expect:

- Client does **not** call `IssueVeilCapability` on the dead front.
- **New relay** logs: `capability (v3) valid, routing to tunnel ticket_id=…`
- **Home** gRPC access log / veil-upstream: source IP is the **relay VPS**, not the phone.
- Messaging still works (send / stream).

If you never block the primary, the selector will keep the working seed. Silence on the new box is not a failed deploy.

#### F. Test 3 — capability straight at the new hostname (DEBUG / Internal)

Stock App Store importer still requires `{addr, spki}` in `hardcodedRelaySPKIs` / seed. For a hostname that is **not** in the IPA:

```bash
# laptop — construct-veil/deploy/scripts/provision-link.sh
# NEVER on the relay; needs the config-signing seed locally
RELAY=${DOMAIN}:443 DAYS=1 ./provision-link.sh second-front-smoke
```

Paste/scan the `konstruct://veil-config?d=…` link in an **Internal/DEBUG** build that already pins this SPKI (temporary `seedRelays` append), **or** after the signed manifest is fetched. On the relay, AUTH must precede any gRPC to home. Browser-only success is still just the cover.

A 60-day tester link is the wrong TTL for this door; hours, then throw the B2 away after V3.

#### If AUTH never happens

| Symptom | Cause |
|---|---|
| Cover OK, app also only sees cover | Missing/wrong capability, wrong `ISSUER_PUBKEY`, clock skew |
| `UnknownRelay` / empty `alternates` | Address not in `VEIL_RELAYS` or `count` still 1 |
| Client drops the alternate | `{addr, spki}` not in seed **and** not in the signed manifest it actually fetched |
| HandshakeFailure | Stale SPKI in env vs live cert |
| Home sees the phone IP | Client is on **direct**, not VEIL (auto-mode; primary still reachable) |

---

## 3. Second-front options (decision guide)

### Option A — Revive / re-home `<retired-front>` (fastest if infra exists)

**Pros:** domain already in `tools/relays.json` (`ams-het-1`); NL/Hetzner diversity vs RU primary; same issuer model.

**Cons (2026-08-05):** live TLS probe failed — the name is not a working veil-front right now. Client also retired **obfs4** AMS (`ice.ams…`); a **new** veil-front hostname is fine, do not resurrect obfs4.

**Work:**
1. Deploy `construct-veil` prod stack on a reachable AMS VPS (`deploy/docker-compose.prod.yml`).
2. `DOMAIN=<retired-front>` (or a fresh subdomain), LE cert with `--reuse-key`.
3. `ISSUER_PUBKEY=8a0ee71c…`, backend `ams.konstruct.cc:443` (or current home).
4. DNS A/AAAA → VPS; `spki` into `VEIL_RELAYS` + `relays.json` + client seed.

### Option B — New VPS, new domain (recommended for real resilience)

**Pros:** clean ASN/geo split; no baggage from retired AMS paths; can pick co-tenancy-friendly hosting.

**Checklist:**
1. VPS outside RU DPI (e.g. EU commercial VPS — not the same AS as primary if possible).
2. Domain that looks like ordinary HTTPS — **do not re-use the primary front's branding**.
3. Cover image: **`construct-veil/deploy/cover-site-weather/`** (IP weather + Open-Meteo + SSE). The primary keeps its own, unrelated cover.
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

### Concrete pilot: domestic front → primary IP (chain)

Target layout (domestic VPS + the existing clean primary, dialled by IP):

```text
client → <domestic-front> (chain) → <primary-front-ip>:443 (SNI <primary-front>) → DO backend
client → <primary-front> (direct) → DO backend   # primary when reachable
```

- **IP dial is supported:** `--chain-upstream-addr <primary-front-ip>:443` +
  `--chain-upstream-sni <primary-front>` + SPKI pin (no DNS required on the domestic box).
- Full steps, ROLE_RELAY issuance, compose overlay:
  **`construct-veil/deploy/CHAIN.md`** + `docker-compose.chain.yml`.
- Client seed order: primary first, domestic second (ISP blocks the primary → the
  domestic box still reaches its IP).

---

## 5. Related

- `ops/secrets.example.env` — env var comments
- `veil-service/src/core.rs` — `parse_relays_spec`, `issue_bundle`
- `construct-veil/deploy/` — front stack
- `construct-docs/decisions/entry-directory-design.md`
- `construct-docs/decisions/veil-ticket-provisioning-system.md`
- `construct-docs/decisions/relay-enrollment-is-admission.md` — no self-enroll; this runbook is the self-operated attach path
- Client: `VeilCapabilityProvisioner`, `VeilAlternatesCache`
