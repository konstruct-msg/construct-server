# Pre-publish audit findings (security + stability)

**Date:** 2026-07-28  
**Scope:** construct-server services + crates (Phase 0–3 sweep)  
**Priorities:** security, stability, trust boundaries  
**Plan:** session plan (phased audit); this file is the living findings log.

---

## Executive summary

The architecture comment “gateway injects `x-user-id` after JWT” is **out of date** for the current prod path. Traffic is **Caddy → service h2c** with no JWT plugin and no header rewrite. Several services **trust client-supplied `x-user-id` / `x-device-id`**. That is the highest-severity class of issues found so far.

Second class: **insecure secret defaults** that boot with a warning only (HMAC/TURN/MASQUE).

Third class: intentional **Redis fail-open** on abuse controls (availability over anti-spam) — needs explicit launch acceptance + metrics.

---

## Baseline inventory (Phase 0)

| Pattern | Approx count (prod-ish globs) | Notes |
|---------|--------------------------------|-------|
| `let _ =` | 51 | Many signaling channel sends; security-critical discards listed below |
| `.unwrap()` / `.expect(` | 375 | Majority tests/boot; ~15–25 request-path concern |
| `panic!` / `todo!` / `unimplemented!` | 22 | Context adapters, invite version, federation |
| fail-open/closed mentions | 28 | Dominated by messaging-service |
| SQL injection via `format!` queries | 0 | Parameterized sqlx throughout |

### Public surface (prod compose)

| Port | Binding | Service |
|------|---------|---------|
| 80, 443 | host | Caddy TLS → internal h2c services |
| 9443 | host | gateway veil/obfs4 |
| 127.0.0.1:8080 | loopback | Caddy h2c for host-network QUIC |
| 127.0.0.1:9090 | loopback | Prometheus |
| Internal only | docker net | identity, messaging, key, group, signaling, media, veil, postgres, redis |

**Dockerfile:** does not copy `prkeys/`; does not build `masque-service`. Good for release hygiene.

**Caddy:** routes gRPC by proto path; **does not strip or set `x-user-id`**; **does not verify JWT** (vanilla caddy:alpine).

---

## P0 — block publish until fixed or explicitly accepted

### P0-A — CRITICAL: Client can spoof `x-user-id` (auth bypass)

**Status:** FIXED (2026-07-28) — Bearer required; header must match claims  
**Severity:** Critical (was open)  

**Mechanism:**

1. Prod path: client → Caddy:443 → `reverse_proxy h2c://<service>` (no auth middleware).
2. gRPC metadata maps to HTTP/2 headers; client can send `x-user-id: <any-uuid>`.
3. Services that prefer or require this header treat it as authenticated identity.

**Affected code:**

| Location | Behavior |
|----------|----------|
| `messaging-service/src/grpc.rs` `extract_authed_user_id` | **Prefers** `x-user-id` over Bearer+blocklist |
| `shared/.../auth_utils.rs` `extract_user_id` | Same preference (used by identity UserService paths) |
| `group-service/src/helpers.rs` | **Only** `x-user-id` / `x-device-id` — no JWT |
| `veil-service/src/main.rs` | **Only** `x-user-id` |
| `signaling-service/src/service.rs` `caller_user_id` | **Only** `x-user-id` (device_id optionally JWT-checked) |
| `key-service` upload path | Trusts `x-device-id` for authz match (no JWT verify on that header) |
| `crates/construct-extractors/src/trusted_user.rs` | Documents “gateway-only” but gateway no longer injects |

**Impact:** Impersonate any user UUID for messaging send/stream (if only header path used), groups/channels, veil tickets, call signaling user identity, identity user APIs that use `extract_user_id`. Bypass logout/blocklist (Bearer path is skipped when header present).

**Note:** Gateway binary does **not** inject `x-user-id` today (no matches in `gateway/src`). Comments referring to gateway JWT injection are stale.

**Recommended fix (choose one stack):**

1. **Preferred:** At every service: **ignore client `x-user-id` unless from a mTLS/internal mesh identity**, OR strip at Caddy and only set after edge auth.  
2. **Minimal for publish:** Stop trusting client headers: require Bearer JWT (or PASETO) on all authenticated RPCs; optionally use `x-user-id` only when request comes from a known internal peer network (harder with Caddy alone).  
3. **Caddy mitigation (insufficient alone if services still trust client header):** `header_up -x-user-id` then inject after JWT — but vanilla Caddy has no JWT plugin (AGENTS.md). So service-side verify is mandatory.

**Acceptance alternative (not recommended):** Keep header trust **only** if every authenticated client binary is proven never to set it and a WAF/proxy strips it — still fails against a malicious client. Do not accept for public publish.

---

### P0-B — Insecure secret defaults boot successfully

| ID | Secret | Default | File | Status |
|----|--------|---------|------|--------|
| P0-B1 | `USERNAME_HMAC_SECRET` | insecure constant | `security.rs` | **FIXED** — prod fail-boot |
| P0-B2 | `CONTACT_HMAC_SECRET` | insecure constant | security + signaling | **FIXED** |
| P0-B3 | `REQUEST_ENVELOPE_KEY` | insecure constant | `security.rs` | **FIXED** |
| P0-B4 | `TURN_SECRET` | `"changeme"` | signaling | **FIXED** |
| P0-B5 | `MASQUE_AUTH_TOKEN` | empty → open relay | masque | **FIXED** |

**Escape hatch (dev only):** `ALLOW_INSECURE_SECRETS=true`.  
**Preflight:** hard-errors missing HMAC/envelope + `TURN_SECRET=changeme`.

---

### P0-C — Device revoke discards session revocation

**Status:** FIXED (2026-07-28)

- `mark_device_revoked:{device_id}` Redis marker (TTL = access-token lifetime); messaging auth rejects tokens for revoked devices
- Device revoke blocklists caller access JTI when same device; fail-closed on Redis errors
- Logout fail-closed on blocklist / revoke-all / secondary-device cleanup failures
- Fixed wrong key: sessions index is `user_sessions:{user_id}`, not device_id

---

### P0-D — Media admin delete / upload mint unauthenticated

**Status:** FIXED (2026-07-28)

- gRPC `GenerateUploadToken` requires Bearer (PASETO/JWT)
- gRPC `DeleteMedia` requires Bearer **and** existing admin_token HMAC
- REST `handlers::delete_media` (not mounted in prod binary) requires `MEDIA_ADMIN_TOKEN` Bearer
- `UploadMedia` still capability-only via short-lived HMAC upload_token (after authed mint)
- `DownloadMedia` / metadata remain public by media_id (E2E ciphertext capability URL)

---

## P1 — high (fix before or immediately after publish)

### P1-1 Fail-open matrix (messaging + key)

**Status:** DOCUMENTED + METERED (launch policy = keep fail-open; alert on metrics)

| control | On Redis/err | Location | Metric label |
|---------|--------------|----------|--------------|
| send_dedup | proceed | `grpc` SendMessage | `send_dedup` |
| dispatch_dedup | proceed | `core` dispatch | `dispatch_dedup` |
| sentinel | **allow** | `grpc` + `stream` | `sentinel` |
| rate_trust | Trusted, skip caps | `grpc` | `rate_trust` |
| sealed_ip | proceed | SendSealedMessage | `sealed_ip` |
| delivery_tag | deliver | `envelope` | `delivery_tag` |
| federation_origin | proceed | federation RL | `federation_origin` |
| OTPK drain | allow | key-service | `otpk_drain_check` / `otpk_drain_record` |

Fail-closed (unchanged): JWT blocklist, device revoked, PP `enforce`, refresh rotate, signaling mutual contacts.

Metric: `construct_msg_abuse_fail_open_total{control=...}`  
Doc module: `messaging-service/src/fail_open.rs`  
Alert: sustained non-zero `rate(construct_msg_abuse_fail_open_total[5m])`.

### P1-2 Logout / blocklist best-effort

**Status:** FIXED earlier (`c68b1cf`) — logout fail-closed on blocklist/revoke.

### P1-3 Failed-login temporary block discarded

**Status:** FIXED — lockout runs **awaited on request path** (no fire-and-forget
`tokio::spawn`); Redis errors log + `construct_auth_security_fail_open_total`
(`login_block_check` / `login_fail_count` / `login_block_apply` / `login_fail_reset`).
Policy: fail-open on Redis for login availability (same bias as messaging abuse).

### P1-4 Receipt HMAC fallback key

**Status:** FIXED — removed fixed `b"fallback"` key; HMAC uses configured salt only
(`expect` on init; HMAC-SHA256 accepts any key length).

### P1-5 Signature length unwrap (low residual)

**Status:** FIXED — `try_into` → `AppError::Validation` (no request-path panic).

### P1-6 Invite unsupported version panic

**Status:** FIXED — `canonical_string()` returns `Result` (`UnsupportedVersion` / missing device);
callers map to signature/validation errors (no panic on wire data).

### P1-7 Recovery backup dropped

**Status:** FIXED — migration `065_recovery_encrypted_backup.sql`; store opaque blob
(max 256 KiB); `has_backup` reflects column.

### P1-8 Media GenerateUploadToken unauthenticated

**Status:** FIXED via P0-D (`5839407`).

### P1-9 Stealth / Privacy Pass launch policy

**Status:** LOCKED for launch = **`warn`**

| value | Behavior | Use |
|-------|----------|-----|
| `off` | no redeem | emergency/dev only — loud warn at messaging boot |
| **`warn`** | redeem + metrics, always deliver | **default code + prod compose** |
| `enforce` | reject on any redeem failure | after `construct_stealth_token_*` metrics healthy |

Code: `StealthTokenPolicy` default `Warn`; invalid env → `Warn` (not `Off`).  
Compose: `MSG_STEALTH_TOKEN_POLICY=${MSG_STEALTH_TOKEN_POLICY:-warn}`.  
Boot log: messaging prints active policy.  
Path to enforce: runbook + client replenish-and-retry already in place.

### P1-10 key-service upload auth (header-only historically)

**Status:** FIXED via auth PR (`24ba385`) — Bearer + device_id claim match on upload paths.
GetPreKeyBundle remains public-ish with IP rate limit + OTPK drain (metered fail-open).

---

## P2 — stability / hygiene

| ID | Issue | Status |
|----|-------|--------|
| P2-1 | Signaling `let _ = out_tx.send` | **FIXED** — `send_out()` logs on closed stream |
| P2-2 | APNs token DELETE/UPDATE errors discarded | **FIXED** — `if let Err` + error logs |
| P2-3 | Context adapter panic if APNs/token-enc missing | **FIXED** — optional fields, no panic |
| P2-4 | Zero signature placeholders in DB key bundles | **FIXED** (SPK sig from DB); outer bundle envelope sig remains zeros (unused by clients) |
| P2-5 | masque not in workspace / Dockerfile | **FIXED** — in workspace; Dockerfile COPYs sources for resolve, `--exclude masque-service` from multi-service image |
| P2-6 | VoIP rate-limit TODO | **FIXED** — recipient + peer Redis limits; fail-open + `voip_push` metric |
| P2-7 | Docs claim gateway injects user id | **FIXED** — AGENTS + TrustedUser docs |

---

## Positive findings (do not regress)

- Parameterized SQL everywhere checked
- Bearer JWT blocklist path is fail-closed when used
- Privacy Pass redeem is typed; enforce mode is strict
- `secret_hygiene` catches present-but-malformed critical keys
- No production `unsafe` / transmute / mem::forget
- Signaling mutual-contact policy fail-closed
- Refresh token rotation fail-closed
- Internal service ports not published in prod compose
- Docker release stage only copies binaries + migrations

---

## Phase priority (start order)

```
1. P0-A  x-user-id spoofing          ← start immediately (blocks publish)
2. P0-B  insecure secrets fail-boot
3. P0-C  device revoke sessions
4. P0-D  media unauthenticated mint/delete
5. P1-1  fail-open matrix + metrics + PP policy decision
6. P1-2…P1-7 remaining auth/crypto stability
7. Mechanical let _ / unwrap sweep
8. Verification: tests, preflight, smoke, publish memo
```

---

## Recommended fix PR stack

| PR | Content | Blocks publish? |
|----|---------|-----------------|
| **PR-1** | Require cryptographic auth on all user-scoped RPCs; stop trusting client `x-user-id` (or Caddy strip + service verify JWT always) | **YES** |
| **PR-2** | Fail-boot insecure HMAC/TURN/MASQUE; harden preflight | **YES** |
| **PR-3** | Device revoke + logout revocation completeness | **YES** |
| **PR-4** | Media: auth on GenerateUploadToken; lock down delete | **YES** if media public |
| **PR-5** | Receipt HMAC no fallback; invite panic→error; recovery backup | Strongly |
| **PR-6** | Fail-open metrics + optional Sentinel tighten | Policy |
| **PR-7** | Doc/comment fix (gateway no longer injects headers) | Soft |

---

## Decisions (resolved in audit)

1. **Auth:** Bearer required at services (no trust of client `x-user-id`).
2. **`MSG_STEALTH_TOKEN_POLICY`:** **`warn` at launch**; `enforce` later via metrics.
3. **Redis outage abuse:** fail-open + `construct_msg_abuse_fail_open_total` metrics.
4. **Masque:** require `MASQUE_AUTH_TOKEN` in production (fail-boot).

---

## Next actions

- [x] P0 auth / secrets / revoke / media  
- [x] P1 small + fail-open metrics + stealth policy + OTPK meter  
- [x] P1-3 failed-login lockout (await + metrics)  
- [x] Phase 7 smoke script extended (spoof headers, logout, signaling, metrics scrape)  
- [x] Grafana: fail-open panels in `ops/grafana/dashboards/construct-overview.json`  
- [x] P2 hygiene sweep (P2-1…P2-7)  
- [ ] Deploy batch + run `./scripts/smoke-test.sh` against live smoke/prod stack  
- [ ] Confirm Grafana provision picks up dashboard (reload / re-import)  

### Phase 7 smoke (local / CI)

```bash
# Against docker-compose.smoke.yml (default ports):
./scripts/smoke-test.sh
# Optional: IDENTITY_HTTP=localhost:8081 ./scripts/smoke-test.sh
```

Audit-specific cases added: `x-user-id` spoof without Bearer, Bearer+mismatched header,
Logout empty token, InitiateCall spoof, optional identity `/metrics` scrape.

---

## Appendix: key file map

| Area | Paths |
|------|-------|
| Auth extract | `messaging-service/src/grpc.rs`, `shared/src/construct_server/auth_utils.rs`, `construct-extractors` |
| Secrets | `construct-config/src/{security,secret_hygiene}.rs`, `scripts/preflight-secrets.sh` |
| Sealed / PP | `messaging-service/src/{envelope,token_redeem,spent_tag}.rs` |
| Edge | `ops/Caddyfile`, `ops/docker-compose.prod.yml`, `gateway/src/main.rs` |
| Revoke | `identity-service/src/main.rs`, `construct-auth-service/src/core.rs` |
| Media | `media-service/src/{main,handlers}.rs` |
