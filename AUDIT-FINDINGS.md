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

| Control | On Redis error | Location |
|---------|----------------|----------|
| Send idempotency/dedup | proceed | `grpc.rs` ~374 |
| Sentinel `check_send_permission` outer Err | **allow** | `grpc.rs` ~431–445, `stream.rs` |
| Trust/hourly rate | skip; trust=Trusted | `grpc.rs` ~497–498 |
| Sealed IP rate limit | proceed | `grpc.rs` ~662 |
| Delivery-tag replay | deliver | `envelope.rs`, `spent_tag.rs` |
| Federation origin RL | proceed | `federation.rs` ~79 |
| Dedup mark write | ignore | `core.rs` ~78 |
| OTPK drain | allow | `key-service` |
| JWT blocklist (Bearer only) | **reject** | `grpc.rs` ~953 |
| Privacy Pass `enforce` | reject incl. RedisError | `token_redeem` + envelope |
| Refresh token rotate | fail closed | `construct-auth-service` |
| Signaling mutual contacts | fail closed | signaling |

**Launch default:** `MSG_STEALTH_TOKEN_POLICY` = `warn` in `docker-compose.prod.yml` (log, still deliver).

**Actions:** Document product acceptance; add metrics counters on every fail-open branch; consider fail-closed for Sentinel outer Err and sealed IP limits under prolonged outage.

### P1-2 Logout / blocklist best-effort

`construct-auth-service` `logout_user`: blocklist / revoke-all errors logged, logout still succeeds.

### P1-3 Failed-login temporary block discarded

`devices.rs` ~724: `let _ = q.block_user_temporarily(...).await` inside spawn — lockout can silently fail.

### P1-4 Receipt HMAC fallback key

`messaging-service/src/core.rs` ~412–413: invalid salt → key `b"fallback"`. Never use fixed fallback; panic at boot or return error if salt empty.

### P1-5 Signature length unwrap (low residual)

`devices.rs` ~404: `.unwrap()` after earlier length check (~390). Prefer `try_into` + Validation for consistency (panic if check drifts).

### P1-6 Invite unsupported version panic

`crypto-agility` / shared invite model: `panic!("Unsupported invite version")` — convert to error.

### P1-7 Recovery backup dropped

`identity-service/src/recovery.rs`: `let _ = backup; // placeholder` — client may believe backup stored.

### P1-8 Media GenerateUploadToken unauthenticated

See P0-D; storage DoS vector.

### P1-9 key-service auth is header-only for uploads

Upload paths require `x-device-id` metadata and body match — spoofable if client sets both to same value without JWT binding. GetPreKeyBundle is intentionally public-ish with IP rate limit.

---

## P2 — stability / hygiene

| ID | Issue | Where |
|----|-------|-------|
| P2-1 | Many `let _ = out_tx.send` | signaling (call UX) |
| P2-2 | APNs token DELETE/UPDATE errors discarded | notification_core |
| P2-3 | Context adapter panic if APNs/token-enc missing | identity/auth/user contexts |
| P2-4 | Zero signature placeholders in DB key bundles | construct-db TODOs |
| P2-5 | masque not in workspace / Dockerfile | root Cargo / ops |
| P2-6 | VoIP rate-limit TODO | notification_core |
| P2-7 | Docs claim gateway injects user id | AGENTS, extractors, auth_utils |

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

## Decisions needed from product/security

1. **Auth model for public gRPC via Caddy:** JWT-only at every service, or reintroduce edge auth that strips/injects headers?
2. **`MSG_STEALTH_TOKEN_POLICY` at launch:** keep `warn` or move to `enforce`?
3. **Redis outage abuse policy:** accept fail-open with metrics, or fail-closed for rate/sentinel after N errors?
4. **Is masque in scope for this publish?** If no, document “not shipped”; if yes, require auth token at boot.

---

## Next actions (execution)

- [ ] Implement PR-1 (auth spoofing) — highest ROI  
- [ ] Implement PR-2 (secrets)  
- [ ] Implement PR-3 (revoke)  
- [ ] Re-grep after fixes; update this file status columns  
- [ ] Phase 7 verification gate  

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
