# construct-server — Agent Guide

> Invariants and footguns for agents. Details live in `DOCUMENTATION.md` and
> `~/Code/construct-docs`. Prefer a link over restating a tutorial here.

---

## Service Map

See `ops/docker-compose.prod.yml`. Ports / roles:

| Service | Binary | Port | Role |
|---|---|---|---|
| `caddy` | external | 443 / 8080 | Edge TLS; gRPC route by proto path |
| `quic` | external | 443/UDP | Plain QUIC → caddy:8080 |
| `gateway` | `gateway` | HTTP 3000 / 9443 | health, well-known, federation S2S; veil/obfs4 → caddy:8080 |
| `identity` | `identity-service` | 50051 | Auth + Device + DeviceLink + User + Invite; PoW; PP issuance; sender certs |
| `messaging` | `messaging-service` | 50053 | send/stream, sealed+PP redeem, Redis mailbox, APNs, Sentinel (in-process) |
| `media` | `media-service` | 50056 | Encrypted media gRPC; volume `media-data`; 7d TTL |
| `veil` | `veil-service` | 50056 | VEIL capability issuance (separate deploy) |
| `key` | `key-service` | 50057 | X3DH + ML-KEM prekeys |
| `group` | `group-service` | 50058 | MLS + broadcast channels |
| `signaling` | `signaling-service` | 50060 | WebRTC signaling |
| `masque` | `masque-service` | WS 9200 | MASQUE-lite (not behind Caddy) |

`auth-service` / `user-service` / notification / sentinel as separate deployables are
**gone** — merged into identity or messaging.

**Layout:** `identity-service` wraps `construct-auth-service` / `construct-user-service`.
Notification lives in `messaging-service` (`notification_core.rs`). Product APIs are gRPC.
There is **no** `shared/.../messaging_service/core.rs`. Shared tests inline a
partial dispatcher in `shared/tests/test_utils.rs` — it is not a twin to keep
in sync; production delivery lives only in `messaging-service/src/core.rs`.

Key crates: `construct-config` (+ `secret_hygiene`), `construct-queue`,
`construct-message`, `construct-auth` (PASETO v4.public + legacy JWT),
`construct-db`, `construct-types` (`UserId`, `RouteId`), `construct-federation`,
`construct-apns`. Full crate list → `DOCUMENTATION.md`.

---

## Message Delivery (Redis mailbox)

```
send → XADD delivery:offline:{user}           (legacy; gated by MSG_MAILBOX_USER_WRITE)
     → XADD delivery:offline:{user}:{device}  (per-device fan-out)
     → PUBLISH inbox:wakeup:{user}

stream → SUBSCRIBE inbox:wakeup:{user}
       → read_mailbox_messages (dual-read: device+user when claims.device_id present;
         user-only for legacy tokens; dedupe by message_id, prefer device)
```

**Invariants (do not regress):**

1. **`since_cursor` = read offset only** (Subscribe + GetPendingMessages). Never `XTRIM`
   from a client-asserted cursor — silent-loss class (paging/cancel + multi-device).
2. **Retention** = `MAXLEN ~` on XADD + hourly age sweep (~30d). ADR:
   construct-docs `decisions/minimal-server-delivery.md` (Accepted).
3. **Wake push:** skip APNs silent `new_message` when
   `user:{user_id}:server_instance_id` is set. Online = `inbox:wakeup` only
   (silent push while online → reconnect storms).
4. **Step 4 cutover:** `MSG_MAILBOX_USER_WRITE` (default `1`). Gate =
   `construct_msg_mailbox_user_only_entries_total` **flat zero for 7 days**
   (not `mailbox_read_total{mode=…}` — that only proves clients send `device_id`).
   Rollback = set flag back to `1`. With flag off, reaching no stream is a **hard
   error**, never silent `Ok`.
5. **Serialization:** `rmp_serde::encode::to_vec_named` write /
   `rmp_serde::from_slice` read.
6. **No Kafka** as the user offline queue without a new ADR
   (`decisions/redis-direct-delivery-not-kafka.md`, `architecture/scaling.md`).

---

## Redis Key Namespace

| Key | Type | Purpose |
|---|---|---|
| `delivery:offline:{user}` | Stream | Legacy user inbox |
| `delivery:offline:{user}:{device}` | Stream | Per-device inbox |
| `inbox:wakeup:{user}` | Pub/Sub | Real-time wakeup |
| `msg:dedup:{message_id}` | String | Send idempotency (set **after** mailbox XADD) |
| `user:{user}:server_instance_id` | String | Active MessageStream owner (O(1) routing) |
| `delivery_queue:{instance}` | List | Leftover delivery-worker registry. **Tests only** — prod never writes or polls it |
| `rate_limit:{scope}:{id}` | String | Sliding window |
| `pow_challenge:{token}` | String | PoW challenge |
| `rate:pp_tokens:{user}:{hour}` | Counter | PP issuance cap |
| `spent:{sha256(nonce)}` | String | PP double-spend (30d) |
| `pp:unit:{sha256(spend_id\|recipient)}` | String | Paid multi-chunk unit (2h; recipient-bound) |
| `sealed:exact:{sha256(tag)}` / `sealed:seen:…` | String | `delivery_tag` replay (5m / 24h) |
| `invalidated_token:{jti}` | String | Access-token blocklist |

Do not use `KEYS delivery_queue:*` for discovery (and do not revive that
list). Routing is `GET user:{user}:server_instance_id`.

---

## Auth & Edge

- **PASETO v4.public** primary; legacy RS256 JWT still verified (`v4.public.` prefix).
  Non-standard framing `nonce(32) || message || sig(64)` — client offsets are NOT a bug
  (construct-docs PASETO framing note). TTL default 24h (`ACCESS_TOKEN_TTL_HOURS`).
- **Blocklist:** `invalidated_token:{jti}` on logout/revoke. Logout requires
  `access_token` in body; empty → `INVALID_ARGUMENT`.
- **messaging gRPC:** `extract_authed_user_id()` — Bearer required; verify + blocklist
  (fail-closed on Redis error). Optional `x-user-id` / `x-device-id` must match claims;
  headers alone are never trusted.
- **Caddy does not inject `x-user-id`.** Gateway `:9443` is veil/obfs4 proxy only, not JWT.
  Each service validates via `construct-auth::AuthManager`. File: `ops/Caddyfile`.
- Refresh reverse index: `user_tokens:{user}` → `RevokeAll` is O(n_tokens), not O(all keys).

---

## Sealed Sender + Privacy Pass

Full economics + rollout: construct-docs
`decisions/sealed-sender-anti-abuse-economics.md`,
`deployment/stealth-token-keys-runbook.md`,
`backend/TOKEN_SPEND_UNIT_RECIPIENT_BINDING_SPEC.md`.

**Must not regress:**

- Issuance: identity `IssueTokens`; `TOKEN_ISSUER_KEY` = **32-byte hex** (≠
  `SERVER_SIGNING_KEY` base64). Unset ⇒ fail-quiet; malformed ⇒ boot fail.
- Redemption: messaging `token_redeem.rs`; `MSG_STEALTH_TOKEN_POLICY` =
  `off` | `warn` | `enforce`. Enforce → `FAILED_PRECONDITION` `privacy_pass:{label}`.
  Client may replenish-and-retry; **never** downgrade to identified send.
- Multi-chunk unit: `SealedInner.token_spend_id` + recipient binding
  (`pp:unit:…`); empty spend_id = per-envelope. Cap 256.
- **Invariant:** empty token wallet may degrade anti-abuse, never delivery or anonymity.
  No server path that reveals sender identity on token failure.

Envelope bytes: `sealed_inner` / `encrypted_payload` are `Vec<u8>` with dual-read of
legacy base64/string MessagePack (see `construct-message`). Sealed path keeps
`encrypted_payload` empty (no Redis dual-copy). Federation hashes the wire form as today.

---

## APNs (in messaging)

Merged into messaging (`notification_core`); other services call messaging `:50053`.
Prod + sandbox by `device_tokens.push_environment`.

- Delete tokens only on `BadDeviceToken` / `Unregistered`. **403 = provider auth —
  never delete** (commit `938f395`).
- Registration accepts ≤512 chars (FCM >128 is normal). Silent push is best-effort.
- Low prekeys: key-service may fire `activity_type=replenish_prekeys` when OTP < 5
  or empty (`NOTIFICATION_SERVICE_URL` on key-service).

---

## Sentinel

In-process in messaging (`SentinelCore`); same gRPC port 50053. Fail-open on
Redis/internal errors. IDs are **32-char hex device ids**, not user UUIDs.

---

## Config gotchas

- **`INSTANCE_DOMAIN` required** on every Rust service (no default). Domain mismatch
  breaks federation.
- Never re-declare an `app.env` secret as bare `${VAR}` under compose `environment:` —
  unset shell var blanks it ("Seed must be 32 bytes, got 0"). Rotate with
  `up -d --force-recreate`, not `restart`.
- `SERVER_SIGNING_KEY` = **base64**; `TOKEN_ISSUER_KEY` = **hex**.
- `secret_hygiene` fails boot on present-but-malformed secrets;
  `scripts/preflight-secrets.sh` before deploy.
- Stream knobs / rate limits / PoW tiers: `construct-config` + env
  (`MSG_STREAM_*`, `MSG_POW_*`, `IP_RATE_LIMIT_*`, …). tonic **0.14.x** has no
  `http2_keepalive_while_idle` — app HeartbeatAck is the keepalive.

---

## Identity (Epic E) — short

Additive: `identity_public_key` + `identity_key_type` + `route_id`
(`SHA-256(type || key)`, hex) alongside UUID. E.1/E.2 done; **E.3 pending**
(`UserId::parse` dual addressing + `dispatch_sealed_sender` route_id resolution —
still UUID-only). Details: migration 064, `construct-types` / `construct-db`.

---

## Server-influence minimization

When device A references data on device B, apply construct-docs
`decisions/server-influence-minimization.md`. Outer envelope fields
(`message_id`, `timestamp`, `conversation_id`, `edits_message_id`) are
**transport-only** — E2E semantics live in `MessageContent` / `SealedInner`.

---

## Git workflow (branch + PR only)

**Never commit or push to `main` / `master`.** Landing on `main` is allowed
**only via a GitHub Pull Request** (prefer squash-merge). A topic branch alone
is not enough — opening the PR is mandatory whenever the user asked to commit
and/or push.

1. `git checkout -b feat|fix|chore|docs/<short-topic>` from up-to-date `main`
2. Commit on that branch only (never on `main`)
3. `git push -u origin HEAD` and **`gh pr create`** (or update the existing PR)
4. Land by merging the PR on GitHub — not by local merge + push of `main`,
   and not via `git push origin HEAD:main`

**Forbidden:** commit/push while checked out on `main`; force-push to `main`;
updating `origin/main` outside a PR merge.

If already on `main` with local changes: create/switch to a branch **before**
`git commit`. No agent exceptions for “tiny” / docs-only work.
See `.grok/rules/no-direct-main.md`.

---

## Build, Lint, Test

```bash
cargo build                     # or: cargo build -p messaging-service
cargo test
cargo fmt && cargo clippy       # pre-commit enforces both
```

Commit tip: `cargo fmt && git add -A && git commit` so the hook does not reformat
and fail the commit.

**`cargo test` does not exercise the offline mailbox.** Redis round-trip tests are
`#[ignore]` — a green suite says nothing about delivery (how 2026-08-18 loss shipped).
Before touching delivery or flipping `MSG_MAILBOX_USER_WRITE`:

```bash
docker exec construct-redis-local redis-cli ping   # or: docker compose up -d redis
cargo test -p construct-queue --lib -- --ignored mailbox
```

---

## Known debt (skim)

- `to_app_context()` leaves APNs / token_encryption `None` outside messaging.
- `delivery_queue:{instance}` / `register_server_instance` / `poll_delivery_queue`
  are leftover from delivery-worker; not called in production.
- Signaling: Redis call state OK; in-memory `user_channels` empty after restart
  (clients reconnect — acceptable).
- Epic E.3 pending (above).

---

## Docs

- Repo handbook: `DOCUMENTATION.md`
- Vault: `~/Code/construct-docs` (see its `AGENTS.md` for session/ADR rules)
- Sessions: `sessions/YYYY-MM-DD-<topic>.md` — Context / What Changed / Why /
  Decisions / Open Questions
