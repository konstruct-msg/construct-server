# construct-server — Agent Guide

> Quick-start reference for AI agents (and developers) working on this codebase.
> Read this before investigating any service to avoid re-discovering the architecture.

---

## Service Map

| Service | Binary | gRPC Port | HTTP/REST Port | Role |
|---|---|---|---|---|
| `caddy` | external | 443 / 8080 | 80 | TLS (Let's Encrypt), JWT validation, gRPC routing |
| `quic` | external | — | 443/UDP | SALAMANDER-obfuscated QUIC → caddy:8080 (construct-transport) |
| `gateway` | `gateway` | — | 3000 / 9443 | veil/obfs4 obfuscation proxy → caddy:8080 |
| `auth` | `auth-service` | 50051 | 8081 | JWT auth, device registration, PoW challenges |
| `user` | `user-service` | 50052 | 8082 | User profiles, search, relationships, invite tokens |
| `messaging` | `messaging-service` | 50053 | 8083 | gRPC MessageStream, send, Redis direct delivery, APNs push (prod + sandbox), Sentinel anti-spam (in-process) |
| `media` | `media-service` | 50056 | 8086 | S3/local upload, presigned URLs |
| `key` | `key-service` | 50057 | 8087 | X3DH pre-key management (E2EE) |
| `signaling` | `signaling-service` | 50060 | 8091 | WebRTC SDP/ICE signaling |
| `group` | `group-service` | 50058 | 8097 | MLS groups (RFC 9420) + Broadcast channels (PUBLIC/PRIVATE), Sender Key encryption |

---

## Code Structure

### Thin-wrapper pattern
`auth-service`, `user-service` are thin HTTP/gRPC wrappers.
(Notification logic now lives in `messaging-service`; invite logic in `user-service`.)
Their `src/handlers.rs` literally does:
```rust
pub use construct_server_shared::auth_service::handlers::*;
```
All business logic lives in `shared/src/construct_server/<service>/`.

### Shared crate
`shared/` (`construct-server-shared`) contains:
- `src/construct_server/auth_service/` — auth business logic
- `src/construct_server/messaging_service/core.rs` — `dispatch_envelope` + `confirm_pending_message` used **only** by `shared/tests/test_utils.rs` integration tests. Mirrors `messaging-service/src/core.rs` — keep both in sync.
- `src/clients/notification.rs` — `NotificationClient` wrapper (lazy gRPC connect)

### Crates under `crates/`
| Crate | Purpose |
|---|---|
| `construct-config` | All config structs + env var parsing |
| `construct-queue` | Redis stream read/write for messaging |
| `construct-message` | Message envelope types (`MessageEnvelope` — no Kafka transport) |
| `construct-auth` | JWT signing/verification |
| `construct-pow` | Proof-of-Work challenge/verify |
| `construct-rate-limit` | Redis-backed sliding window rate limiter |
| `construct-apns` | APNs HTTP/2 client |
| `construct-redis` | Redis connection pool + retry helpers |
| `construct-context` | `AppContext` adapter (bridges old context to shared services) |
| `construct-federation` | Server signing keys (Ed25519) |
| `construct-metrics` | Prometheus metrics helpers |

---

## Message Delivery Flow (Redis direct — production, multi-device)

```
Client ──gRPC──► messaging-service
                    │
                    ├─► Redis XADD delivery:offline:{user_id}          (legacy user stream)
                    ├─► Redis XADD delivery:offline:{user_id}:{device} (per-device fan-out)
                    └─► Redis PUBLISH inbox:wakeup:{user_id}           (pub/sub wakeup)

messaging-service (stream loop per connected device)
    │
    ├─► Redis SUBSCRIBE inbox:wakeup:{user_id}
    └─► Redis XREAD delivery:offline:{user_id}:{device_id}  (per-device)
            │
            └─► gRPC ServerStreamingResponse → client
```

Fan-out is backwards-compatible: `delivery:offline:{user_id}` is always written, so old clients without `x-device-id` continue to receive messages.

**Critical channel name**: `inbox:wakeup:{user_id}`.

**Serialization**: envelopes must use `rmp_serde::encode::to_vec_named` on write and `rmp_serde::from_slice` on read.

---

## Redis Key Namespace

| Key pattern | Type | Owner | Purpose |
|---|---|---|---|
| `delivery:offline:{user_id}` | Stream (XADD) | messaging-service | Message inbox per user (legacy) |
| `delivery:offline:{user_id}:{device_id}` | Stream (XADD) | messaging-service | Per-device message inbox |
| `inbox:wakeup:{user_id}` | Pub/Sub | messaging-service | Real-time wakeup signal |
| `dispatched_msg:{message_id}` | String (SETEX) | messaging-service | Send-path idempotency dedup |
| `user:{user_id}:server_instance_id` | String (SET) | messaging-service | Which server holds connection |
| `delivery_queue:{server_instance_id}` | List/key (TTL) | messaging-service | Server heartbeat registry |
| `rate_limit:{scope}:{id}` | String | construct-rate-limit | Sliding window counters |
| `pow_challenge:{token}` | String (SETEX) | auth-service | PoW challenge storage |

> Note: `KEYS delivery_queue:*` appears in old comments but is **not used** in runtime code.
> Server discovery uses O(1) `GET user:{user_id}:server_instance_id`.

---

## gRPC Service Dependencies

```
messaging-service
    └── → key-service (via HTTP for key bundles, rare)

auth-service
    └── → user-service (internal gRPC for profile lookup during auth)
```

`sentinel-service` **merged** into messaging-service.
- Sentinel business logic: `construct_server_shared::sentinel_service::core::SentinelCore`
- Sentinel gRPC service (`SentinelService` proto) is registered on messaging's gRPC port (50053)
  — external clients (mobile apps, admin tools) hit the same proto on `messaging:50053`,
  Caddy routes `/shared.proto.sentinel.v1.SentinelService/*` → `messaging:50053`.
- In-process send-path enforcement: `messaging-service/src/grpc.rs` + `stream.rs` call
  `SentinelCore::check_send_permission()` directly (no gRPC hop). Fail-open on Redis/internal
  errors so a sentinel outage never blocks messaging.
- Checks `sender_device_id` / `recipient_device_id` (32-char hex, NOT user UUID)
- `SentinelCore` shares `PgPool` + Redis `ConnectionManager` with messaging-service

---

## APNs Push Architecture

**Notification-service merged into messaging-service:**
- `messaging-service` calls APNs directly via `notification_core::send_blind_notification()`
- APNs clients (prod + sandbox) are initialized in `messaging-service/main.rs`
- `NotificationServiceServer` runs on messaging's gRPC port (50053) for other services (key, signaling, mls, user)
- Env var: `NOTIFICATION_SERVICE_URL` is no longer used by messaging-service; other services point to `messaging:50053`
- Circuit-breaker `NotificationClient` removed — direct APNs call replaces gRPC round-trip

---

## Connection & Stream Config (key defaults)

| Env Var | Default | Effect |
|---|---|---|
| `MSG_STREAM_HEARTBEAT_INTERVAL_SECS` | 10 | HeartbeatAck sent to client |
| `MSG_STREAM_POLL_FALLBACK_SECS` | 1 | XREAD fallback if no pub/sub wakeup |
| `GRPC_KEEPALIVE_INTERVAL_SECS` | 30 | H2 PING interval on gRPC servers |
| `MSG_POW_LEVEL_LOW` | 16 | PoW difficulty bits (low-trust new device) |
| `MSG_POW_LEVEL_MID` | 22 | PoW difficulty bits (mid-trust) |
| `MSG_POW_LEVEL_HIGH` | 24 | PoW difficulty bits (high-trust established) |
| `MESSAGE_TTL_DAYS` | 7 | Redis offline stream retention |

> Note: tonic version is **0.14.5** — no `http2_keepalive_while_idle` support.
> Application-level HeartbeatAck is the keepalive workaround.

---

## Rate Limiting Defaults

| Env Var | Default | Scope |
|---|---|---|
| `IP_RATE_LIMIT_PER_HOUR` | 1000 | Anonymous requests per IP/hour |
| `COMBINED_RATE_LIMIT_PER_HOUR` | 500 | Authenticated requests per user+IP/hour |
| `RATE_LIMIT_BLOCK_SECONDS` | 30 | Block duration after violation |
| `POW_CHALLENGES_PER_HOUR` | 10 | PoW challenge issuance limit |
| `LONG_POLL_RATE_LIMIT_WINDOW_SECS` | 60 | Long-poll rate limit window |

---

## Build, Lint, Test

```bash
cargo build                  # build all
cargo build -p messaging-service  # build one service
cargo test                   # all tests
cargo fmt                    # format (required before commit — pre-commit hook enforces)
cargo clippy                 # lint (pre-commit hook enforces)
```

Pre-commit hook runs `cargo fmt` + `cargo clippy`. Always run `cargo fmt && git add -A && git commit` to avoid the hook re-formatting and failing your commit.

---

## Caddy Configuration

- File: `ops/Caddyfile`
- TLS termination (Let's Encrypt) via vanilla `caddy:alpine` — no JWT plugin
- Internal listener on `:8080` for gateway proxy (plain h2c)
- Routes by gRPC service path prefix to upstream h2c services
- Each service validates JWT itself via `construct-auth::AuthManager`

## Gateway (veil/obfs4 proxy)

- Listens on `0.0.0.0:9443` (obfuscated port for censorship-resistant clients)
- Plain gRPC clients connect via Caddy directly (port 443)
- veil/obfs4 clients connect via gateway:9443 → caddy:8080
- `gateway/src/` — cleaned up, contains only veil proxy logic (no dead code as of checkpoint 004)

---

## Message Delivery Latency Analysis

```
Client gRPC send
  → messaging-service receive
  → Redis XADD + dedup (Mutex on queue)                  ~1-5 ms
  → Redis PUBLISH inbox:wakeup (implicit in write_message_to_user_stream)
  → messaging-service sub wakeup → XREAD                 ~1-5 ms
  → gRPC stream deliver to client

Total: ~5-15 ms

---

## Security Architecture

### Token Lifecycle (access tokens)

- **TTL**: 24 hours (env `ACCESS_TOKEN_TTL_HOURS`, default 24). Was 168h — reduced to limit exposure window.
- **Blocklist key**: `invalidated_token:{jti}` — Redis `SET` with TTL = remaining token lifetime. Written on explicit logout/revocation.
- **Check on gRPC logout** (`AuthService.Logout`): server requires `access_token` in request body (`field 1`). Extracts JTI → adds to blocklist. Client **must populate** `request.accessToken` from Keychain; if empty, server returns `INVALID_ARGUMENT` (client should treat this as a non-fatal warning and continue session cleanup).
- **Check on token verify** (`AuthService.VerifyToken`): crypto verify + `EXISTS invalidated_token:{jti}`.
- **Check in messaging-service gRPC**: `extract_authed_user_id()` in `grpc.rs` — checks blocklist for Bearer JWT auth path (fail-closed on Redis error). `x-user-id` header path (gateway-injected) is trusted without extra check.
- **NOT checked in**: user-service (and other gateway-only services) local JWT verify — these only receive `x-user-id`, no Bearer fallback, so a revoked token cannot reach them directly.

### Refresh Token Reverse Index

- On login: `SADD user_tokens:{user_id} {jti}` + `EXPIRE` to track all active refresh tokens.
- `RevokeAll`: `SMEMBERS user_tokens:{user_id}` → delete each `refresh_token:{jti}` → delete index. O(n_tokens), not O(all_keys).

### Low-Prekey Replenishment

- After `GetPreKeyBundle` / `GetPreKeyBundles` consumes an OTP, key-service fires a **fire-and-forget** `SendBlindNotification` with `activity_type = "replenish_prekeys"` to the device owner if:
  - Remaining OTP count < 5 (`LOW_PREKEY_THRESHOLD`), OR
  - OTP store was already empty (has_one_time_key = false).
- Requires `NOTIFICATION_SERVICE_URL` env var to be set on key-service.
- Client must handle `activity_type = "replenish_prekeys"` by calling `KeyService.UploadPreKeys` in the background (upload `max(0, recommended_minimum - current_count)` keys; recommended_minimum = 20).

---

## Known Issues / Tech Debt

1. **`to_app_context()` adapter** — `AppContext::apns_client` is non-optional, so APNs clients are initialized in `messaging-service/main.rs` even though `to_app_context()` doesn't use them. Full fix: make `apns_client` `Option<ApnsClient>` in `construct-context`.

2. **`delivery_queue:{server_instance_id}` heartbeat keys** — still written by messaging-service heartbeat but never read (routing is user-based via `user:{user_id}:server_instance_id`). Harmless but wasteful writes.

3. **Signaling call state** — call state IS persisted in Redis hashes (`call:{call_id}`, TTL 300s) and `user:{user_id}:active_call` keys. Cross-instance signal forwarding uses Redis pub/sub (`signaling:instance:{instance_id}` channels). Stale in-memory cache bug after `accept_call`/`note_ringing`/`note_keepalive` mutations was fixed (commit `0ec9aac`). Remaining limitation: on restart the in-memory `user_channels` broadcast map is empty, so connected clients lose their gRPC stream and must reconnect — this is acceptable since gRPC streams break on restart anyway.

---

## Documentation

All project documentation: `~/Code/construct-docs` (Obsidian vault).
See `~/Code/construct-docs/AGENTS.md` for writing rules and vault layout.

Session notes: `sessions/YYYY-MM-DD-<topic>.md` with sections `# Context`, `# What Changed`,
`# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`.
