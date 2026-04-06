# construct-server — Agent Guide

> Quick-start reference for AI agents (and developers) working on this codebase.
> Read this before investigating any service to avoid re-discovering the architecture.

---

## Service Map

| Service | Binary | gRPC Port | HTTP/REST Port | Role |
|---|---|---|---|---|
| `traefik` | external | — | 443/80 | TLS termination, HTTPS redirect, CORS |
| `envoy` | external | 8443 | 8080 | H2 multiplexing, gRPC routing, upstream LB |
| `gateway` | `gateway` | — | 3000 / 9443 | ICE/obfs4 obfuscation proxy → envoy:8080 |
| `auth` | `auth-service` | 50051 | 8081 | JWT auth, device registration, PoW challenges |
| `user` | `user-service` | 50052 | 8082 | User profiles, search, relationships |
| `messaging` | `messaging-service` | 50053 | 8083 | gRPC MessageStream, send, Kafka produce |
| `notification` | `notification-service` | 50054 | 8084 | APNs push (prod + sandbox), FCM |
| `invite` | `invite-service` | 50055 | 8085 | Invite link creation and redemption |
| `media` | `media-service` | 50056 | 8086 | S3/local upload, presigned URLs |
| `key` | `key-service` | 50057 | 8087 | X3DH pre-key management (E2EE) |
| `sentinel` | `sentinel-service` | 50059 | 8090 | Anti-spam: rate limiting, block enforcement, trust scoring |
| `signaling` | `signaling-service` | 50060 | 8091 | WebRTC SDP/ICE signaling |
| `delivery` | `delivery-worker` | — | 8092 | Kafka consumer → Redis stream writer |
| `mls` | `mls-service` | — | — | **Stub — commented out in prod** |

---

## Code Structure

### Thin-wrapper pattern
`auth-service`, `user-service`, `notification-service` are thin HTTP/gRPC wrappers.
Their `src/handlers.rs` literally does:
```rust
pub use construct_server_shared::auth_service::handlers::*;
```
All business logic lives in `shared/src/construct_server/<service>/`.

### Shared crate
`shared/` (`construct-server-shared`) contains:
- `src/construct_server/auth_service/` — auth business logic
- `src/construct_server/messaging_service/core.rs` — `dispatch_envelope` + `confirm_pending_message` used **only** by `shared/tests/test_utils.rs` integration tests. The authoritative version is `messaging-service/src/core.rs`; if you change the signature, update both.
- `src/clients/notification.rs` — `NotificationClient` wrapper (lazy gRPC connect)

### Crates under `crates/`
| Crate | Purpose |
|---|---|
| `construct-config` | All config structs + env var parsing |
| `construct-queue` | Redis stream read/write for messaging |
| `construct-broker` | Kafka producer/consumer (`KafkaMessageEnvelope`) |
| `construct-auth` | JWT signing/verification |
| `construct-pow` | Proof-of-Work challenge/verify |
| `construct-rate-limit` | Redis-backed sliding window rate limiter |
| `construct-apns` | APNs HTTP/2 client |
| `construct-redis` | Redis connection pool + retry helpers |
| `construct-context` | `AppContext` adapter (bridges old context to shared services) |
| `construct-federation` | Server signing keys (Ed25519) |
| `construct-metrics` | Prometheus metrics helpers |

---

## Message Delivery Flow (Kafka enabled — production)

```
Client ──gRPC──► messaging-service
                    │
                    ├─► Kafka PRODUCE (topic: messages)
                    │
delivery-worker ◄── Kafka CONSUME
    │
    ├─► Redis XADD  delivery_queue:offline:{user_id}   (stream, 7-day TTL)
    └─► Redis PUBLISH inbox:wakeup:{user_id}            (pub/sub wakeup)

messaging-service (stream loop per connected user)
    │
    ├─► Redis SUBSCRIBE inbox:wakeup:{user_id}  ← wakeup triggers immediate XREAD
    └─► Redis XREAD delivery_queue:offline:{user_id}  (fallback poll: 1s)
            │
            └─► gRPC ServerStreamingResponse → client
```

**Critical channel name**: delivery-worker must publish to `inbox:wakeup:{user_id}`.
Using `message_notifications:{user_id}` (old name) would silently break real-time wakeup, causing ~1s delivery delay.

### Offset commit strategy (at-least-once)
- Delivery-worker writes to Redis stream + marks `processed_msg:{message_id}` atomically (MULTI/EXEC)
- Returns `UserOffline` → Kafka offset NOT committed immediately
- Kafka redelivers → dedup check finds `processed_msg` → returns `Skipped` → offset committed

---

## Redis Key Namespace

| Key pattern | Type | Owner | Purpose |
|---|---|---|---|
| `delivery_queue:offline:{user_id}` | Stream (XADD) | delivery-worker | Message inbox per user |
| `inbox:wakeup:{user_id}` | Pub/Sub | delivery-worker | Real-time wakeup signal |
| `processed_msg:{message_id}` | String (SETEX) | delivery-worker | Dedup guard |
| `delivered_direct:{message_id}` | String (SETEX) | messaging-service | Direct delivery dedup |
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
    ├── → notification-service (SendBlindNotification, silent APNs push for offline users)
    ├── → sentinel-service (CheckSendPermission — rate limit + block enforcement on send path)
    └── → key-service (via HTTP for key bundles, rare)

auth-service
    └── → user-service (internal gRPC for profile lookup during auth)

delivery-worker
    └── Kafka consumer only — no gRPC calls
```

`sentinel-service` has full implementation (`CheckSendPermission`, `ReportSpam`, `GetTrustStatus`).
**Integrated** into messaging-service send path (`grpc.rs`) via `SentinelClient` (lazy gRPC, fail-open).
- `SENTINEL_SERVICE_URL` env var, default `http://sentinel:50059`
- Checks `sender_device_id` / `recipient_device_id` (32-char hex, NOT user UUID)
- On any gRPC error → fail-open (message allowed through)

---

## APNs Push Architecture

**Refactored (commit `69a2cf5`):**
- `messaging-service` → gRPC → `notification-service` → APNs
- `messaging-service/src/core.rs`: `send_blind_notification()` calls `SendBlindNotificationRequest`
- Env var: `NOTIFICATION_SERVICE_URL` (default: `http://notification:50054`)
- APNs clients are still initialized in `messaging-service/main.rs` for `to_app_context()` adapter compat — this is intentional, not dead code

**Before refactor:** messaging-service called APNs directly.

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
| `MESSAGE_TTL_DAYS` | 7 | Kafka + Redis message retention |

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

## Envoy Configuration

- File: `ops/envoy.yaml`
- Uses `dns_lookup_family: V4_ONLY` (important for Docker DNS)
- Routes by `:authority` header or path prefix to upstream gRPC services
- H2 multiplexing: clients connect once, all gRPC calls share the connection

## Gateway (ICE/obfs4 proxy)

- Listens on `0.0.0.0:9443` (obfuscated port for censorship-resistant clients)
- Plain gRPC clients connect via Envoy directly (port 8443)
- ICE/obfs4 clients connect via gateway:9443 → envoy:8080
- `gateway/src/` — cleaned up, contains only ICE proxy logic (no dead code as of checkpoint 004)

---

## Message Delivery Latency Analysis

### Kafka-enabled path (production)

```
Client gRPC send
  → messaging-service receive + Kafka produce            ~1-5 ms
  → Kafka broker stores message
  → delivery-worker poll()                               0-500 ms  ← bottleneck (fetch.wait.max.ms=500)
  → delivery-worker: Redis XADD + SETEX (MULTI/EXEC)    ~1-5 ms
  → delivery-worker: Redis PUBLISH inbox:wakeup          ~1-2 ms
  → messaging-service sub wakeup → XREAD                 ~1-5 ms
  → gRPC stream deliver to client

Total best case:  ~10 ms
Total worst case: ~520 ms  (Kafka consumer just started a 500ms fetch wait)
```

**Key tunable:** `fetch.wait.max.ms=500` in `crates/construct-broker/src/consumer.rs:50`
Reducing to **10ms** would drop worst-case Kafka consumer latency from 500ms → 10ms.
No other config changes needed.

### Kafka-disabled path (dev / when KAFKA_ENABLED=false)

```
Client gRPC send
  → messaging-service receive
  → Redis XADD + dedup (Mutex on queue)                  ~1-5 ms
  → Redis PUBLISH inbox:wakeup (implicit in write_message_to_user_stream)
  → messaging-service sub wakeup → XREAD                 ~1-5 ms
  → gRPC stream deliver to client

Total: ~5-15 ms
```

### Two-delivery Kafka pattern (known design issue)

Every message is processed by delivery-worker **twice**:
1. First delivery: writes to Redis, publishes wakeup → returns `UserOffline` (offset NOT committed)
2. Kafka redelivers → dedup check finds `processed_msg:{id}` → returns `Skipped` → offset committed

The second delivery does NOT affect client-facing latency (message already in Redis stream).
It doubles Kafka consumer throughput consumption and Redis dedup key lookups.

**How to fix** (when ready):
In `delivery-worker/src/processor.rs` `process_kafka_message()`, change the final return to:
```rust
Ok(ProcessResult::Delivered)  // instead of ProcessResult::UserOffline
```
And in `delivery-worker/src/main.rs` consumer loop, commit offset for `Delivered` too.
This requires trusting that Redis MULTI/EXEC was truly atomic (it is — no fix needed there).
At-least-once is still guaranteed by the atomic XADD + SETEX + dedup check.

---

## Security Architecture

### Token Lifecycle (access tokens)

- **TTL**: 24 hours (env `ACCESS_TOKEN_TTL_HOURS`, default 24). Was 168h — reduced to limit exposure window.
- **Blocklist key**: `invalidated_token:{jti}` — Redis `SET` with TTL = remaining token lifetime. Written on explicit logout/revocation.
- **Check on gRPC logout** (`AuthService.Logout`): server requires `access_token` in request body (`field 1`). Extracts JTI → adds to blocklist. Client **must populate** `request.accessToken` from Keychain; if empty, server returns `INVALID_ARGUMENT` (client should treat this as a non-fatal warning and continue session cleanup).
- **Check on token verify** (`AuthService.VerifyToken`): crypto verify + `EXISTS invalidated_token:{jti}`.
- **Check in messaging-service gRPC**: `extract_authed_user_id()` in `grpc.rs` — checks blocklist for Bearer JWT auth path (fail-closed on Redis error). `x-user-id` header path (gateway-injected) is trusted without extra check.
- **NOT checked in**: user-service and notification-service local JWT verify — these are gateway-only services (only receive `x-user-id`, no Bearer fallback), so a revoked token cannot reach them directly.

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

1. **Two-delivery Kafka pattern** — every message is processed twice by delivery-worker (see latency section above). Low priority (second pass is nearly free). Fix: return `ProcessResult::Delivered` in `delivery-worker/src/processor.rs` and commit offset for `Delivered` in the consumer loop.

2. **`to_app_context()` adapter** — `AppContext::apns_client` is non-optional, so APNs clients must be initialized in `messaging-service/main.rs` even though messaging-service no longer calls APNs directly. Full fix: make `apns_client` `Option<ApnsClient>` in `construct-context`.

3. **Duplicate `dispatch_envelope`** — `messaging-service/src/core.rs` (authoritative, 466 lines) and `shared/src/construct_server/messaging_service/core.rs` (462 lines, test-only copy). If you change `dispatch_envelope` signature, update **both** files.

4. **`delivery_queue:{server_instance_id}` heartbeat keys** — still written by messaging-service heartbeat but never read by delivery-worker (routing is user-based via `user:{user_id}:server_instance_id`). Harmless but wasteful writes.

5. **DLQ topic must exist** — delivery-worker sends failures to `{topic}-dlq` (i.e. `messages-dlq`) via `MessageProducer::send_raw_to_topic`. Topic must be pre-created in Redpanda. On producer error falls back to structured `DLQ_MESSAGE` error log.

6. **content-hash dedup (Layer 3) never fires** — `should_skip_message_with_content` hashes ciphertext which always has a random IV per message, so this dedup layer is dead code for E2EE messages. Function exists but is not called from `processor.rs`.

7. **`run_user_online_notification_listener`** in delivery-worker subscribes to `ONLINE_CHANNEL` but takes no action on messages (Kafka auto-redelivers on reconnect). Can be removed.

8. **Signaling registry is in-memory only** — `CallRegistry` stores active call state in `RwLock<HashMap>`. Service restart = all active calls lost. Multi-instance deployments will have desynchronised state (partially mitigated by Redis pub/sub forwarding for signalling messages, but not for call state). Fix: persist call state in Redis hashes with TTL.
