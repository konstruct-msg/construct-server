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
| `sentinel` | `sentinel-service` | 50059 | 8090 | Anti-spam trust scoring (**running but not integrated**) |
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
- `src/construct_server/messaging_service/` — **second copy** of messaging core used only by shared integration tests (`shared/tests/test_utils.rs`)
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
    └── → key-service (via HTTP for key bundles, rare)

auth-service
    └── → user-service (internal gRPC for profile lookup during auth)

delivery-worker
    └── Kafka consumer only — no gRPC calls
```

`sentinel-service` has full implementation (`CheckSendPermission`, `ReportSpam`, `GetTrustStatus`)
but **no other service calls it**. It is an architectural island. Should either be wired into
messaging-service's send path or disabled in docker-compose.prod.yml.

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
| `POW_DIFFICULTY` | 10 | Leading-zero bits required in PoW |
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

## Known Issues / Tech Debt

1. **sentinel-service** — implemented but not integrated into any send path (architectural island)
2. **`to_app_context()` adapter** — requires non-optional `apns_client` in `MessagingServiceContext`, preventing full APNs client cleanup from messaging-service. Full fix: make `AppContext::apns_client` optional in `construct-context`.
3. **Duplicate messaging_service code** — `messaging-service/src/` AND `shared/src/construct_server/messaging_service/` must be kept in sync. Any change to `dispatch_envelope` signature needs updating in both places AND in `shared/tests/test_utils.rs`.
4. **delivery_queue:{server_instance_id} keys** — these are still created by server heartbeat but never read by delivery-worker (routing is user-based now). Consider removing the heartbeat registration or repurposing.
5. **DLQ** — now sends to `{topic}-dlq` Kafka topic via `MessageProducer::send_raw_to_topic`. Topic must exist in Redpanda (`messages-dlq`). On Kafka failure falls back to structured `DLQ_MESSAGE` error log.
6. **content-hash dedup (Layer 3)** — `should_skip_message_with_content` hashes ciphertext which always has a random IV, so Layer 3 never fires for E2EE messages. Function exists but is not called from processor.rs.
7. **`run_user_online_notification_listener`** in delivery-worker subscribes to `ONLINE_CHANNEL` but takes no action (Kafka auto-redelivers). Monitoring only.
