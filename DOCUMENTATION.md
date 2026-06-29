# Konstruct Server: Developer Documentation

**Last Updated:** 2026-06-09  
**Status:** Living Document

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Service Map & Entry Points](#service-map--entry-points)
3. [Key Call Chains](#key-call-chains)
4. [Message Delivery Flow](#message-delivery-flow)
5. [Cryptography Reference](#cryptography-reference)
6. [Database Schema](#database-schema)
7. [Testing](#testing)
8. [Debugging](#debugging)
9. [Implementation Status](#implementation-status)

---

## Architecture Overview

Konstruct is an end-to-end encrypted messenger with a fully gRPC-first backend. All client traffic terminates TLS at **Caddy** (edge, Let's Encrypt) which routes to individual microservices by gRPC service path prefix (`h2c` backends). There are no REST endpoints for core functionality — authentication, messaging, and key management are all gRPC.

```
Client
  │
  ▼
Caddy :443   (edge TLS termination, Let's Encrypt; routes by /shared.proto.services.v1.<ServiceName>/*)
  │
  ├─► auth-service       :50051  (AuthService, DeviceService)
  ├─► user-service        :50052  (UserService, InviteService)
  ├─► messaging-service   :50053  (MessagingService, MessageGateway, NotificationService)
  ├─► media-service       :50056  (MediaService)
  ├─► key-service         :50057  (KeyService)
  ├─► group-service       :50058  (MlsService, ChannelService)
  ├─► sentinel-service    :50059  (SentinelService — called by messaging on send)
  ├─► signaling-service   :50060  (SignalingService — WebRTC call signaling)
  ├─► veil-service                (VeilService — obfuscation ticket provisioning)
  ├─► masque-service              (MASQUE-lite QUIC datagram relay)
  └─► gateway             :3000   (HTTP: /health, /.well-known, /federation; veil/obfs4 proxy :9443)
```

**Shared infrastructure:**
- **Redis Streams** — message delivery transport: per-user/per-device offline stream (`delivery:offline:{user_id}[:{device_id}]`); pub/sub wakeup channel (`inbox:wakeup:{user_id}`).
- **PostgreSQL** — device registration, keys, `delivery_pending` (receipt routing hashes only — **message content is never stored in PostgreSQL**)
- **Proto definitions** — `shared/proto/services/*.proto`

---

## Service Map & Entry Points

### Binary entry points

Each service is an independent Rust binary. `main()` in each service:
1. Loads `Config::from_env()` (crate `construct-config`)
2. Creates a DB pool (`construct-db`) and Redis connection
3. Builds a tonic gRPC server and binds to its port

| Service | Binary entry | Default gRPC port | Env var override |
|---------|-------------|-------------------|-----------------|
| auth-service | `auth-service/src/main.rs` | 50051 | `AUTH_GRPC_BIND_ADDRESS` |
| user-service | `user-service/src/main.rs` | 50052 | `USER_GRPC_BIND_ADDRESS` |
| messaging-service | `messaging-service/src/main.rs` | 50053 | `MESSAGING_GRPC_BIND_ADDRESS` |
| media-service | `media-service/src/main.rs` | 50056 | `MEDIA_GRPC_BIND_ADDRESS` |
| key-service | `key-service/src/main.rs` | 50057 | `KEY_GRPC_BIND_ADDRESS` |
| group-service | `group-service/src/main.rs` | 50058 | `PORT` (metrics: `METRICS_PORT` 8097) |
| sentinel-service | `sentinel-service/src/main.rs` | 50059 | *(PORT env var)* |
| signaling-service | `signaling-service/src/main.rs` | 50060 | *(PORT env var)* |
| veil-service | `veil-service/src/main.rs` | (own gRPC port) | — |
| masque-service | `masque-service/src/main.rs` | (UDP/WS relay) | — |
| gateway | `gateway/src/main.rs` | 3000 (HTTP) | `PORT` |

### Required environment variables (all services)

```
DATABASE_URL=postgres://user:pass@localhost:5432/construct_test
REDIS_URL=redis://localhost:6379
```

Additional per-service vars: `JWT_SECRET`, `RS256_PRIVATE_KEY`, `REDIS_URL`, etc.  
See `crates/construct-config/src/lib.rs` for the full list and defaults.

### gRPC services per binary

| Binary | gRPC services exposed |
|--------|----------------------|
| auth-service | `AuthService`, `DeviceService` |
| user-service | `UserService`, `InviteService` |
| messaging-service | `MessagingService`, `MessageGateway`, `NotificationService` |
| media-service | `MediaService` |
| key-service | `KeyService` |
| group-service | `MlsService`, `ChannelService` |
| sentinel-service | `SentinelService` |
| signaling-service | `SignalingService` |
| veil-service | `VeilService` |
| masque-service | MASQUE-lite relay (no gRPC service) |

Proto package: `shared.proto.services.v1`  
Proto sources: `shared/proto/services/`

---

## Key Call Chains

### 1. Device Registration

```
Client → AuthService::RegisterDevice
  └─► auth-service/src/main.rs  (tonic handler dispatch)
      └─► crates/construct-auth-service/src/devices.rs
          pub async fn register_device_v2(...)
            ├─ verify PoW challenge (construct-pow)
            ├─ verify prekey signatures (Ed25519, construct-crypto)
            ├─ INSERT INTO devices (construct-db)
            ├─ INSERT otpks + signed prekey (construct-db)
            └─ issue JWT access + refresh tokens (construct-auth)
```

### 2. Pre-Key Upload (after registration)

```
Client → KeyService::UploadPreKeys
  └─► key-service/src/main.rs
      └─► key-service/src/core.rs
          pub async fn upload_prekeys(...)
            ├─ verify Ed25519 signatures on each key
            │   formula: sign("KonstruktX3DH-v1" || [0x00, suite_id] || pubkey_bytes)
            ├─ INSERT INTO one_time_prekeys (suite 0x01 = X25519 OTPKs)
            └─ INSERT kyber prekeys (suite 0x10 = ML-KEM-768+X25519 hybrid)
```

### 3. Fetch Pre-Key Bundle (X3DH initiation)

```
Client → KeyService::GetPreKeyBundle
  └─► key-service/src/core.rs
      pub async fn get_prekey_bundle(...)
        ├─ SELECT identity_key, signed_prekey, spk_signature FROM devices
        ├─ SELECT + DELETE one one_time_prekey (soft-delete via deleted_at)
        └─ return KeyBundle proto
```

### 4. Send Message

```
Client → MessagingService::SendMessage
  └─► messaging-service/src/grpc.rs
      async fn send_message(...)
        ├─ extract message_id from envelope.message_id (echo back to client)
        ├─ idempotency check: SETNX Redis key
        └─► messaging-service/src/core.rs
            pub async fn dispatch_envelope(...)
              ├─ check recipient domain (local vs federated)
              ├─ write directly to Redis Stream (XADD delivery:offline:{user}[:{device}] + PUBLISH wakeup)
              └─ store receipt routing hash in delivery_pending (PostgreSQL, async, non-critical)
                  NOTE: message content is NEVER written to PostgreSQL
```

**message_id contract:** The server echoes back the client's `envelope.message_id`.  
Priority: `envelope.message_id` → `idempotency_key` → server-generated UUID.

### 5. Message Stream (receive messages)

```
Client → MessagingService::MessageStream
  └─► messaging-service/src/grpc.rs
      async fn message_stream(...)
        └─► messaging-service/src/stream.rs
            pub(crate) async fn poll_messages(...)
              ├─ read_user_messages_from_stream → XREAD delivery:offline:{user_id} (no delete)
              ├─► messaging-service/src/envelope.rs
              │   pub(crate) fn convert_kafka_envelope_to_proto(...)
              └─► spawn_inbox_wakeup(...)  (subscribes Redis pub/sub for real-time push)
                  channel: inbox:wakeup:{user_id}

  Subscribe(since_cursor) → handle_stream_request → MessageQueue::trim_offline_stream
    (deletes ≤ since_cursor only — the client's durable ACK; see Offline delivery)
```

### 6. Delivery Receipt

```
Recipient sends receipt → MessagingService::SendMessage (CONTENT_TYPE_DELIVERY_RECEIPT)
  └─► messaging-service/src/receipts.rs
      pub(crate) async fn relay_delivery_receipt(...)
        ├─ compute routing hash (recipient → original sender)
        ├─ XADD delivery:offline:{sender_user_id}  (receipt rides the sender's own stream)
        └─ original sender's stream picks it up → green checkmark
```

### 7. Sealed Sender Dispatch

```
Client sends SealedSenderEnvelope
  └─► messaging-service/src/envelope.rs
      pub(crate) async fn dispatch_sealed_sender(...)
        ├─ [local recipient] → dispatch_envelope (same server)
        └─ [remote recipient] → crates/construct-federation
            forward sealed_inner opaquely to recipient's home server
```

---

## Message Delivery Flow

```
Alice (sender)                  Server                         Bob (recipient)
─────────────                ─────────────                   ──────────────────
SendMessage RPC ──────────► grpc.rs::send_message
                                  │
                             dispatch_envelope
                                  │
                     writes directly to Redis:
                     XADD delivery:offline:{bob_user}
                     XADD delivery:offline:{bob_user}:{device}
                               │
                     PUBLISH inbox:wakeup:{bob_user}
                               │
                    └──────────────────────────────────► stream.rs::poll_messages
                                                              │
                                                    read_user_messages_from_stream
                                                    (XREAD delivery:offline:{bob_user})
                                                              │
                                                    convert_kafka_envelope_to_proto
                                                              │
                                                    stream.send(Envelope) ──────► Bob client
                                                                                       │
                                                        relay_delivery_receipt ◄───────┘
                                                              │
                                                    XADD delivery:offline:{alice_user}
                                                              │
                                          Alice stream receives receipt ──────► ✅ delivered
```

**Offline delivery (ACK-driven).** If Bob is offline, messages accumulate in his Redis
stream `delivery:offline:{user_id}` (7-day TTL). On reconnect his client subscribes with
`since_cursor` — the Redis stream ID of the last message it *durably persisted*. The server:

1. reads **forward** from that cursor and streams the backlog to the client
   (`read_user_messages_from_stream` — side-effect-free, no deletion);
2. deletes (`XTRIM MINID ack+1`) only messages **≤ `since_cursor`** — i.e. only what the
   client has acknowledged — in `MessageQueue::trim_offline_stream`, invoked from the
   `Subscribe` handler in `stream.rs`.

Deletion is driven by the client's durable acknowledgement, **never** by the server's send
position. A short or broken session re-delivers (the client dedups by `message_id`) but never
loses an un-acknowledged message. The 7-day TTL and `trim_streams_by_age` are the backstop for
streams that are never acknowledged.

> **History:** before 2026-06, `read_stream_messages` trimmed the stream by the server's *read
> position* on every poll. A message buffered into the gRPC channel but not yet received by a
> short-lived client was deleted on the next poll → silent loss. The trim is now ACK-driven.

---

## Cryptography Reference

### Crypto Suites

| Suite ID | Name | Keys | Status |
|----------|------|------|--------|
| `0x01` | ClassicX25519 | Ed25519 identity + X25519 prekeys | ✅ Active |
| `0x10` | HybridKyber1024X25519 | Ed25519 identity + ML-KEM-768⊕X25519 prekeys | ✅ Active |

Clients negotiate the suite during registration. Hybrid PQC (`0x10`) is available and used when both parties support it.

### Prekey Signature Scheme

All prekeys (SPK, OTPKs) are signed with the device's Ed25519 signing key:

```
signature = Ed25519.sign(
    device_signing_key,
    "KonstruktX3DH-v1" || [0x00, suite_id] || public_key_bytes
)
```

- Suite `0x01` = Classical X25519 SPK
- Suite `0x10` = Hybrid ML-KEM-768+X25519

Verification uses `ed25519-dalek v2.1` (RFC 8032 strict mode).

### X3DH Key Agreement (client-side)

```
Alice initiates with Bob's key bundle:

DH1 = ECDH(IK_A_priv,  SPK_B_pub)
DH2 = ECDH(EK_A_priv,  IK_B_pub)
DH3 = ECDH(EK_A_priv,  SPK_B_pub)
DH4 = ECDH(EK_A_priv,  OPK_B_pub)  // if one-time prekey available

SK = HKDF-SHA256(salt=0xFF×32, ikm=DH1||DH2||DH3||DH4, info="ConstructX3DH")
```

### JWT / Auth

- Access tokens: RS256, TTL 168 hours (1 week)
- Refresh tokens: RS256, TTL 90 days
- Claims: `{ sub: user_id, device_id, iss: "construct-server" }`

### Sender Certificate (sealed sender)

Issued by `AuthService::GetSenderCertificate`:
- Ed25519 signed, 24-hour TTL
- Contains: sender user_id, device_id, expiry
- Used for cross-server anonymous message routing

---

## Database Schema

Migrations live in `shared/migrations/`. Current latest: `030_restore_key_updated_at.sql`.

Key tables:

| Table | Purpose |
|-------|---------|
| `devices` | Device records: `user_id`, `identity_key`, `signed_prekey`, `verifying_key`, push tokens |
| `one_time_prekeys` | X25519 OTPKs; soft-deleted (`deleted_at`) on consumption |
| `kyber_prekeys` | ML-KEM-768 OTPKs; same soft-delete pattern |
| `delivery_pending` | Receipt routing: `message_hash → sender_id` (30-day TTL). **Not message storage** — only used to route delivery receipts back to the original sender. |
| `media_files` | Upload metadata (actual bytes on CDN/local storage) |
| `user_blocks` | Block list entries |
| `invites` | Invite tokens (used for invite-only onboarding) |
| `mls_groups` | MLS group state (stub) |

> **Message content is never stored in PostgreSQL.** Messages travel messaging-service → Redis Stream → client. The `delivery_pending` table only stores `HMAC(message_id, salt) → sender_id` to enable receipt routing.

Run migrations:
```bash
DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test \
  sqlx migrate run --source shared/migrations
```

---

## Testing

### Start local dependencies

```bash
docker compose -f ops/docker-compose.dev.yml up -d
# Starts: PostgreSQL :5432, Redis :6379
```

### Run unit tests (no DB required)

```bash
cargo test --lib                            # all unit tests
cargo test -p messaging-service             # single service (11 tests)
cargo test -p construct-auth-service        # auth crate unit tests
cargo test -p construct-key-management      # key management unit tests
```

### Run integration tests (require DB + Redis)

```bash
export DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test
export REDIS_URL=redis://localhost:6379

cargo test -p construct-server-shared                         # all shared integration tests
cargo test -p construct-server-shared --test delivery_ack_test
cargo test -p construct-server-shared --test e2e_crypto_test
```

Most integration tests are gated with `#[ignore]` and skipped in CI unless the full stack is up:
```bash
cargo test -p construct-server-shared -- --ignored   # run skipped integration tests
```

### Pre-deploy check

```bash
./scripts/pre_deploy_check.sh
# Runs: cargo check, cargo test --lib
```

### cargo check / clippy

```bash
cargo check --workspace
cargo clippy --workspace -- -D warnings
```

A `pre-commit` hook runs `cargo fmt` automatically. If it fails, run:
```bash
cargo fmt --all
```

---

## Debugging

### Run a single service locally

```bash
DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test \
REDIS_URL=redis://localhost:6379 \
RUST_LOG=debug \
cargo run -p auth-service
```

### Inspect gRPC services with grpcurl

```bash
# List all services on a port
grpcurl -plaintext localhost:50051 list

# List methods of a service
grpcurl -plaintext localhost:50051 list shared.proto.services.v1.AuthService

# Get a PoW challenge
grpcurl -plaintext localhost:50051 \
  shared.proto.services.v1.AuthService/GetPowChallenge '{}'

# Get pre-key bundle for a user (requires JWT)
grpcurl -plaintext \
  -H 'authorization: Bearer <jwt>' \
  -d '{"user_id": "<uuid>"}' \
  localhost:50057 \
  shared.proto.services.v1.KeyService/GetPreKeyBundle
```

### Inspect Redis delivery queues

```bash
redis-cli

# List active offline streams
KEYS delivery:offline:*

# Read messages from a stream
XRANGE delivery:offline:<user_id> - +

# Watch for wakeup signals
SUBSCRIBE inbox:wakeup:<user_id>

# Receipts ride the sender's own offline stream (no separate receipt: key)
XRANGE delivery:offline:<sender_user_id> - +
```

### Inspect PostgreSQL

```bash
psql postgres://postgres:password@localhost:5432/construct_test

-- Active devices
SELECT device_id, user_id, created_at FROM devices ORDER BY created_at DESC LIMIT 10;

-- Receipt routing table (NOT message storage)
SELECT message_hash, sender_id, expires_at FROM delivery_pending ORDER BY expires_at DESC LIMIT 20;

-- One-time prekey counts per device
SELECT device_id, COUNT(*) as available
FROM one_time_prekeys
WHERE deleted_at IS NULL
GROUP BY device_id;

-- Kyber prekey counts
SELECT device_id, COUNT(*) as available
FROM kyber_prekeys
WHERE deleted_at IS NULL
GROUP BY device_id;
```

### Inspect Caddy routing (production/Docker)

```bash
# Caddy admin API (bound to 127.0.0.1:2019)
curl http://localhost:2019/config/ | jq .
docker logs construct-caddy --tail 50
```

### Trace a message end-to-end

1. **Send** — add `RUST_LOG=debug` to messaging-service, watch `dispatch_envelope` logs
2. **Redis** — `XRANGE delivery:offline:<recipient_user_id> - +` confirms delivery to stream (also `delivery:offline:<user>:<device>` per-device)
3. **Wakeup** — `SUBSCRIBE inbox:wakeup:<recipient_user_id>` confirms the real-time wakeup fired
4. **Receipt** — `XRANGE delivery:offline:<sender_user_id> - +` confirms the delivery receipt arrived

> Messages are **never** in PostgreSQL. If a message is missing, check the Redis Stream.

---

## Implementation Status

### ✅ Fully implemented

**Transport & Auth:**
- gRPC-only architecture (REST removed from all core paths)
- Caddy edge routing by proto path prefix (h2c backends, Let's Encrypt TLS)
- Passwordless device auth (Ed25519 + JWT RS256)
- Proof-of-Work anti-spam on registration
- Invite-code-only onboarding

**Key Management:**
- X3DH key bundles (identity key, signed prekey, OTPKs)
- Ed25519 prekey signatures (scheme: `KonstruktX3DH-v1` prefix)
- One-time prekey soft-delete (consumed atomically)
- Kyber (ML-KEM-768) hybrid prekeys (suite 0x10)
- SPK rotation with age tracking

**Messaging:**
- SendMessage, MessageStream, GetPendingMessages RPCs
- message_id echo-back (client ID preserved end-to-end)
- Idempotency via Redis SETNX
- Offline delivery (Redis stream `delivery:offline:{user_id}`, **ACK-driven** trim, 7-day TTL)
- Delivery receipts routed back to sender
- EditMessage RPC

**Notifications:**
- APNs push notifications for iOS
- FCM for Android (stub)

**Media:**
- Upload/download via MediaService gRPC
- Local file storage + CDN-ready design

**Federation:**
- `.well-known/konstruct` server discovery
- `gateway/src/routes/federation.rs` — server-to-server key bundle proxy

### ⚠️ Stub / partial

- MLS group messaging (`group-service` — RFC 9420, partial)
- Broadcast channels (`group-service`)
- WebRTC call signaling (`signaling-service`)
- MASQUE-lite QUIC relay (`masque-service` — transport / DPI resistance)
- Sentinel service (rate-limit sentinel — partial)
- Multi-device message fan-out (single device delivery only)

### ❌ Not started

- Device linking (QR-based secondary device add)
- Cross-server sealed sender routing
- TCP relay / DPI resistance
- gRPC-over-WebSocket (Cloudflare ECH)

---

**Maintainer:** Konstruct Team  
**License:** MIT (see LICENSE)
