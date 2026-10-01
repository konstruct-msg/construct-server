# Konstruct Server: Developer Documentation

**Last Updated:** 2026-10-01  
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
  ├─► identity-service    :50051  (AuthService, DeviceService, DeviceLinkService,
  │                                 UserService, InviteService — merged)
  ├─► messaging-service   :50053  (MessagingService, NotificationService,
  │                                 SentinelService — merged; HTTP :8083 federation S2S)
  ├─► media-service       :50056  (MediaService, StickerService)
  ├─► veil-service        :50056  (VeilService — separate deployment)
  ├─► key-service         :50057  (KeyService)
  ├─► group-service       :50058  (MlsService, ChannelService)
  ├─► signaling-service   :50060  (SignalingService — WebRTC call signaling)
  └─► gateway             :3000   (HTTP: /health, /.well-known incl. the federation key; veil/obfs4 proxy :9443)

Non-gRPC services (not routed through Caddy):
  └─► masque-service      :9200   (WebSocket MASQUE-lite QUIC datagram relay)
```

**Shared infrastructure:**
- **Redis Streams** — message delivery transport: per-user/per-device offline stream (`delivery:offline:{user_id}[:{device_id}]`); pub/sub wakeup channel (`inbox:wakeup:{user_id}`).
- **PostgreSQL** — users, devices, keys, `delivery_pending` (receipt routing hashes only). **1:1 message content is never stored in PostgreSQL**; MLS group messages (`mls_ciphertext`) and channel posts (`channel_posts.ciphertext`) are, as ciphertext
- **Proto definitions** — `shared/proto/services/*.proto` (13 service protos), `shared/proto/core/`, `shared/proto/messaging/`, `shared/proto/signaling/`

---

## Service Map & Entry Points

### Binary entry points

Each service is an independent Rust binary. `main()` in each service:
1. Loads `Config::from_env_for(SecretNeeds::<SERVICE>)` (crate `construct-config`) — only the secrets that service uses are required
2. Creates a DB pool (`construct-db`) and Redis connection
3. Builds a tonic gRPC server and binds to its port

| Service | Binary entry | Default gRPC port | Env var override |
|---------|-------------|-------------------|-----------------|
| identity-service | `identity-service/src/main.rs` | 50051 | `IDENTITY_GRPC_BIND_ADDRESS` |
| messaging-service | `messaging-service/src/main.rs` | 50053 | `MESSAGING_GRPC_BIND_ADDRESS` |
| media-service | `media-service/src/main.rs` | 50056 | `MEDIA_GRPC_BIND_ADDRESS` |
| veil-service | `veil-service/src/main.rs` | 50056 | `VEIL_GRPC_BIND_ADDRESS` |
| key-service | `key-service/src/main.rs` | 50057 | `KEY_SERVICE_GRPC_ADDR` |
| group-service | `group-service/src/main.rs` | 50058 | `PORT` (metrics: `METRICS_PORT` 8097) |
| signaling-service | `signaling-service/src/main.rs` | 50060 | *(PORT env var)* |
| masque-service | `masque-service/src/main.rs` | — (WS :9200) | `MASQUE_LISTEN_ADDR` |
| gateway | `gateway/src/main.rs` | — (HTTP; code default 8080, compose sets 3000) | `PORT` |

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
| identity-service | `AuthService`, `DeviceService`, `DeviceLinkService`, `UserService`, `InviteService` |
| messaging-service | `MessagingService`, `NotificationService`, `SentinelService` (plus HTTP :8083 for `/federation/v1/*`) |
| media-service | `MediaService`, `StickerService` (public, unauthenticated) |
| key-service | `KeyService` |
| group-service | `MlsService`, `ChannelService` |
| signaling-service | `SignalingService` |
| veil-service | `VeilService` |
| masque-service | none (WebSocket relay) |
| gateway | none (HTTP proxy) |

Proto package: `shared.proto.services.v1`  
Proto sources: `shared/proto/services/`

---

## Key Call Chains

### 1. Device Registration

```
Client → AuthService::RegisterDevice
  └─► identity-service/src/main.rs  (tonic handler dispatch)
      └─► crates/construct-auth-service/src/core.rs  register_device (pass-through)
          └─► crates/construct-auth-service/src/devices.rs
              register_device_core(...)
                ├─ verify the signed prekey's Ed25519 signature (construct-crypto)
                ├─ device-exists check
                ├─ verify PoW challenge
                ├─ create_user_with_first_device: INSERT users + devices
                │    (the device row carries the signed prekey; no OTPKs here —
                │     they arrive through KeyService::UploadPreKeys)
                └─ issue access + refresh tokens (PASETO v4.public, construct-auth)
```

### 2. Pre-Key Upload (after registration)

```
Client → KeyService::UploadPreKeys
  └─► key-service/src/main.rs
      └─► key-service/src/core.rs
          pub async fn upload_prekeys(...)
            ├─ INSERT INTO one_time_prekeys (X25519 OTPKs — unsigned, as in X3DH)
            └─ Kyber prekeys (ML-KEM-1024, PQXDH v2), each checked before it is stored:
                 check_kyber_prekey_v2        — size + Ed25519 over the v2 message
                 check_kyber_prekey_hybrid_v2 — Ed25519 + ML-DSA-65 hybrid signature
               → kyber_one_time_pre_keys (one-time) / devices.kyber_signed_pre_key (signed)
```

### 3. Fetch Pre-Key Bundle (X3DH initiation)

```
Client → KeyService::GetPreKeyBundle
  └─► key-service/src/core.rs
      pub async fn get_prekey_bundle(...)
        ├─ SELECT identity_key, signed_prekey, spk_signature FROM devices
        ├─ DELETE … RETURNING one one_time_prekey (hard delete — consumed once)
        └─ return KeyBundle proto
```

### 4. Send Message

```
Client → MessagingService::SendMessage
  └─► messaging-service/src/grpc.rs
      async fn send_message(...)
        ├─ extract message_id from envelope.message_id (echo back to client)
        ├─ idempotency check: EXISTS msg:dedup:{message_id} (set with SET EX 24h only
        │    after the mailbox XADD — check-then-set, not SETNX)
        └─► messaging-service/src/core.rs
            pub async fn dispatch_envelope(...)   (local only — federation is the sealed path, §7)
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
              ├─ read_mailbox_messages (dual-read when token has device_id:
              │     device stream + user stream, dedupe by message_id, prefer device,
              │     skip user-stream entries named to another device;
              │     legacy tokens without device_id → user stream only; no delete)
              ├─► messaging-service/src/envelope.rs
               │   pub(crate) fn convert_envelope_to_proto(...)
              └─► spawn_inbox_wakeup(...)  (subscribes Redis pub/sub for real-time push)
                  channel: inbox:wakeup:{user_id}

  Subscribe(since_cursor) → handle_stream_request → apply_since_cursor (read offset only;
    no XTRIM — see Offline delivery / minimal-server-delivery)
```

### 6. Delivery Receipt

```
Recipient sends receipt → MessagingService::SendMessage (CONTENT_TYPE_DELIVERY_RECEIPT)
  └─► messaging-service/src/receipts.rs
      pub(crate) async fn relay_delivery_receipt(...)
        ├─ find the original sender: DirectReceipt.recipient_user_id when the client
        │    filled it (fast path); otherwise the routing hash → Redis cache →
        │    delivery_pending (legacy path)
        ├─ XADD delivery:offline:{sender_user_id}  (receipt rides the sender's own stream)
        └─ original sender's stream picks it up → green checkmark
```

### 7. Sealed Sender Dispatch (+ Privacy Pass)

```
Client sends SealedSenderEnvelope
  └─► messaging-service/src/envelope.rs
      pub(crate) async fn dispatch_sealed_sender(...)
        ├─ [recipient_server ≠ ours] → crates/construct-federation: forward
        │    sealed_inner opaquely to the recipient's home server. Nothing below runs
        │    on this branch — the home server checks it
        ├─ decode SealedInner; resolve the recipient (an `ed25519:<hex>` key address
        │    → route_id → UUID via get_user_by_route_id)
        ├─ intake credential check (intake.rs) — contact traffic vouched by the
        │    recipient may owe no token (construct-docs
        │    decisions/contact-traffic-is-vouched-not-purchased.md)
        ├─ Privacy Pass token redemption (token_redeem.rs), when a token is owed
        │    policy: MSG_STEALTH_TOKEN_POLICY = off | warn | enforce
        │    - unseal (X25519 to server key) → verify VOPRF (TOKEN_ISSUER_KEY)
        │    - double-spend: SET spent:{sha256(nonce)} NX EX 30d
        │    - enforce rejection → FAILED_PRECONDITION "privacy_pass:{label}"
        │      (labels: missing_token/invalid_token/double_spent/decrypt_failed/
        │       redis_error/not_configured; client retries once, never de-anonymizes)
        ├─ delivery_tag replay guard (spent_tag.rs — sealed:exact/sealed:seen Redis keys)
        └─ local delivery → mailbox
```

Token issuance lives in **identity-service** (`IssueTokens`, authed): hourly cap
`TOKEN_ISSUANCE_MAX_PER_HOUR` (120), young accounts (< `TOKEN_ISSUANCE_MATURITY_HOURS`,
24 h) get `TOKEN_ISSUANCE_YOUNG_MAX_PER_HOUR` (30). The token *encryption* key (X25519)
is delivered in `GetSenderCertificateResponse.token_encryption_key`.
Ops runbook: construct-docs `deployment/stealth-token-keys-runbook.md`.

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
                                                    read_mailbox_messages (dual-read:
                                                    device + user when device_id present)
                                                              │
                                                     convert_envelope_to_proto
                                                              │
                                                    stream.send(Envelope) ──────► Bob client
                                                                                       │
                                                        relay_delivery_receipt ◄───────┘
                                                              │
                                                    XADD delivery:offline:{alice_user}
                                                    (+ per-device fan-out)
                                                              │
                                          Alice stream receives receipt ──────► ✅ delivered
```

**Offline delivery (retention-bounded, cursor = read offset).** If Bob is offline, messages
accumulate in Redis `delivery:offline:{user_id}` (and per-device fan-out keys). On reconnect
his client subscribes with `since_cursor` — the Redis stream ID of the last message it
*durably persisted*. The server:

1. reads **forward** from that cursor (`read_mailbox_messages` — side-effect-free dual-read);
   the user stream is read from `StreamCatchupState::user_stream_id` when that is ahead —
   a server-side position that moves past entries the reader examined and skipped (a
   sibling device's), never told to the client;
2. does **not** delete from the client cursor. Client-asserted `XTRIM` caused silent loss
   (paging/cancel races; multi-device shared mailbox). See construct-docs
   `decisions/minimal-server-delivery.md` (Accepted).

Capacity backstops: `MAXLEN ~` on XADD (`MSG_QUEUE_MAXLEN_STANDARD`, default 10_000) and hourly age sweep
(~30 days — not the stale “7-day TTL” wording). A short session re-delivers; the client
dedups by `message_id`. Worst case is redelivery, not unrecoverable drop from a bad cursor.

**Step 4 cutover:** `MSG_MAILBOX_USER_WRITE` (default `1`) still writes the legacy user
stream alongside per-device. Flip to `0` only after
`construct_msg_mailbox_user_only_entries_total` is flat zero for 7 days (see AGENTS.md /
minimal-server-delivery). Rollback = set the flag back to `1`.

**Wake push:** `dispatch_envelope` sends APNs silent `new_message` only when the recipient
has **no** active MessageStream (`user:{id}:server_instance_id` absent). Online recipients
are woken via Redis `inbox:wakeup` only — silent push while online caused client reconnect
storms and full offline-stream redelivery.

> **History:** before 2026-06, `read_stream_messages` trimmed by the server's *read position*
> → silent loss on short sessions. 2026-08 briefly used client `since_cursor` as ACK-trim
> (Subscribe + GetPendingMessages) — same loss class via paging/cancel and multi-device.
> Retention-only deletion is the accepted model (`minimal-server-delivery`).

---

## Cryptography Reference

### Prekeys

The server stores and serves prekeys; the key agreement itself (PQXDH v2) is client-side
and specified in the protocol book, not here.

| Key | Algorithm | Signed? | Where |
|-----|-----------|---------|-------|
| Signed prekey | X25519 | Ed25519, suite byte `0x01` | `devices.signed_prekey` |
| One-time prekeys | X25519 | no (as in X3DH) | `one_time_prekeys` |
| Signed Kyber prekey | ML-KEM-1024 (1568-byte public key) | Ed25519 v2 + hybrid Ed25519/ML-DSA-65 | `devices.kyber_signed_pre_key` |
| One-time Kyber prekeys | ML-KEM-1024 | Ed25519 v2 + hybrid Ed25519/ML-DSA-65 | `kyber_one_time_pre_keys` |

ML-KEM-768 Kyber keys were dropped by migration 071; a key of any other size is refused.

### Prekey Signature Scheme

```
classic SPK:  Ed25519.sign(device_signing_key,
                  "KonstruktX3DH-v1" || [0x00, 0x01] || public_key)

Kyber (v2):   Ed25519.sign(device_signing_key,
                  "KonstruktX3DH-v1" || [0x00, 0x11] || created_at (u64 BE) || public_key)
              + a hybrid Ed25519 + ML-DSA-65 signature under the device's hybrid identity key
```

Suite byte `0x10` (the v1 Kyber message, no `created_at`) is no longer accepted, so an old
key cannot pass as a new one (`crates/construct-crypto/src/pqc/hybrid.rs`).

Verification is `ed25519-dalek` 2.2 `Verifier::verify` — not `verify_strict`, so weak
(small-order) public keys are not rejected by this check.

### Auth Tokens (PASETO + legacy JWT)

- Format: **PASETO v4.public** (Ed25519) primary; legacy RS256 JWT still verified —
  `construct-auth` dispatches by the `v4.public.` prefix.
- PASETO payload framing is non-standard: `nonce(32) || message || sig(64)` even for the
  signed purpose (documented; client-side slice offsets are intentional).
- Access tokens: TTL 24 hours (env `ACCESS_TOKEN_TTL_HOURS`, reduced to limit token exposure window)
- Refresh tokens: TTL 90 days
- Claims: `{ sub: user_id, device_id, iss: "construct-server" }`
- Revocation blocklist: `invalidated_token:{jti}` in Redis (checked on verify and in
  messaging's Bearer path, fail-closed)

### Sender Certificate (sealed sender)

Issued by `AuthService::GetSenderCertificate` (via identity-service):
- Ed25519 signed, 24-hour TTL
- Contains: sender user_id, device_id, identity_key, domain, expiry, server signature
- Used for cross-server anonymous message routing

---

## Database Schema

Migrations live in `shared/migrations/`. Current latest: `071_pqxdh_v2_kyber_1024.sql`.

Key tables:

| Table | Purpose |
|-------|---------|
| `users` | User records: `id`, `username_hash`, `identity_public_key`, `identity_key_type`, `route_id`, recovery keys |
| `devices` | Device records: `user_id`, `identity_public`, `signed_prekey`, `verifying_key`, `crypto_suites`, `supports_pq_ratchet`, `kyber_signed_pre_key*` |
| `device_tokens` | Push notification tokens (APNs/FCM), per-device |
| `one_time_prekeys` | X25519 OTPKs; hard-deleted when a bundle consumes one; `is_expired` / `expired_at` mark keys superseded by a `replace_existing` upload |
| `kyber_one_time_pre_keys` | ML-KEM-1024 one-time prekeys, with `created_at` and `hybrid_signature` |
| `delivery_pending` | Receipt routing: `message_hash → sender_id` (30-day TTL). **Not message storage** — only used to route delivery receipts back to the original sender. |
| `media_files` | Upload metadata (actual bytes on CDN/local storage) |
| `sticker_blobs` / `sticker_packs` | Public sticker packs, content-addressed (sha256 / pack_id), **no TTL** — a pack must resolve for as long as any message references it. Migration 070. |
| `user_blocks` | Block list entries |
| `invites` | Invite tokens (used for invite-only onboarding) |
| `contact_requests` | Contact request state |
| `mls_groups` | MLS group state; group application messages are stored as `mls_ciphertext` |
| `channels` / `channel_posts` | Broadcast channels; posts stored as `ciphertext` |

> **1:1 message content is never stored in PostgreSQL.** Those messages travel messaging-service → Redis Stream → client. Group (MLS) messages and channel posts are the exception: stored as ciphertext in group-service's tables. The `delivery_pending` table only stores `HMAC(message_id, salt) → sender_id` to enable receipt routing.

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
cargo test -p messaging-service             # single service
cargo test -p construct-auth-service        # auth crate unit tests
cargo test -p identity-service              # identity service unit tests
cargo test -p construct-sentinel-service    # sentinel crate unit tests
```

### Run integration tests (require DB + Redis)

```bash
export DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test
export REDIS_URL=redis://localhost:6379

cargo test -p construct-server-shared                         # all shared integration tests
cargo test -p construct-server-shared --test e2e_crypto_test
```

Most integration tests are gated with `#[ignore]` and skipped in CI unless the full stack is up:
```bash
cargo test -p construct-server-shared -- --ignored   # run skipped integration tests
```

### cargo check / clippy

```bash
cargo check --workspace
cargo clippy --all-targets --all-features -- -D warnings
```

The `pre-push` hook (`.githooks/pre-push`, enabled by `git config core.hooksPath .githooks`)
checks `cargo fmt --all -- --check`, the clippy line above, `scripts/check-observability.py`,
`scripts/check-redis-timeouts.sh` and the front-coordinates guard. It does not reformat;
run `cargo fmt --all` and push again. There is no pre-commit hook.

---

## Debugging

### Run a single service locally

```bash
DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test \
REDIS_URL=redis://localhost:6379 \
RUST_LOG=debug \
cargo run -p identity-service
```

### Inspect gRPC services with grpcurl

```bash
# List all services on identity-service (merged auth + user + invite)
grpcurl -plaintext localhost:50051 list

# List all services on messaging (includes sentinel + notification)
grpcurl -plaintext localhost:50053 list

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
WHERE is_expired = false
GROUP BY device_id;

-- Kyber one-time prekey counts
SELECT device_id, COUNT(*) as available
FROM kyber_one_time_pre_keys
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

> 1:1 messages are **never** in PostgreSQL. If one is missing, check the Redis Stream.

---

## Implementation Status

### ✅ Fully implemented

**Transport & Auth:**
- gRPC-first architecture (HTTP only for health, metrics, discovery, federation S2S)
- Caddy edge routing by proto path prefix (h2c backends, Let's Encrypt TLS)
- Identity service merge: `AuthService`, `DeviceService`, `DeviceLinkService`, `UserService`, `InviteService` in one binary
- Passwordless device auth (Ed25519 device key; PASETO v4.public tokens, legacy RS256 JWT still verified)
- Proof-of-Work anti-spam on registration
- Invite-code-only onboarding
- Device linking via join request flow
- Privacy Pass token issuance (Ristretto255)
- Account recovery (recovery key verification + social recovery bundle)

**Key Management:**
- X3DH key bundles (identity key, signed prekey, OTPKs)
- Ed25519 prekey signatures (scheme: `KonstruktX3DH-v1` prologue)
- One-time prekeys consumed atomically (`DELETE … FOR UPDATE SKIP LOCKED`)
- ML-KEM-1024 Kyber prekeys, signed and one-time (PQXDH v2; Ed25519 + hybrid ML-DSA-65 signatures)
- SPK rotation with age tracking

**Messaging:**
- SendMessage, MessageStream, GetPendingMessages RPCs
- message_id echo-back (client ID preserved end-to-end)
- Idempotency via Redis `msg:dedup:{message_id}` (24 h, set after the mailbox write)
- Offline delivery (Redis stream `delivery:offline:{user_id}[:{device_id}]`; `since_cursor` = read offset only — **no client XTRIM**; retention via `MAXLEN ~` + age sweep ~30d)
- Dual-read mailbox (device + user merge when token has `device_id`; cutover flag `MSG_MAILBOX_USER_WRITE`)
- Delivery receipts routed back to sender
- EditMessage RPC
- **Multi-device fan-out** (per-device streams `delivery:offline:{user_id}:{device_id}`)
- **Sentinel in-process** (anti-spam, same binary, no gRPC hop)
- **NotificationService + APNs push** (merged into messaging-service, direct APNs call)

**Media:**
- Upload/download via MediaService gRPC
- Local file storage + CDN-ready design
- Storage persists on named volume `media-data` (`MEDIA_STORAGE_DIR=/data/media`) —
  before 2026-07-16 it was ephemeral in-container and lost on redeploy
- Retention: 7 days from upload (`MEDIA_FILE_TTL_SECONDS`; downloads do not extend)

**Stickers (media-service, `StickerService`):**
- Public, unauthenticated, per-IP window (`STICKER_RATE_LIMIT_PER_HOUR`, default 600)
- Content-addressed: `pack_id = sha256(manifest canonical bytes)`, blob key = sha256(bytes);
  the client verifies the Ed25519 signature (`BUNDLE_SIGNING_KEY`'s public half) and every hash
- Not the media store: tables `sticker_blobs` / `sticker_packs`, no TTL, no reaper
- Publish: `sticker-publish` (in the image, `media-service/src/bin`) signs a pack built by
  `construct-messenger/scripts/build_sticker_pack.py` and inserts it — runbook in the vault,
  `deployment/sticker-publish-runbook.md`; design `backend/STICKER_SERVICE_SPEC.md`

**Sealed sender anti-abuse (stealth):**

Logical-message unit: multi-chunk sealed bodies share `SealedInner.token_spend_id`.
One Privacy Pass token pays for the whole set to one recipient (first envelope
redeems; follow-ups are `unit_covered`, max 256). Unit key is
`pp:unit:{sha256(spend_id||"|"||recipient_user_id)}` so a client-chosen spend_id
cannot fan out to other users. Empty `token_spend_id` keeps legacy per-envelope spend.
- Per-message Privacy Pass tokens (VOPRF, ristretto255): issuance in identity-service
  (hourly + age-tiered caps), redemption in messaging-service
- `MSG_STEALTH_TOKEN_POLICY` off/warn/enforce; typed enforce rejection
  `FAILED_PRECONDITION privacy_pass:{label}`
- `delivery_tag` replay guard (Redis `sealed:exact`/`sealed:seen`)

**Push:**
- APNs prod + sandbox clients, routed per-token by `push_environment`
- 403 = provider-auth error (never deletes device tokens); only
  `BadDeviceToken`/`Unregistered` do
- Device-token registration accepts ≤ 512 chars (FCM-ready); FCM send path not yet implemented

**Federation:**
- `.well-known/construct-server` + `jwks.json` server discovery
- S2S sealed sender forwarding (`/federation/v1/sealed`, `/federation/v1/messages`)
- Inbound S2S receiver (signature-verified) implemented — two-VPS end-to-end test pending
  (construct-docs `decisions/decentralization-execution-plan.md`, Epic A)
- `INSTANCE_DOMAIN` is required on all services (no default)

**Cryptographic identity:**
- `identity_public_key` + `identity_key_type` + `RouteId` (SHA-256(type ‖ key))
- Dual addressing in `UserId::parse` (`ed25519:<hex>`); a sealed envelope addressed by key is
  resolved RouteId → UUID on the recipient's server (`dispatch_sealed_sender`)

### Stub / partial

- MLS group messaging (`group-service` — RFC 9420, partial)
- Broadcast channels (`group-service`)
- WebRTC call signaling (`signaling-service`)
- MASQUE-lite WS relay (`masque-service` — transport / DPI resistance; not in `ops/docker-compose.prod.yml`)

---

**Maintainer:** Konstruct Team  
**License:** AGPL-3.0-only (see LICENSE)
