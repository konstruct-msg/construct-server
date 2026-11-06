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
```

**Shared infrastructure:**
- **Redis Streams** — message delivery transport: per-user/per-device offline stream (`delivery:offline:{user_id}[:{device_id}]`); pub/sub wakeup channel (`inbox:wakeup:{user_id}`).
- **PostgreSQL** — users, devices, keys. **1:1 message content is never stored in PostgreSQL**; MLS group messages (`mls_ciphertext`) and channel posts (`channel_posts.ciphertext`) are, as ciphertext
- **Proto definitions** — `shared/proto/services/*.proto` (13 service protos), `shared/proto/core/`, `shared/proto/messaging/`, `shared/proto/signaling/`

---

## Service Map & Entry Points

### Binary entry points

Each service is an independent Rust binary. `main()` in each service:
1. Loads `Config::from_env_for(SecretNeeds::<SERVICE>)` (crate `construct-config`) — only the secrets that service uses are required
   Malformed encoded secrets and literal quotes fail independently of the slice. Optional blank
   values mean unconfigured; required log salt and CSRF reject whitespace-only values.
   Explicitly enabled federation fails boot without its signing key. Identity and
   messaging share `construct_config::load_token_issuer_key` (blank → disabled,
   malformed → error). The contract matrix in `crates/construct-config/src/contract_tests.rs`
   runs each env scenario in a separate process with a cleared environment and empty `.env`.
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
| gateway | `gateway/src/main.rs` | — (HTTP; code default 8080, compose sets 3000) | `PORT` |

### Runtime configuration reference

```
DATABASE_URL=postgres://user:pass@localhost:5432/construct_test
REDIS_URL=redis://localhost:6379
```

These connection values apply where consumed. Requirements follow
`Config::from_env_for(SecretNeeds::<ROLE>)` and the service entry point; gateway,
for example, does not require database/HMAC secrets. Secret names belong to the
per-service allowlist in `ops/secrets-allowlist.ini`; values stay in the operator's
secret store. Never copy secret values into this reference.

The table is the operator index for the retained settings. Named loaders define
parsing and defaults; audit 242 changes none of their live values. Changes to
limits, PoW tiers, retention or cutover policy still require measured evidence.

| Area | Settings and consumer/default authority |
|---|---|
| Service/connection | `INSTANCE_DOMAIN`, `SERVER_HOSTNAME`, `DATABASE_URL`, `REDIS_URL`, `PORT`, `HEALTH_PORT`, `METRICS_PORT`, `SERVICE_NAME`, `RUST_LOG`; service entry points and `crates/construct-config/src/lib.rs`. Domain is required by Config; DB/Redis requirements are per role. |
| Production/secret policy | `ENVIRONMENT`, `PRODUCTION`, `ALLOW_INSECURE_SECRETS`, `FLY_APP_NAME`, `FLY_REGION`, `RAILWAY_ENVIRONMENT`; `crates/construct-config/src/secret_hygiene.rs`. Present malformed active secrets still fail boot. |
| Auth | `PASETO_PRIVATE_KEY`, `PASETO_PUBLIC_KEY`, `PASETO_PUBLIC_KEY_PREVIOUS`, `AUTH_TOKEN_ISSUER` (fallback **`JWT_ISSUER`**), `ACCESS_TOKEN_TTL_HOURS`, `REFRESH_TOKEN_TTL_DAYS`; `construct-config/src/lib.rs` and `construct-auth`. `SESSION_TTL_DAYS` also remains: presence uses it. |
| Privacy identifiers | `USERNAME_HMAC_SECRET`, `CONTACT_HMAC_SECRET`, `REQUEST_ENVELOPE_KEY`, `LOG_HASH_SALT`; `construct-config/src/security.rs`, `logging.rs`, `secret_needs.rs`. Requirements stay unchanged for all six remaining role bits. |
| DB pools | `DB_MAX_CONNECTIONS`, `DB_MIN_CONNECTIONS`, `DB_ACQUIRE_TIMEOUT_SECS`, `DB_IDLE_TIMEOUT_SECS`; `crates/construct-config/src/database.rs` and service entry points. |
| Redis timeouts | Pinned code constants in `crates/construct-redis/src/connect.rs`: response 500 ms, connect 1 s, reconnect cap 2 s. These are not env settings. |
| Presence/mailbox | **`REDIS_KEY_PREFIX_USER`**, **`DELIVERY_QUEUE_PREFIX`**, `DEDUP_SAFETY_MARGIN_HOURS`; config loaders and `construct-queue`. Active namespaces are unchanged. Mailbox age retention remains the code constant, not a newly introduced env knob. |
| gRPC | `GRPC_KEEPALIVE_INTERVAL_SECS`, `GRPC_KEEPALIVE_TIMEOUT_SECS`, plus service-specific bind variables `IDENTITY_GRPC_BIND_ADDRESS`, `MESSAGING_GRPC_BIND_ADDRESS`, `MEDIA_GRPC_BIND_ADDRESS`, `KEY_SERVICE_GRPC_ADDR`, `KEY_SERVICE_HTTP_ADDR`, `VEIL_GRPC_BIND_ADDRESS`; `construct-utils::net` and service entry points. |
| Message trust/send limits | `MSG_TRUST_NEW_MAX_AGE_HOURS`, `MSG_TRUST_WARMING_MAX_AGE_HOURS`, `MSG_HOURLY_LIMIT_NEW`, `MSG_HOURLY_LIMIT_WARMING`, `MSG_HOURLY_LIMIT_TRUSTED`, `MSG_FANOUT_LIMIT_NEW`, `MSG_FANOUT_LIMIT_WARMING`; `construct-config/src/messaging.rs` and `messaging-service/src/trust.rs`. |
| Message streams | `MSG_QUEUE_MAXLEN_STANDARD`, `MSG_STREAM_HEARTBEAT_INTERVAL_SECS`, `MSG_STREAM_POLL_FALLBACK_SECS`, `MSG_STREAM_XREAD_SLOW_MS`; `construct-config/src/messaging.rs`, queue and stream code. |
| Sealed/Privacy Pass | `MSG_STEALTH_TOKEN_POLICY`, `MSG_SEALED_IP_RATE_LIMIT_PER_MIN`, `MSG_REJECT_LEGACY_SEALED_SENDER`, `MSG_MAILBOX_USER_WRITE`, `TOKEN_ISSUER_KEY`, `TOKEN_ISSUER_KEY_VERSION`, `TOKEN_ENCRYPTION_PUBLIC_KEY`, `TOKEN_ISSUANCE_MAX_PER_HOUR`, `TOKEN_ISSUANCE_YOUNG_MAX_PER_HOUR`, `TOKEN_ISSUANCE_MATURITY_HOURS`; messaging/gateway/identity entry points and messaging config. Fresh-token retries and measured mailbox cutover gates remain. |
| Identity abuse limits | `MAX_POW_CHALLENGES_PER_HOUR`, `MAX_REGISTRATIONS_PER_HOUR`, `MAX_FAILED_LOGIN_ATTEMPTS`, `POW_DIFFICULTY`; `construct-config/src/security.rs` and `construct-auth-service/src/devices.rs`. Adaptive policy values are unchanged. |
| Federation/signing | `FEDERATION_ENABLED`, `FEDERATION_BASE_DOMAIN`, `SERVER_SIGNING_KEY`, `FEDERATION_MAX_PER_ORIGIN_PER_HOUR`, `FEDERATION_MTLS_REQUIRED`, `FEDERATION_CLIENT_CERT_PATH`, `FEDERATION_CLIENT_KEY_PATH`, `FEDERATION_VERIFY_SERVER_CERT`, `FEDERATION_PINNED_CERTS`; `construct-config/src/federation.rs`. Outbound mTLS/pinning still needs the island-plan wiring described in audit 241; a loaded setting is not proof it is connected. |
| Server trust | `BUNDLE_SIGNING_KEY`, `BUNDLE_SIGNING_PUBLIC_KEY`, `SERVER_TRUST_DIR`, `SERVER_TRUST_ROOTS`, `SERVER_TRUST_SENDER_CERT_KEY`, `SERVER_TRUST_KT_HEAD_KEY`; `construct-crypto/src/server_trust.rs`, identity/key/sticker entry points. |
| APNs | `APNS_ENABLED`, `APNS_ENVIRONMENT`, `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`, `APNS_TOPIC`, `APNS_VOIP_TOPIC` (fallback `APNS_VOIP_BUNDLE_ID`), `APNS_DEVICE_TOKEN_ENCRYPTION_KEY`; `construct-config/src/federation.rs`, `construct-apns` and in-process notification core. |
| Notification clients | **`NOTIFICATION_SERVICE_URL` remains live** in identity/key/group for contact-accepted, low-prekey and MLS pushes; **`NOTIFICATION_GRPC_ENDPOINT` remains live** in signaling. The old `MicroservicesConfig` wrapper was not their consumer. Actual notification-client circuit breakers are unchanged. |
| MLS/media | `MLS_CLEANUP_INTERVAL_HOURS`; group entry point. `MEDIA_UPLOAD_TOKEN_SECRET` (fallback `MEDIA_HMAC_SECRET`), `MEDIA_STORAGE_DIR`, `MEDIA_MAX_FILE_SIZE`, `MEDIA_FILE_TTL_SECONDS`, `MEDIA_BIND_ADDRESS`, `MEDIA_PUBLIC_HOST`, `MEDIA_RATE_LIMIT_PER_HOUR`, `STICKER_RATE_LIMIT_PER_HOUR`; `media-service/src/config.rs` and main. |
| Signaling | `TURN_SECRET`, `TURN_HOSTS` (fallback `TURN_HOST`), `TURN_CREDENTIALS_TTL_SECONDS`, `RATE_LIMIT_PEER_SALT`, `INSTANCE_ID`, `RATE_LIMIT_CALL_MAX`, `RATE_LIMIT_CALL_WINDOW_SECS`, `RATE_LIMIT_PEER_MAX`, `RATE_LIMIT_PEER_WINDOW_SECS`, `RATE_LIMIT_DECLINE_COOLDOWN_SECS`, `RATE_LIMIT_TURN_MAX`, `RATE_LIMIT_TURN_WINDOW_SECS`; signaling main/turn/rate-limiter code. |
| Sentinel administration | `ADMIN_TOKEN`; the Sentinel gRPC adapter still checks admin request metadata. No admin/auth policy changes in this cleanup. |
| VEIL | `VEIL_ENABLED`, `VEIL_PORT`, `VEIL_SERVER_KEY`, `VEIL_IAT_MODE`, `VEIL_UPSTREAM`, `VEIL_TLS_CERT_PATH`, `VEIL_TLS_KEY_PATH`, `VEIL_COVER_UPSTREAM`, `VEIL_RELAY_ADDRESSES`; gateway/config. `VEIL_RELAYS`, legacy `VEIL_RELAY_ADDRESS`/`VEIL_RELAY_SCOPE`/`VEIL_RELAY_SPKI`/`VEIL_RELAY_SNI`, `VEIL_ISSUER_SEED`, `VEIL_BOOTSTRAP_VOUCHER`, `VEIL_VOUCHER_QUOTA`; veil-service main/core. |
| Logging/deep links | `LOG_MESSAGE_METADATA`, `LOG_USER_IDENTIFIERS`, `LOG_HASH_SALT`; `construct-config/src/logging.rs`. `APPLE_TEAM_ID`, `ANDROID_PACKAGE_NAME`, `ANDROID_CERT_FINGERPRINT`, `DEEP_LINK_BASE_URL`; deep-link loader and entry points. |
| Compatibility config | `PREKEY_TTL_DAYS`, `PREKEY_MIN_TTL_DAYS`, `PREKEY_MAX_TTL_DAYS`, `MAX_MESSAGES_PER_HOUR`, `MAX_MESSAGES_PER_IP_PER_HOUR`, `MAX_KEY_ROTATIONS_PER_DAY`, `MAX_PASSWORD_CHANGES_PER_DAY`, `MAX_CONNECTIONS_PER_USER`, `KEY_BUNDLE_CACHE_HOURS`, `RATE_LIMIT_BLOCK_SECONDS`, `IP_RATE_LIMITING_ENABLED`, `MAX_REQUESTS_PER_IP_PER_HOUR`, `COMBINED_RATE_LIMITING_ENABLED`, `MAX_REQUESTS_PER_USER_IP_PER_HOUR`, `MAX_LONG_POLL_REQUESTS_PER_WINDOW`, `LONG_POLL_RATE_LIMIT_WINDOW_SECS`, `METRICS_AUTH_ENABLED`, `METRICS_IP_WHITELIST`, `METRICS_BEARER_TOKEN`, `HEARTBEAT_INTERVAL_SECS`, `SERVER_REGISTRY_TTL_SECS`, `MEDIA_ENABLED`, `MEDIA_BASE_URL` remain loaded. Legacy `MAX_MESSAGES_PER_HOUR` is advertised by identity, not used for active `MSG_HOURLY_LIMIT_*` enforcement. Loaded compatibility fields do not imply an active limiter, cache, REST route or metrics-auth gate. |

Audit 242 retires **24 unused env readers**: `AUTH_SERVICE_URL`,
`USER_SERVICE_URL`, `MESSAGING_SERVICE_URL`, `MICROSERVICES_ENABLED`,
`SERVICE_DISCOVERY_MODE`, `SERVICE_TIMEOUT_SECS`, the three old
`CIRCUIT_BREAKER_{FAILURE_THRESHOLD,SUCCESS_THRESHOLD,TIMEOUT_SECS}` values,
all six `CSRF_*` values, `REQUEST_SIGNING_REQUIRED`, and eight unused
`REDIS_KEY_PREFIX_*` overrides (all except `REDIS_KEY_PREFIX_USER`). The old
`REDIS_CHANNEL_*` readers were already removed in 240. These retired values no
longer configure a subsystem or impose a boot-secret requirement. Caddy's accepted
header list and generic error variants are retained for compatibility; they do not
constitute a CSRF implementation. The secret-split fixture deliberately contains a
retired CSRF key so filtering still sees obsolete input; production templates and
preflight no longer request it. No production secret file is edited by this change.

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
        ├─ idempotency check: EXISTS msg:dedup:v2:{scope_hash} (set with SET EX 24h only
        │    after the mailbox XADD — check-then-set, not SETNX)
        │    scope = sender account + recipient account + recipient device (or none) + message_id
        └─► messaging-service/src/core.rs
            pub async fn dispatch_envelope(...)   (local only — federation is the sealed path, §7)
              └─ write directly to Redis Stream (XADD delivery:offline:{user}[:{device}] + PUBLISH wakeup)
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

A delivery receipt is an ordinary end-to-end message: the client puts it inside the
ciphertext (KNST content type 14) and sends it like any other, so the server routes it
without knowing it is a receipt or which message it answers.

The server does not relay a plaintext `DirectReceipt` sent on the message stream: one is
dropped unread (`stream.rs`). Until migration 072 it was routed back through a
`message → sender` map kept 30 days in Redis (`receipt:sender:*`) and Postgres
(`delivery_pending`); no client sends that kind any more, and the map is gone.
`receipts.rs` still converts Receipt-type envelopes written before that, so a reader does
not stall on them.

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
                                     Bob's receipt is a message to Alice (E2E, type 14) ┘
                                     and takes the same path back
```

**Offline delivery (retention-bounded, cursor = read offset).** If Bob is offline, messages
accumulate in Redis `delivery:offline:{user_id}` (and per-device fan-out keys). On reconnect
his client subscribes with `since_cursor` — the Redis stream ID of the last message it
*durably persisted*. The server:

1. reads **forward** from that cursor (`read_mailbox_messages` — side-effect-free dual-read);
   the user stream is read from `StreamCatchupState::user_stream_id` when that is ahead —
   a server-side position that moves past entries the reader examined and skipped (a
   sibling device's), never told to the client;
   continues immediately while `MailboxPage::has_more`, even when a page contains only
   sibling entries; checks device revocation before each page and stops on a closed channel;
2. does **not** delete from the client cursor. Client-asserted `XTRIM` caused silent loss
   (paging/cancel races; multi-device shared mailbox). See construct-docs
   `decisions/minimal-server-delivery.md` (Accepted).

Capacity backstops: `MAXLEN ~` on XADD (`MSG_QUEUE_MAXLEN_STANDARD`, default 10_000) and hourly age sweep
(7 days, `MAILBOX_MAX_AGE_DAYS` — the window the clients keep keys for). A short session re-delivers; the client
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

### Auth Tokens (PASETO v4.public only)

- Format: **PASETO v4.public** (Ed25519) only, since 0.20.0. Legacy RS256 JWT issuance and
  verification were removed; `construct-auth` rejects any token without the `v4.public.` prefix.
  Env: `PASETO_PRIVATE_KEY` (issuing service), `PASETO_PUBLIC_KEY`, `PASETO_PUBLIC_KEY_PREVIOUS`
  (rotation overlap), `AUTH_TOKEN_ISSUER` (the `iss` claim; falls back to the pre-0.20.0 `JWT_ISSUER`).
  Metric `construct_auth_token_verify_format_total{format="paseto"}`.
- PASETO payload framing is non-standard: `nonce(32) || message || sig(64)` even for the
  signed purpose (documented; client-side slice offsets are intentional).
- Access tokens: TTL 24 hours (env `ACCESS_TOKEN_TTL_HOURS`, reduced to limit token exposure window)
- Refresh tokens: TTL 90 days
- Claims: `{ sub: user_id, device_id, iss: "construct-server" }`
- Revocation: a verified token is checked against its `devices` row and, where the service has
  Redis, `invalidated_token:{jti}`, before any handler (`shared/src/construct_server/revocation.rs`,
  fail-closed with `UNAVAILABLE`; media and veil have no Redis and read the row only). Messaging
  checks in `extract_authed_identity` against `invalidated_token:{jti}` and `revoked_device:{id}`,
  so that a Postgres outage cannot stop delivery. A `Signal` stream asks again per frame.
- `x-device-id` never names a device: a token without a `device_id` claim has none.

### Account Recovery

- `SetRecoveryKey` and `RecoverAccount` accept only the 1984-byte hybrid public key
  (Ed25519 32 + ML-DSA-65 1952), verified with both signature parts. The old 32-byte
  setup and challenge-only proof were retired on 2026-11-01; their writer/verifier
  and calendar gate are removed. The legacy proto field stays for schema compatibility
  and cannot authorize recovery.
- Historical Ed25519-only account rows remain supported: a valid hybrid setup or
  device-bound claim of the same phrase adds the ML-DSA half. The stored Ed25519 key,
  `identity_public_key`, `route_id` and recovery fingerprint remain unchanged.
- Signing bytes and freshness checks come from `construct-server-trust::recovery`;
  clients use the core's `sign_recovery_setup` / `sign_recovery_claim`, without
  exporting private keys or constructing their own signing messages.

### Sender Certificate (sealed sender)

Issued by `AuthService::GetSenderCertificate` (via identity-service):
- Ed25519 signed, 24-hour TTL
- Contains: sender user_id, device_id, identity_key, domain, expiry, server signature
- Used for cross-server anonymous message routing
- Required `x-device-id` must agree with a device-bound access token; the selected device
  must be active and belong to the token's account. `BUNDLE_SIGNING_KEY` is required.

Device link/join tokens are consumed atomically with Redis `GETDEL` (Redis 6.2+, production
uses Redis 7). Approval and Privacy Pass issuance use the common token/header consistency
check. Invite signatures require an active issuing device belonging to the signed account;
rejected invites do not burn their jti. The wire formats, key bytes and TTLs are unchanged.

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
| `media_files` | Upload metadata (actual bytes on CDN/local storage) |
| `sticker_blobs` / `sticker_packs` | Public sticker packs, content-addressed (sha256 / pack_id), **no TTL** — a pack must resolve for as long as any message references it. Migration 070. |
| `user_blocks` | Block list entries |
| `invites` | Invite tokens (used for invite-only onboarding) |
| `contact_requests` | Contact request state |
| `mls_groups` | MLS group state; group application messages are stored as `mls_ciphertext` |
| `channels` / `channel_posts` | Broadcast channels; posts stored as `ciphertext` |

> **1:1 message content is never stored in PostgreSQL.** Those messages travel messaging-service → Redis Stream → client. Group (MLS) messages and channel posts are the exception: stored as ciphertext in group-service's tables.

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

Most integration tests are gated with `#[ignore]`. CI starts Redis/Postgres and runs
them in a separate service-backed step; locally, run them explicitly:
```bash
cargo test -p construct-server-shared -- --ignored   # run skipped integration tests
```

Identity contracts (actual RPC/core paths, random accounts/keys, cleanup on assertion failure):
`cargo test -p identity-service contract_tests -- --include-ignored --test-threads=1`.
Requires `DATABASE_URL` (migrated Postgres) and `REDIS_URL`. Checks issuance validation/cap/DLEQ,
certificate binding/signature/lifetime, link/join single-use across 16 connections, private link
results, invite signature/account/address/expiry/burn/revoke and mutual contacts. PoW's external
vector remains in `construct-pow`; the unused server-side negotiation API was removed in audit 241.

SQL contracts in `crates/construct-db/tests/contracts.rs` run the production queries
against a separate PostgreSQL schema per test, with all migrations applied. They cover
single-use KeyPackages and invite JTIs under contention, selection scope/expiry,
directional blocklists, route lookup, ownership transfer, membership removal, epoch
locking, channel invite usage and sender-key rotation. `shared/test_support/postgres.rs`
owns schema creation/cleanup, including cleanup on failed mutations; it contains no
delivery or authorization implementation. Set `DATABASE_URL`, then run
`cargo test -p construct-db --test contracts -- --ignored`.

Their RPC consumers run with Redis too:
`cargo test -p group-service tests::db_contracts -- --ignored`. These tests call the
real signed ownership, SubmitCommit and SubscribeChannel paths. Lock contention is
observed through PostgreSQL lock waits, rather than assumed from a sleep. Ownership
is rechecked within the transaction; private invites are channel-bound and their
atomic SQL refusal is honored; sender-key reads exclude rotated rows, and rotation is
scoped to channel and device. Audit 241 removes the unused sender-key writer; the
reader/rotation test seeds residual rows directly and still calls the production queries.

Audit 239 contracts run with `cargo test -p group-service -p media-service
-p identity-service -p construct-utils -p construct-metrics audit_239 -- --include-ignored`.
They check channel admission/usage/counter rollback, last-slot contention, idempotent
retry, atomic unsubscribe, invite revocation while SQL waits, and channel read access.
Media tests use a private schema and temporary directory: expired blobs/partials
disappear, filesystem failures retain retry records, missing files are harmless,
and non-expiring sticker packs survive. The identity error mapper preserves auth
codes/device-refusal metadata while keeping internal details in server logs.

The MLS worker floors a zero interval to one hour and falls back to 24 hours for
overflow/unrepresentable timers. Real send/commit/epoch-refusal/cleanup events now
produce their Prometheus counters; tests inspect the resulting series. Unproduced
gauges and connection/setup call metrics were removed, including the dashboard's
connected-call target: signaling does not observe E2EE SDP Answers.

`DeleteMedia` returns `UNIMPLEMENTED`; its unissued admin HMAC deletion path was
removed. The vendored proto declaration stays wire compatible; client blobs expire
through retention cleanup. `MEDIA_DEBUG` and the unread config field were removed;
service logging is configured through `RUST_LOG`.

Queue cleanup (audit 240) removes the unused delivery-worker list registry/poller,
sleep-only notification API, replay/cache/connection wrappers and dormant counters.
There is one mailbox write entry point: `write_message_to_device_streams`; its
internal legacy-user XADD remains behind the existing cutover flag. User/device
read helpers are private and no longer accept an unused server-instance argument.
Legacy session creation/validation helpers are gone; device deactivation still
calls `revoke_all_sessions` to remove residual indexed keys. Refresh store/rotation,
bulk revocation, access/device blocklists and Privacy Pass cap reads/reservations stay.

The obsolete `RedisChannels`, `ONLINE_CHANNEL`, `OFFLINE_QUEUE_PREFIX` and
`DELIVERY_POLL_INTERVAL_MS` configuration is removed, including compose's unused
overrides. **`DELIVERY_QUEUE_PREFIX` stays:** it addresses the active mailbox streams.
`construct-queue` no longer needs its direct crypto dependency or a production Tokio
dependency (Tokio remains a dev dependency). Shared `queue_test.rs` was removed:
its nine tests exercised retired counters/registry or raw Redis commands, not the
live queue. The actual Redis mailbox, sealed-dispatch and identity contracts remain.

### Crate-by-crate dead-code review (audit 241)

All 30 workspace members were checked against definitions, complete references,
re-exports, same-named protobuf/library methods, tests and feature gates. The retired
REST chain crosses DB, crypto, types and message crates, so its removal is one
connected change. It does not remove an HTTP/gRPC route: none of these retired
handlers or converters had a service caller. Vendored protobuf and the stored
`MessageEnvelope` schema, including legacy binary/string readers and MLS/federated
enum spellings, remain unchanged.

| Member | Review result |
|---|---|
| `construct-db` | Remove 16 unused public functions, the old bundle builder/records and unused pool-provider trait. Keep account deletion, capabilities, atomic invite burn, MLS/channel queries, reader/rotation and all 13 SQL contracts. No migrations or data cleanup. |
| `construct-crypto` | Remove the uncalled REST validator/types, unused delivery-ack hashes and obsolete PQ wire wrappers/validators. Keep Privacy Pass, hybrid signatures, server trust, at-rest encryption, username/HMAC hashing and the hybrid size constants actually read by signatures. |
| `construct-types` | Remove the old REST/WebSocket request/response and `ChatMessage` family. Keep account `UserId` and `RouteId` and their tests. |
| `construct-message` | Remove the uncalled `ChatMessage` conversions and reset constructor. Keep proto conversion, all stored-envelope variants and all current serialization/read contracts; remove redundant `allow(dead_code)`. |
| `construct-utils` | Remove unused REST request signing and security-header helpers. Keep network/TLS/Redis helpers and the validators used by services. |
| `construct-redis` | Remove 10 unused list/counter/set/script/stream convenience methods. Keep connection timeouts and the active mailbox stream operations. |
| `construct-context` | Remove unused provider traits, grouping views, direct constructor, conversion trait and sandbox setter. Keep the service-used builder, dependency fields and signer initialization. |
| `construct-error` | Remove unused `AppResult` and Hyper response adapter. Keep Axum responses, conversions, refusal metadata and error redaction. |
| `crypto-agility` | Remove unused negotiation, capability helpers, legacy invite record and unused error family. Keep the persisted protocol/suite labels, capability records and actual invite validation/signature contracts. |
| `construct-rate-limit` | Remove the uncalled action-based Redis/PG fallback limiter. Keep sliding windows, warmup cache, account-age lookup, address buckets and the degraded limiter. No live limit values change. |
| `construct-apns` | Remove unused silent/visible convenience methods, payload constructors, filter enum and version getter. Keep actual APNs send/VoIP, payload fields, environment probing and invalid-token policy. |
| `construct-auth` | Remove unread session TTL copy in `AuthManager`. Keep token TTL config where presence uses it, token verification/rotation/revocation and all auth tests. |
| `construct-auth-service` | Remove unused REST profile handler/request/key wrappers and unused `AuthServiceContext`. Keep binary registration/authentication core, PoW and refresh/logout/device deactivation. |
| `construct-notification-service` | Remove uncalled AppContext adapter and pool-provider implementation. Keep the notification context and every field used by messaging's in-process APNs path. |
| `construct-sentinel-service` | Remove an uncalled breaker-state accessor. Keep actual permission/quota/device/admin paths and degraded-limiter metrics. |
| `construct-pow` | Remove three unreferenced named difficulty constants. Keep the challenge verifier, measured adaptive policies and external vector. |
| `construct-federation` | Remove uncalled old identified-send client and write-only trust timestamps. Keep inbound identified/sealed routes, outbound sealed send, signing, SSRF and TLS. A narrow `expect(dead_code)` preserves required remote `messageId` deserialization instead of weakening the response contract. |
| `construct-config` | Remove unused `error-types` feature and redundant suppressions. Other dormant env/config candidates remain task 242. |
| `construct-metrics` | Remove a redundant suppression on the actively observed delivery histogram. Keep registry and live series. |
| `construct-queue` | Reviewed after 240; active implementation unchanged. Mailbox, retention, scoped dedup, token operations and fresh Privacy Pass retry rule remain. |
| `construct-server-shared` | Remove dead re-exports, unused combined identity extractor, unused health wrapper/build timestamp constant and empty `integration-tests` feature. Keep proto/adapters, metrics registration and build SHA reporting. |
| `identity-service` | Remove unused `RecoveryResult` and pool-provider implementation. Keep all identity/recovery/certificate/token/invite consumers. |
| `messaging-service` | Remove blanket context suppression and unused pool-provider implementation. Keep all context fields, actual dispatch/stream/receipt/sealed/APNs/Sentinel paths. |
| `media-service` | Remove unused file-size helper and unread result/state fields. Keep HMAC/expiry/size verification, storage SQL, cleanup retries and stickers. |
| `group-service` | Remove blanket test-helper suppression. Signed RPC handlers, MLS worker, SQL admission/ownership/commit logic and their tests remain. |
| `key-service` | Reviewed; actual prekey, archive, hybrid signature and KT consumers remain unchanged. |
| `signaling-service` | Reviewed; call registry/participant/auth/VoIP consumers remain unchanged. |
| `veil-service` | Reviewed; voucher issuance and signed config/capability producers/consumers remain unchanged. |
| `gateway` | Reviewed; current HTTP/2 forwarding/TLS paths remain unchanged. Dependency cleanup is task 242. |

`FederationClient::new_with_mtls` has no service call site, but is retained with its
TLS support because `construct-docs/decisions/domestic-island-deployment.md` explicitly
plans this surface. Current `new`/`new_with_signer` use platform CA verification;
the island plan must wire and test pinning before claiming it is deployed.

The test-count delta is explicit: retire 29 tests of removed REST/wire-wrapper/hash/
action-limiter APIs (10 types, 7 shared REST messages, 9 crypto and 3 limiter tests).
The sender-key SQL test is adapted and renamed, not retired. No test of the active
mailbox, sealed dispatch, account identifiers, auth, identity, group or media path
is dropped. Dependency pruning and other env deletion remain task 242.

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

# Get pre-key bundle for a user (requires an access token)
grpcurl -plaintext \
  -H 'authorization: Bearer <access_token>' \
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
- Passwordless device auth (Ed25519 device key; PASETO v4.public tokens only)
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
- Idempotency via Redis `msg:dedup:v2:{scope_hash}` (24 h, set after the mailbox write).
  The length-prefixed hash includes sender account, recipient account, recipient device (or
  none), and message id. Unary fast-path, dispatch, and mailbox merge use the same scope.
  Old global keys are not read: they can suppress another sender. A retry spanning the
  rollout may be delivered again once; mailbox retention is unchanged.
- Offline delivery (Redis stream `delivery:offline:{user_id}[:{device_id}]`; `since_cursor` = read offset only — **no client XTRIM**; retention via `MAXLEN ~` + age sweep 7d)
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
- Empty delivery tags remain compatible and are counted by
  `construct_msg_sealed_delivery_tag_missing_total` at the local replay guard.
  Token redemption still precedes that guard: retries use a fresh token, even after a
  failed mailbox write; no nonce is refunded (234, `sealed_matrix_tests::t2`).

**Push:**
- APNs prod + sandbox clients, routed per-token by `push_environment`
- 403 = provider-auth error (never deletes device tokens); only
  `BadDeviceToken`/`Unregistered` do
- Device-token registration accepts ≤ 512 chars (FCM-ready); FCM send path not yet implemented

**Federation:**
- `.well-known/construct-server` server discovery (the RS256 `jwks.json` and `/public-key` endpoints were removed in 0.20.0)
- S2S sealed sender forwarding (`/federation/v1/sealed`, `/federation/v1/messages`)
- S2S signatures bind all seven envelope fields, escaping `%` and `:` before joining;
  the receiver binds the destination to `INSTANCE_DOMAIN`. Regular requests require
  nonempty signed `from`/`to`; sealed requests sign empty addresses.
  Replay claims use `fed:v2:msg:<SHA-256(length-framed origin, message_id)>`, seven-day
  `SET NX EX`, after signature verification; dispatch failure releases the claim,
  a claim-store outage returns 503. See [the signing contract](crates/construct-federation/README.md)
  for compatibility and test coverage.
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

---

**Maintainer:** Konstruct Team  
**License:** AGPL-3.0-only (see LICENSE)
