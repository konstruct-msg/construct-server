# Konstruct

**Privacy by Architecture. Not by Promise.**

> Your messages are encrypted on your device before they leave it.  
> The server routes sealed blobs — it cannot read what you wrote, who you wrote to, or when you last opened the app.

---

## What is Konstruct?

Konstruct is an open, federated, end-to-end encrypted messenger built on the principle that **privacy is a technical guarantee, not a policy statement**.

We don't ask you to trust us. The cryptography makes trust unnecessary.

```
Signal's Security  +  Email's Openness  +  Minimal Attack Surface
```

---

## Privacy Guarantees

### How this is enforced technically

**End-to-end encryption** — Messages are encrypted on the sender's device using the recipient's public key. The ciphertext is what travels over the network. The server stores nothing readable.

**Sealed sender** — The server does not learn who sent you a message. The sender's identity is encrypted inside the message envelope. To the server it's an opaque blob destined for a device.

**No message persistence** — Messages are never written to a database. They travel: sender → messaging-service → Redis Stream → recipient. Once delivered they are gone from the server.

**Invite-only onboarding** — No phone number. No email. Access is via cryptographic invite tokens. Zero personally identifiable information required to register.

**Passwordless authentication** — Your device *is* your identity. A device-local Ed25519 key pair is your credential. The server never sees a password.

**No metadata collection** — The server does not log IP addresses, does not track who messages whom, does not store timestamps of activity.

---

## Cryptography

All encryption happens on the client. The server is a dumb router of sealed envelopes.

### Key agreement — X3DH (Signal Protocol)

```
Alice fetches Bob's public key bundle from the server
  ↓
Alice performs X3DH locally — 4 ECDH operations
  ↓
Shared secret derived with HKDF-SHA256
  ↓
Double Ratchet session initialized — every message gets a fresh key
```

### Post-Quantum Cryptography — active today

The server supports two crypto suites simultaneously:

| Suite ID | Name | Keys | Status |
|----------|------|------|--------|
| `1` | ClassicX25519 | Ed25519 + X25519 | Active |
| `2` | PQHybridKyber | Ed25519 + ML-KEM-768 ⊕ X25519 | Active |

Hybrid PQC means: even if ML-KEM-768 has an undiscovered flaw, X25519 still protects you. Even if a quantum computer breaks X25519, ML-KEM-768 still protects you.

**Why it matters now:** Nation-states collect encrypted traffic today to decrypt it when quantum computers become capable. "Harvest now, decrypt later" is a documented threat. Konstruct's PQC protects messages sent today against future quantum attacks.

### Prekey signature scheme

Every uploaded prekey is signed with the device's Ed25519 key:

```
Ed25519.sign(device_key, "KonstruktX3DH-v1" || [0x00, suite_id] || pubkey_bytes)
```

The server verifies all signatures on upload (RFC 8032 strict). A forged or tampered key bundle is rejected before it can reach any client.

### Algorithms in use

| Primitive | Algorithm | Notes |
|-----------|-----------|-------|
| Asymmetric encryption | X25519 + ML-KEM-768 (FIPS 203) | Hybrid KEM |
| Identity signatures | Ed25519 (RFC 8032) | Strict verification |
| Message encryption | ChaCha20-Poly1305 | 256-bit AEAD |
| Key derivation | HKDF-SHA256 | Per Signal spec |
| Token signing | RS256 (JWT) | Short-lived access tokens |

---

## Federation

Your identity is not owned by any company.

```
alice@your-server.com  ←─ E2E encrypted ─→  bob@another-server.org
        │                                             │
   your server                                  their server
 (routes envelopes,                          (routes envelopes,
  can't read them)                            can't read them)
```

- Run your own server. Control your own data.
- No vendor lock-in — the protocol is open.
- Server-to-server routing uses sealed sender — even federated servers don't learn conversation participants.

---

## Architecture

```
Client (iOS / macOS)
  │  gRPC over TLS (HTTP/2) — optionally via QUIC :443/UDP or veil/obfs4 gateway :9443
  ▼
Caddy :443      — edge TLS termination (Let's Encrypt), gRPC routing to services
  │
  ├──► identity-service  :50051  (Auth, Device, DeviceLink, User, Invite — merged)
  ├──► messaging-service :50053  (Messaging, Notification, Sentinel — merged)
  ├──► media-service     :50056  (encrypted attachments)
  ├──► veil-service      :50056  (VEIL ticket provisioning — separate deployment)
  ├──► key-service       :50057  (X3DH prekeys, ML-KEM keys)
  ├──► group-service     :50058  (MLS groups RFC 9420 + broadcast channels)
  ├──► signaling-service :50060  (WebRTC call signaling)
  └──► gateway           :3000   (HTTP: /health, /.well-known, /federation; veil/obfs4 proxy :9443)

Non-gRPC services:
  └──► masque-service    :9200   (WebSocket MASQUE-lite QUIC datagram relay)

Message flow (Redis-direct, no Kafka):
  sender → messaging-service → Redis stream delivery:offline:{user}[:{device}] + PUBLISH inbox:wakeup → recipient
  (never touches a SQL database — no message content persistence)
```

**gRPC-first architecture.** Core messaging, auth, and key management are gRPC. REST endpoints exist only for health, discovery, notification registration, and federation S2S.

---

## Minimal by Design

| Feature | Our choice | Why |
|---------|-----------|-----|
| Read receipts | Off by default | The sender doesn't need to know you read it |
| Typing indicators | None | Reduces anxiety, reduces metadata |
| Presence / last seen | None | Your availability is your business |
| Push notifications | Silent APNs only | You decide when to check |
| Stories, reactions | None | Not a social network |
| Analytics / telemetry | None | We collect nothing |

---

## Project Layout

```
construct-server/
├── gateway/               # Federation, health, discovery, veil/obfs4 proxy
├── identity-service/      # Merged auth + user + invite (Phase 2.7)
├── key-service/           # X3DH prekeys, PQC Kyber keys
├── masque-service/        # WebSocket MASQUE-lite QUIC datagram relay
├── media-service/         # Encrypted media upload/download
├── messaging-service/     # Send/receive, streaming, receipts, APNs push, sentinel
├── group-service/         # MLS group messaging (RFC 9420) + broadcast channels
├── signaling-service/     # WebRTC call signaling relay
├── veil-service/          # VEIL obfuscation ticket provisioning
├── shared/
│   ├── proto/             # Protobuf definitions (source of truth)
│   ├── migrations/        # PostgreSQL schema (65 migrations, 001–064)
│   └── tests/             # Integration tests
└── crates/                # Shared libraries (26 crates)
    ├── construct-crypto/  # Crypto primitives
    ├── construct-auth/    # JWT, PoW
    ├── construct-db/      # Database ORM + queries
    ├── construct-pow/     # Proof-of-Work challenge/verify
    ├── construct-apns/    # APNs HTTP/2 push client
    ├── construct-rate-limit/ # Redis sliding window rate limiter
    └── ...
```

---

## Running Locally

### Dependencies

```bash
# Start PostgreSQL + Redis
docker compose -f ops/docker-compose.dev.yml up -d
```

### Run a service

```bash
DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test \
REDIS_URL=redis://localhost:6379 \
RUST_LOG=info \
cargo run -p identity-service
```

### Run tests

```bash
cargo test --workspace --lib       # unit tests (no infra needed)

# Integration tests (need DB + Redis running)
DATABASE_URL=... REDIS_URL=... cargo test -p construct-server-shared
```

### Pre-commit

The repo has a pre-commit hook that runs `cargo fmt` and `cargo clippy -D warnings`. Run before committing:

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
```

---

## Contributing

Contributions are welcome. Before contributing, read the threat model below.

### Our priorities

| Priority | Area |
|----------|------|
| 🔴 Critical | Anything that weakens privacy or security guarantees |
| 🟠 High | Cross-device message continuity, MLS group chats |
| 🟡 Medium | Performance, observability, federation improvements |
| 🟢 Nice to have | UI polish, client SDKs |

### Rules for contributors

1. **Privacy is non-negotiable.** No feature ships that adds server-side visibility into user behavior, content, or metadata.
2. **No new REST endpoints for core functionality.** The architecture is gRPC-first. REST endpoints exist only for health, discovery, federation S2S, and notification registration.
3. **No PII in logs.** User IDs are HMAC-hashed before logging. IPs are never logged.
4. **Test your crypto changes.** Security-critical code requires unit tests with known vectors.
5. **Secrets never in source.** No keys, tokens, or credentials in any committed file — not even test fixtures.

---

## Threat Model

### Protected against

- ✅ Network observers (ISP, WiFi, national-level interception)
- ✅ Compromised server — server cannot decrypt messages
- ✅ "Harvest now, decrypt later" quantum attacks — hybrid PQC active
- ✅ MITM key substitution — prekey signatures verified client and server
- ✅ Spam / bot registration — Proof-of-Work + invite-only
- ✅ Message replay — idempotency keys, per-message ratchet keys

### Not protected against

- ❌ Compromised device (malware with screen access)
- ❌ Screenshots by the recipient
- ❌ Physical coercion of the recipient
- ❌ Metadata analysis at the network layer (traffic volume, timing)

---

## References

- [Signal Protocol: X3DH](https://signal.org/docs/specifications/x3dh/)
- [Signal Protocol: Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [ML-KEM — FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [MLS — RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 8032: Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)

---

## License

AGPL-3.0-only — see [LICENSE](LICENSE). Network use = source-disclosure obligation (§13).

---

<p align="center">
  <b>Privacy is a right. Not a feature. Not a setting. Not a subscription tier.</b>
</p>

## Trademark

**Konstruct™** / **Конструкт™** and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does **not** grant trademark rights — see [TRADEMARK.md](TRADEMARK.md).
Forks that distribute a modified version must rebrand.
