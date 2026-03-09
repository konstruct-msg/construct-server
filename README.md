# Construct

**Privacy by Architecture. Not by Promise.**

> Your messages are encrypted on your device before they leave it.  
> The server routes sealed blobs — it cannot read what you wrote, who you wrote to, or when you last opened the app.

---

## What is Construct?

Construct is an open, federated, end-to-end encrypted messenger built on the principle that **privacy is a technical guarantee, not a policy statement**.

We don't ask you to trust us. The cryptography makes trust unnecessary.

```
Signal's Security  +  Email's Openness  +  Minimal Attack Surface
```

---

## Privacy Guarantees

### What the server never sees

| Data | Signal | Telegram | **Construct** |
|------|--------|----------|---------------|
| Message content | ✅ never | ❌ sees | ✅ never |
| Contact list | ⚠️ sees hashes | ❌ sees | ✅ never stored |
| Who you talk to | ⚠️ metadata | ❌ sees | ✅ sealed sender |
| When you were last online | ❌ sees | ❌ sees | ✅ never |
| Your real name | ⚠️ via phone | ❌ sees | ✅ not required |
| Phone number | ❌ required | ❌ required | ✅ not required |

### How this is enforced technically

**End-to-end encryption** — Messages are encrypted on the sender's device using the recipient's public key. The ciphertext is what travels over the network. The server stores nothing readable.

**Sealed sender** — The server does not learn who sent you a message. The sender's identity is encrypted inside the message envelope. To the server it's an opaque blob destined for a device.

**No message persistence** — Messages are never written to a database. They travel: sender → Kafka → Redis Stream → recipient. Once delivered they are gone from the server.

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

| Suite | Keys | Status |
|-------|------|--------|
| `0x01` ClassicX25519 | Ed25519 + X25519 | ✅ Active |
| `0x10` HybridKyber1024X25519 | Ed25519 + ML-KEM-1024 ⊕ X25519 | ✅ Active |

Hybrid PQC means: even if ML-KEM-1024 has an undiscovered flaw, X25519 still protects you. Even if a quantum computer breaks X25519, ML-KEM-1024 still protects you.

**Why it matters now:** Nation-states collect encrypted traffic today to decrypt it when quantum computers become capable. "Harvest now, decrypt later" is a documented threat. Construct's PQC protects messages sent today against future quantum attacks.

### Prekey signature scheme

Every uploaded prekey is signed with the device's Ed25519 key:

```
Ed25519.sign(device_key, "KonstruktX3DH-v1" || [0x00, suite_id] || pubkey_bytes)
```

The server verifies all signatures on upload (RFC 8032 strict). A forged or tampered key bundle is rejected before it can reach any client.

### Algorithms in use

| Primitive | Algorithm | Notes |
|-----------|-----------|-------|
| Asymmetric encryption | X25519 + ML-KEM-1024 | Hybrid |
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
Client (iOS)
  │  gRPC over TLS
  ▼
Envoy proxy :8080
  │
  ├──► auth-service    :50051   (registration, JWT)
  ├──► key-service     :50057   (prekey bundles, PQC keys)
  ├──► messaging-service :50053 (send/receive, streaming)
  ├──► user-service    :50052   (profiles)
  ├──► media-service   :50056   (encrypted attachments)
  └──► invite-service  :50055   (cryptographic invites)

Message flow:
  sender → messaging-service → Kafka → Delivery Worker → Redis Stream → recipient
  (never touches a SQL database — no message persistence)
```

**Pure gRPC architecture.** No REST. No WebSockets. Binary protocol end-to-end.

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
├── auth-service/          # Device registration, JWT, recovery
├── key-service/           # X3DH prekeys, PQC Kyber keys
├── messaging-service/     # Send/receive, streaming, receipts
├── user-service/          # User profiles
├── media-service/         # Encrypted media upload/download
├── invite-service/        # Cryptographic invite tokens
├── notification-service/  # Silent APNs push
├── gateway/               # Federation, health, discovery
├── delivery-worker/       # Kafka → Redis delivery bridge
├── shared/
│   ├── proto/             # Protobuf definitions (source of truth)
│   └── migrations/        # PostgreSQL schema (devices & keys only)
└── crates/                # Shared libraries
    ├── construct-crypto/  # Crypto primitives
    ├── construct-auth/    # JWT, PoW
    ├── construct-db/      # Database queries
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
cargo run -p auth-service
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
2. **No new REST endpoints.** The architecture is gRPC-only. REST was removed deliberately.
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

See [LICENSE](LICENSE).

---

<p align="center">
  <b>Privacy is a right. Not a feature. Not a setting. Not a subscription tier.</b>
</p>

