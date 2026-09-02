# Konstruct Server

Rust backend services for Konstruct.

The repository contains the gRPC services, shared crates, protobuf definitions,
database migrations, deployment manifests, and operational scripts for the
server side of the system. Product APIs are gRPC. HTTP is limited to health,
metrics, public discovery, federation S2S, and edge proxying.

Detailed implementation notes live in [DOCUMENTATION.md](DOCUMENTATION.md).
Operational ADRs and session notes live in `~/Code/construct-docs`.

## Status

- Production deployment is a single node.
- Federation S2S code exists and is tested, but there are no public seed nodes
  or client-side server selection flows.
- A self-hosted instance is isolated unless it is explicitly peered with another
  instance using mutual SPKI pinning.
- License: AGPL-3.0-only. See [LICENSE](LICENSE).

## Architecture

TLS terminates at Caddy. Caddy routes gRPC requests by protobuf service path to
internal Rust services. Each service validates authentication itself; Caddy does
not inject trusted user identity headers.

| Service | Binary | Port | Role |
| --- | --- | --- | --- |
| `caddy` | external | 443 TCP / 8080 h2c | Edge TLS and gRPC routing |
| `quic` | external | 443 UDP | Obfuscated QUIC transport to Caddy h2c |
| `gateway` | `gateway` | HTTP 3000 / proxy 9443 | Health, well-known, federation S2S, veil/obfs4 proxy |
| `identity` | `identity-service` | 50051 | Auth, device, device-link, user, invite, token issuance |
| `messaging` | `messaging-service` | 50053 | Send, stream, sealed sender, Privacy Pass redemption, APNs, Sentinel |
| `media` | `media-service` | 50056 | Encrypted media upload/download |
| `veil` | `veil-service` | 50056 | VEIL capability issuer; separate deployment surface |
| `key` | `key-service` | 50057 | X3DH and ML-KEM prekeys |
| `group` | `group-service` | 50058 | MLS groups and broadcast channels |
| `signaling` | `signaling-service` | 50060 | WebRTC signaling |
| `masque` | `masque-service` | 9200 WS | MASQUE-lite relay |

Data stores:

- PostgreSQL stores accounts, devices, public keys, migrations, contact-link
  HMACs, and delivery receipt routing state.
- Redis stores offline mailbox streams, wakeup pub/sub channels, rate limits,
  PoW challenges, token-spend state, replay guards, and token blocklist entries.
- Message content is not written to PostgreSQL.

## Message Delivery

Offline delivery uses Redis Streams, not Kafka.

```text
send
  -> messaging-service
  -> XADD delivery:offline:{user}              # legacy user stream
  -> XADD delivery:offline:{user}:{device}     # per-device stream
  -> PUBLISH inbox:wakeup:{user}

stream
  -> SUBSCRIBE inbox:wakeup:{user}
  -> read device stream plus legacy user stream when claims contain device_id
  -> dedupe by message_id, preferring device-stream entries
```

Delivery invariants:

- `since_cursor` is a read offset only. It must never trim or delete mailbox
  entries.
- Retention is handled by `XADD MAXLEN ~` plus the age sweep.
- Online users are woken by Redis pub/sub; APNs silent `new_message` is skipped
  while `user:{user_id}:server_instance_id` is set.
- `MSG_MAILBOX_USER_WRITE` controls legacy user-stream writes during cutover.
  When it is disabled, failure to write a target stream is a hard error.
- Mailbox payloads are written with `rmp_serde::encode::to_vec_named` and read
  with `rmp_serde::from_slice`.

## Authentication And Abuse Controls

- Primary access tokens are PASETO v4.public. Legacy RS256 JWT verification is
  retained for migration compatibility.
- Logout and revoke use Redis blocklist keys: `invalidated_token:{jti}`.
- Messaging requires a bearer token. Optional `x-user-id` and `x-device-id`
  headers must match token claims.
- Sealed sender redemption is controlled by `MSG_STEALTH_TOKEN_POLICY`:
  `off`, `warn`, or `enforce`.
- Privacy Pass uses `TOKEN_ISSUER_KEY`, a 32-byte hex VOPRF issuer key shared by
  identity-service and messaging-service.
- Empty token wallets may reduce abuse resistance, but must not reveal sender
  identity or downgrade a sealed send to an identified send.

## Cryptography

Client-side encryption is outside this repository. The server stores and routes
encrypted envelopes, verifies uploaded key material, and issues or redeems
server-side tokens.

| Area | Implementation |
| --- | --- |
| Device identity | Ed25519 |
| Classic prekeys | X25519 |
| Hybrid prekeys | ML-KEM-768 plus X25519 |
| Prekey signatures | Ed25519, strict RFC 8032 verification |
| Access tokens | PASETO v4.public; legacy RS256 JWT accepted |
| Anonymous anti-abuse | Privacy Pass VOPRF over ristretto255 |
| Groups | MLS, RFC 9420 |

## Repository Layout

```text
construct-server/
  gateway/               HTTP gateway, discovery, federation entrypoints
  identity-service/      auth, user, device, invite, token issuance
  messaging-service/     message send/stream, sealed sender, APNs, Sentinel
  media-service/         encrypted media service
  key-service/           prekey service
  group-service/         MLS and broadcast channels
  signaling-service/     WebRTC signaling
  veil-service/          VEIL capability issuer
  masque-service/        MASQUE-lite relay
  shared/                protobufs, migrations, shared tests
  crates/                shared Rust crates
  ops/                   Docker Compose, Caddy, monitoring, deployment config
  scripts/               local checks and operational scripts
```

## Local Development

After cloning, enable the repository hooks:

```bash
git config core.hooksPath .githooks
```

Start local PostgreSQL and Redis:

```bash
docker compose -f ops/docker-compose.dev.yml up -d
```

Build the workspace:

```bash
cargo build
```

Run a service locally:

```bash
DATABASE_URL=postgres://postgres:password@localhost:5432/construct_test \
REDIS_URL=redis://localhost:6379 \
INSTANCE_DOMAIN=localhost \
RUST_LOG=info \
cargo run -p identity-service
```

Some services require additional secrets. Use
[ops/secrets.example.env](ops/secrets.example.env) and
`crates/construct-config/src/lib.rs` as the source of truth for environment
variables.

## Checks

Default checks:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Offline mailbox Redis tests are ignored by default. Run them before changing
delivery behavior or `MSG_MAILBOX_USER_WRITE`:

```bash
docker exec construct-redis-local redis-cli ping
cargo test -p construct-queue --lib -- --ignored mailbox
```

Static observability checks:

```bash
python3 scripts/check-observability.py
```

## Production

Production deployment is defined in [ops/docker-compose.prod.yml](ops/docker-compose.prod.yml).
Secrets are read from `/opt/construct/secrets/app.env`; use
[ops/secrets.example.env](ops/secrets.example.env) as the template.

Before deploying, validate secrets:

```bash
./scripts/preflight-secrets.sh /opt/construct/secrets/app.env
```

Important configuration rules:

- `INSTANCE_DOMAIN` is required on every Rust service.
- `SERVER_SIGNING_KEY` is base64 for exactly 32 bytes.
- `TOKEN_ISSUER_KEY` is hex for exactly 32 bytes.
- Do not re-declare secrets from `app.env` as bare `${VAR}` entries under a
  Compose `environment:` block; an unset shell variable overrides the secret
  with an empty string.
- Recreate services after secret changes with `docker compose up -d --force-recreate`;
  `restart` does not re-read `env_file`.

## References

- [DOCUMENTATION.md](DOCUMENTATION.md)
- [ops/docker-compose.prod.yml](ops/docker-compose.prod.yml)
- [ops/secrets.example.env](ops/secrets.example.env)
- [TRADEMARK.md](TRADEMARK.md)

## Trademark

Konstruct and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does not grant trademark rights. Forks that distribute a
modified version must rebrand.
