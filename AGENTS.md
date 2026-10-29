# AGENTS.md — construct-server

Rust microservices behind Caddy: identity, messaging (Redis mailbox, sealed sender, APNs), key,
group, media, signaling. The server relays and stores ciphertext; it decides nothing about
sessions and must learn as little as possible. If a rule here and your plan disagree, the rule
wins until a `decisions/` note says otherwise.

| Area | Read first |
|---|---|
| Why these rules exist; checklist before any new protocol feature | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| Crates, services, handbook | `DOCUMENTATION.md` · `ops/docker-compose.prod.yml` |
| Mailbox / delivery | `decisions/minimal-server-delivery.md` · `decisions/redis-direct-delivery-not-kafka.md` · `architecture/scaling.md` |
| Sealed sender + Privacy Pass | `decisions/sealed-sender-anti-abuse-economics.md` · `deployment/stealth-token-keys-runbook.md` · `backend/TOKEN_SPEND_UNIT_RECIPIENT_BINDING_SPEC.md` |
| What a client may influence | `decisions/server-influence-minimization.md` |
| Secrets | `decisions/secrets-are-sliced-not-shared.md` |
| Tokens | `decisions/paseto-v4-public-migration.md` |
| One meaning, two carriers; wire format authority | `decisions/one-meaning-two-carriers.md` · `decisions/wire-format-one-authority.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) — paths relative to the vault |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md`. Change it there first.

## Rules

1. **Prior art first.** A new delivery, mailbox, group or key mechanism starts with a note: how Signal / MLS (RFC 9420) / Matrix solve it, and why we deviate. Group key management is MLS, not ours.
2. **The server relays; the core decides.** Ratchet, session and lifecycle logic belongs to `construct-core`. The server routes opaque ciphertext and holds the account → device directory; it never interprets session state.
3. **Time is not an address.** A server behaviour that needs a timer, cooldown or window to tell current from stale is missing a cursor, epoch or id. Retention TTLs are retention, not protocol.
4. **Reproduce before fixing.** A delivery loss is fixed when a test or stand that was red turns green. The offline mailbox is not covered by plain `cargo test` (see Build).
5. **One meaning, one carrier.** Account UUID and 32-hex device id are different types; outer envelope fields and `SealedInner` are different layers; a new `content_type` adds its row in `construct-protos/conformance` in the same change.
6. **Bytes stay bytes.** Envelope payloads are `Vec<u8>`; no new base64 or JSON for binary. The legacy base64/string dual-read stays only for old clients.
7. **Measure, then build.** Stream knobs, rate limits, PoW tiers and cutover gates are changed on a measured series, not a guess.
8. **The effect is the proof.** Verify a deploy by the version it reports (`construct_build_info` in Prometheus), a backup by restoring it, a delete by querying after it, an alert by its series.
9. **A test must be able to fail.** Put the decision in a pure function and mutation-check the test: one mutation at a time, an unapplied mutation is fatal, restore by shasum. A green suite that skips `#[ignore]` tests says nothing about delivery.
10. **Depth before breadth.** No new service or surface while 1:1 delivery is not boring on the stand and with testers.
11. **A temporary exception has an end date and a check.** Flags (`MSG_MAILBOX_USER_WRITE`, `MSG_STEALTH_TOKEN_POLICY`) and legacy paths are listed with the metric that says when they can go.
12. **Branch and PR, always;** see Git.

**Three questions before a delivery or crypto change lands**, answered in the commit message (the answers, not "this is safe"): (1) what does the server or any relay learn that it did not before; (2) what can a party — server, sender, sibling device — withhold or substitute that it could not before; (3) which trust boundary moves, and which way. An honest "something" on 1 or 2 makes it a `decisions/` note, not a merge.

**A producer with no consumer is a defect.** A send, signal or RPC lands with its reader in the same change, or is removed.

## Invariants of this repo

### Mailbox (Redis)

Send: `XADD delivery:offline:{user}` (legacy, gated by `MSG_MAILBOX_USER_WRITE`) → `XADD delivery:offline:{user}:{device}` → `PUBLISH inbox:wakeup:{user}`. Stream: subscribe to `inbox:wakeup:{user}`, then dual-read device + user streams (device-less legacy tokens read the user stream only); dedupe by `message_id`, prefer device.

- `since_cursor` is a read offset only. Never `XTRIM` from a client-asserted cursor (silent loss with paging, cancel and multi-device).
- Retention: `MAXLEN ~` on XADD plus an hourly age sweep (`construct_queue::MAILBOX_MAX_AGE_DAYS`, 7 d = construct-core `QUEUE_TTL_SECS`; the landing's privacy policy states it). Account deletion deletes the mailboxes (`MessageQueue::delete_mailbox`).
- No APNs silent `new_message` while `user:{user_id}:server_instance_id` is set; online means `inbox:wakeup` only (else reconnect storms).
- A user-stream entry whose `recipient_device` names another device is skipped at the merge and counted in `construct_msg_mailbox_sibling_entries_skipped_total`. `MessageStream` keeps its own position for the user stream (`StreamCatchupState::user_stream_id`) that moves on what a read examined, or the skipped entries are re-read every 5 s poll.
- Cutover gate for `MSG_MAILBOX_USER_WRITE` (default `1`): `construct_msg_mailbox_user_only_entries_total` flat zero for 7 days (not `mailbox_read_total{mode=…}`). Rollback = set it back to `1`. With the flag off, reaching no stream is a hard error, never a silent `Ok`.
- Serialization: `rmp_serde::encode::to_vec_named` / `rmp_serde::from_slice`. No Kafka as the offline queue without a new ADR.
- Keys: `msg:dedup:{message_id}` is set after the mailbox XADD. `delivery_queue:{instance}` is leftover, tests only — never write, poll or `KEYS` it; route by `GET user:{user}:server_instance_id`. Other namespaces (`rate:*`, `pow:*`, `spent:*`, `pp:unit:*`, `sealed:*`, `invalidated_token:*`) are in the code that owns them.

### Auth and edge

- PASETO v4.public only; a token without the `v4.public.` prefix is rejected. Issuer from `AUTH_TOKEN_ISSUER` (fallback `JWT_ISSUER`). Framing is `nonce(32) || message || sig(64)` — client slicing offsets are not a bug. TTL `ACCESS_TOKEN_TTL_HOURS` (24 h).
- Logout needs `access_token` in the body (empty → `INVALID_ARGUMENT`) and writes `invalidated_token:{jti}`; `RevokeAll` walks the `user_tokens:{user}` index, not all keys.
- messaging gRPC uses `extract_authed_user_id()`: Bearer required, verify + blocklist, fail-closed on Redis error. `x-user-id` / `x-device-id` must match claims; headers alone are never trusted. Caddy injects no `x-user-id`; gateway `:9443` has no token auth. Each service validates with `construct-auth::AuthManager`.
- `ops/Caddyfile`: `flush_interval -1` only for streaming RPCs (`MessageStream`, `SignalingService`); on unary RPCs it emits DATA+END_STREAM and grpc-swift reports "EOS alongside a data frame" instead of `privacy_pass:…`. Caddyfile is a single-file bind mount: `up -d --force-recreate caddy` after edits.

### Sealed sender and Privacy Pass

- `TOKEN_ISSUER_KEY` is 32-byte hex (not `SERVER_SIGNING_KEY`, base64). Unset → fail-quiet; malformed → boot fails.
- `MSG_STEALTH_TOKEN_POLICY` = `off` | `warn` | `enforce`; enforce → `FAILED_PRECONDITION` `privacy_pass:{label}`. Never downgrade to an identified send.
- Multi-chunk unit: `SealedInner.token_spend_id` + recipient binding (`pp:unit:…`), empty = per-envelope, cap 256.
- An empty token wallet may degrade anti-abuse, never delivery or anonymity; no server path reveals the sender on token failure.
- Sealed path keeps `encrypted_payload` empty (no Redis dual copy). Outer envelope fields (`message_id`, `timestamp`, `conversation_id`, `edits_message_id`) are transport-only; E2E meaning lives in `MessageContent` / `SealedInner`.

### Services, APNs, Sentinel

- Ports: identity 50051, messaging 50053 (+ HTTP 8083, `/federation/v1/*`), media 50056 (also `StickerService`: public packs, no TTL, published by `sticker-publish`, never via the request path), `veil-service` 50056 (separate deploy), key 50057, group 50058, signaling 50060, masque WS 9200 (built, not deployed). Rest: `ops/docker-compose.prod.yml`.
- Auth/user/notification/sentinel are not separate deployables. Production delivery lives only in `messaging-service/src/core.rs`; a test drives it, never a copy of it (the old `shared/tests/test_utils.rs` dispatcher is gone).
- APNs: delete a token only on `BadDeviceToken` / `Unregistered`; 403 is provider auth — never delete. Registration accepts ≤512 chars. Prod + sandbox by `device_tokens.push_environment`.
- Sentinel is in-process in messaging, fail-open on Redis/internal errors; its ids are 32-char hex device ids, not user UUIDs.
- Identity: `route_id` = `SHA-256(type || key)` hex; `dispatch_sealed_sender` resolves route_id → UUID before delivery; everything after is UUID-based (migration 064, `construct-types` / `construct-db`).

### Config

- Known debt: `AppContext` APNs/token_encryption are set only by identity's `to_app_context()` (messaging pushes through `notification_core`); signaling's in-memory `user_channels` is empty after restart (clients reconnect).
- `INSTANCE_DOMAIN` is required on every Rust service (mismatch breaks federation).
- Never re-declare an `app.env` secret as bare `${VAR}` under compose `environment:` (unset shell var blanks it). Rotate with `up -d --force-recreate`, not `restart`.
- `secret_hygiene` fails boot on malformed secrets; run `scripts/preflight-secrets.sh` before deploy. Binaries load `Config::from_env_for(SecretNeeds::*)`. No Vault-on-box, no `app.env` encrypted with a key beside it.
- tonic 0.14.x has no `http2_keepalive_while_idle`; the app HeartbeatAck is the keepalive.

## Build, lint, test

```bash
cargo build                     # or: cargo build -p messaging-service
cargo fmt && cargo clippy       # .githooks/pre-push checks both, plus observability, Redis-timeout, front-coordinates guards
cargo test
docker exec construct-redis-local redis-cli ping   # or: docker compose up -d redis
cargo test -p construct-queue --lib -- --ignored mailbox   # the offline mailbox; run before touching delivery or the flag
```

`cargo test` skips the `#[ignore]` Redis/Postgres tests — that is how the 2026-08-18 loss shipped; CI now runs them with `-- --ignored` against its own services. A test that needs a service is either `#[ignore = "requires …"]` or skips only outside CI (`CI` set → a missing service fails it); never `FLUSHDB` a shared Redis — name keys per test. Run everything locally with `cargo test --workspace --all-targets -- --ignored --test-threads=1` after `docker compose up -d redis postgres`. There is no pre-commit hook; the pre-push hook does not reformat.

## Git

- **Never commit or push to `main`.** Topic branch (`feat|fix|chore|docs/<topic>`) from up-to-date `main`, `git push -u origin HEAD`, `gh pr create`. No exceptions for docs-only work (`.grok/rules/no-direct-main.md`). The owner merges.
- Check `git branch --show-current` and `git status` before every commit; other sessions share the tree. Never `checkout -- .`, `restore .`, `reset --hard` or `stash`; name files. Never rewrite pushed history.
- Docs: vault `AGENTS.md` is authoritative. A decision that constrains future work goes into `decisions/`; one line into `log.md`.
