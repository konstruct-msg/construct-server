# Audit: sealed sender + server messaging knowledge

**Date started:** 2026-08-02  
**Living log** — update statuses as findings are fixed or accepted.  
**Prior audit (archived):** `construct-docs/_archive/AUDIT-FINDINGS-2026-07-28-pre-publish.md`  
  (auth spoof, secrets, revoke, media, fail-open metrics — code complete).

---

## Scope & goals

| In scope | Out of scope (for this log) |
|----------|-----------------------------|
| Server-side sealed-sender correctness | Client E2E crypto (Double Ratchet / MLS) |
| What the **server learns** per message (metadata) | Network DPI / Veil transport strength |
| Privacy Pass issuance + redemption on the wire | UI / product stealth toggles |
| Protocol fields vs transport fields (independence) | Full federation multi-operator threat model (phase later) |
| Identified vs sealed dual-path residual risk | Android client completeness (note only) |

**Threat orientation:** honest-but-curious **home / destination server** (and colluding pair of federated servers), plus compromised operator with Redis/Postgres/logs access. Goal: minimize load-bearing server knowledge so the messaging **protocol** does not depend on transport-visible metadata (see [[server-influence-minimization]], protocol-independent-of-transport trend).

**Related ADRs / specs (read first):**

- `construct-docs/decisions/stealth-sealed-sender-v2-always-on.md`
- `construct-docs/decisions/sealed-sender-authenticated-transitional.md`
- `construct-docs/decisions/sealed-sender-anti-abuse-economics.md`
- `construct-docs/decisions/server-influence-minimization.md`
- `construct-docs/decisions/stream-delivery-receipt-deanonymized-sealed-sender.md` (accepted 2026-08-02)
- `construct-docs/security/features/sealed-sender.md`
- `construct-docs/deployment/stealth-token-keys-runbook.md`
- **Client handoff checklist:** `construct-docs/client/specs/SEALED_CLIENT_CHECKLIST_FOR_SERVER_PATH.md`

---

## Executive summary (Phase 0 pass, 2026-08-02; client check 2026-08-02)

The server has a **real dual-path design**:

1. **`SendSealedMessage`** — unauthenticated ingress; anti-abuse = IP RL + Privacy Pass + delivery-tag replay. Destination learns **recipient**, not sender. Persist path stores `sender_id = ""`.
2. **`SendMessage` + `sealed_sender`** — **legacy authenticated** sealed branch (`require_legacy_sealed_sender_auth`). Server **sees sender JWT and recipient** at send time. Documented as transitional.
3. **`SendMessage` identified** — full sender+recipient graph; still fully supported for exclusions (heartbeats, multi-device) and DEBUG stealth-off.

### Client reality check (product decision input) — 2026-08-02

| Layer | iOS (`construct-messenger`) | Android |
|-------|----------------------------|---------|
| **Envelope stealth always-on** | ✅ Release: `StealthPolicy.isEnabled = true` hard; DEBUG toggle only | ✅ Release always-on; debug pref kill-switch |
| **Sealed covers** | messages, edits, receipts, profile, calls, **session control** (2026-07-27) | same policy shape (exclusions caller-owned) |
| **Exclusions (identified OK)** | E2E heartbeats (ct=13), multi-device SenderSync / own-device fan-out | same list in docs |
| **Unauth transport flag** | ❌ `FeatureFlags.sealedSenderUnauthenticatedTransport = **false**` | ❌ `SEALED_UNAUTHENTICATED_TRANSPORT = **false**` |
| **Default send path today** | Build SealedInner → **`sendMessage(sealedInnerBytes:)`** (Bearer + JWT) | same: sealed-over-authenticated `SendMessage` |
| **Scaffolding for real anon** | `sendSealedMessage` + `_sealedConn` (no AuthInterceptor) ready | `sendSealedMessage` + `sealedMessaging` ready |
| **Never downgrade to identified** | ✅ `StealthSendRecovery` / seal-fail throws | documented same intent |
| **Token model** | per-message only (per-stream removed) | still has per-stream prefs (lag vs iOS) |

**Product conclusion:** “Stealth always-on” today means **metadata-at-rest + recipient-hidden sender** (T1), **not** real-time anonymity vs the server (T2). Unifying the server onto a **single unauth sealed ingress** is correct end-state, but **cannot be cut hard** until both clients flip `sealedSenderUnauthenticatedTransport` (and preferably PP warn→healthy). Server should keep dual ingress until that flag is ON in release; then deprecate sealed-on-`SendMessage`.

Largest remaining classes:

| Class | Severity | One-liner |
|-------|----------|-----------|
| **A. Dual path / transitional auth** | High (privacy) | Clients still default to authenticated sealed; unauth flag OFF |
| **B. Wire metadata in `SealedInner`** | Medium | `content_type` / `priority` / `ttl` plaintext — **deprecate → 1-byte in E2E** |
| **C. PP policy `warn`** | Medium (abuse) | Tokens optional for delivery; spam path open until `enforce` |
| **D. Block / anti-abuse gaps on sealed** | Medium | Blocklist needs sender UUID — sealed has none (client-side) |
| **E. Stale proto/docs** | Low | **FIXED 2026-08-02** — `envelope.proto` comments corrected + fields deprecated |
| **F. Correlation surfaces** | High (long-term) | Shared connections, size/time, push, IP RL keys |

---

## Phase 0 — inventory (server surface)

### Ingress RPCs (messaging-service)

| RPC | Auth | What server learns | Anti-abuse |
|-----|------|--------------------|------------|
| `SendMessage` (identified) | Bearer required; envelope.sender must match claims | sender, recipient, content_type, payload size, client message_id (echoed), IP | rate limits, sentinel, block check |
| `SendMessage` + `sealed_sender` | Bearer **required** (legacy) | **sender from JWT** + recipient from SealedInner | same + PP (warn/enforce) + delivery_tag |
| `SendSealedMessage` | **None** (by design) | recipient, size, time, IP, SealedInner open fields, PP outcome | `sealed_ip` RL, PP, delivery_tag |
| `MessageStream` / pending fetch | Bearer | recipient (subscriber); sealed payloads without sender_id | stream auth only |
| Federation inbound sealed | S2S signature | dest server: same as local sealed | origin RL (fail-open metered) |

### Key code map

| Concern | Path |
|---------|------|
| Sealed dispatch | `messaging-service/src/envelope.rs` `dispatch_sealed_sender` |
| Unauth sealed RPC | `messaging-service/src/grpc.rs` `send_sealed_message` |
| Legacy sealed gate | `grpc.rs` `require_legacy_sealed_sender_auth` |
| PP redeem | `messaging-service/src/token_redeem.rs` |
| Delivery-tag replay | `messaging-service/src/spent_tag.rs` |
| Persist / fan-out | `messaging-service/src/core.rs` `dispatch_envelope` |
| Envelope model | `crates/construct-message/src/types.rs` `from_sealed_sender` |
| Wire schema | `shared/proto/core/envelope.proto` `SealedSenderEnvelope` / `SealedInner` |
| Token issue | identity-service `IssueTokens` + `TOKEN_ISSUER_KEY` |
| Fail-open matrix | `messaging-service/src/fail_open.rs` |

### Target server-knowledge invariant (from stealth-v2 ADR)

Per sealed message the server **should** learn only:

- recipient user id  
- arrival time  
- ciphertext size  
- source connection (mitigated by Veil / transport)  

**Must not** learn: sender id, device id, conversation id, content type.

### Actual server-knowledge (code-backed, 2026-08-02)

| Field | Destination server (local sealed) | Notes |
|-------|-----------------------------------|-------|
| `SealedInner.recipient_user_id` | **Yes** | Required for routing |
| `SealedInner.delivery_tag` | **Yes** | Replay cache (hashed key material) |
| `SealedInner.token_nonce` / `token_bytes` | **Yes** | Opened/verified; spend marker only |
| `SealedInner.sender_cert_ciphertext` | Opaque bytes | Server must not decrypt (trust discipline) |
| `SealedInner.encrypted_payload` | Opaque + **size** | Size is traffic analysis |
| `SealedInner.content_type` | **Visible if parsed** | Proto field 5; currently **not used** for routing after decode, but present on wire |
| `SealedInner.priority` / `ttl` | **Visible if parsed** | Same |
| `sender_id` at rest | **Empty** | `from_sealed_sender` — good |
| Server-assigned `message_id` | **Yes** | New UUID; not client E2E id — good for influence min. |
| Authenticated path JWT sub | **Yes on legacy path** | Breaks real-time anonymity |
| Blocklist effectiveness | **No for sealed** | `is_blocked_by` skipped when `sender_id` empty |
| Receipt `store_message_sender` / `delivery_pending` | **Skipped when empty** | Good; client-side E2E receipts must not re-link (ADR 2026-08-02) |
| Blind APNs | recipient only | `activity_type=new_message`, no conversation_id — good |

---

## Findings

### SM-A1 — Dual sealed ingress (authenticated legacy still live)

**Status:** OPEN — **blocked on client flag flip** (not a pure server cut)  
**Severity:** High (privacy vs “always-on sealed” narrative)  
**Refs:** `grpc.rs`; ADR transitional; iOS/Android flags still `false` (verified 2026-08-02)

- Production still accepts sealed envelopes on **authenticated** `SendMessage` — and **this is what clients use by default**.
- Against honest-but-curious server, that path yields full (sender, recipient, time) at request time even if at-rest envelope hides sender.
- Scaffolding for the end state exists on both ends (`SendSealedMessage` / `_sealedConn` / `sealedMessaging`).

**Product path (recommended):**

1. Client workstream (parallel): flip `sealedSenderUnauthenticatedTransport` ON after device validation of PP redeem + sealed channel lifecycle (plan Phase 4 in `SEALED_SENDER_PRODUCTION_PLAN.md`).  
2. Server keeps dual ingress until metrics show sealed traffic almost entirely on `SendSealedMessage`.  
3. Then sunset: reject `sealed_sender` on `SendMessage` (or hard-cut) — single path.  
4. **Do not** remove identified `SendMessage` entirely — heartbeats / multi-device exclusions still need it.

---

### SM-A2 — Identified `SendMessage` remains first-class

**Status:** OPEN (by design for control/multi-device?)  
**Severity:** High if clients still prefer it for chat traffic  
**Refs:** `grpc.rs` identified path; stealth exclusion list (heartbeats, multi-device sync)

Server still learns full social graph for any non-sealed traffic. Audit must confirm **which** content types clients still send identified (control, key sync, multi-device, media).

**Next:** inventory client send sites vs server content-type handling; ensure no silent downgrade path (server must not force identified fallback).

---

### SM-B1 — `SealedInner` plaintext `content_type` / `priority` / `ttl`

**Status:** DECISION LOCKED (2026-08-02) — implement on clients next; server already ignores  
**Severity:** Medium (metadata)  
**Refs:** `envelope.proto` fields 5–7 (now marked DEPRECATED); iOS `StealthSenderService.buildSealedInner` still writes `contentType`; MessageRouter recovers type from SealedInner before/alongside decrypt

**Facts:**
- Destination server **can** read message kind without decrypting DR payload.
- `dispatch_sealed_sender` does **not** branch on these fields today (good).
- Blind APNs already does not use content type (good).
- Enum max value is 26 → **fits in 1 `u8`**.

**Product direction (agreed):**
1. **Do not keep a server-visible type field** “for convenience”.
2. **Target:** message kind is a **1-byte (or compact binary) signal inside the E2E payload** — after Double Ratchet decrypt — not on `SealedInner`. Aligns with existing binary control work (`SessionControl` / `binarySessionControlPayload`, receipts binary, protocol-independent-of-transport).
3. **Space win is free:** protobuf enum varint for type ≈ 1–2 bytes on wire already; the win is **privacy + single source of truth**, not bytes.
4. **Migration:** clients stop writing fields 5–7 (leave default/unspecified); recipients that still see old peers read SealedInner type as fallback for one release, then drop. Server comments already say ignore.

**Not doing now:** hard remove fields from proto (breaks old clients decoding? actually optional defaults ok — can leave reserved later).

---

### SM-B2 — Stale proto comment: “sealed ONLY for federation / local uses Envelope.sender”

**Status:** FIXED (2026-08-02)  
**Severity:** Low  
**Refs:** `shared/proto/core/envelope.proto` sealed section rewritten

Comments now describe local + federated sealed, dual transport transitional note, and deprecation of content_type/priority/ttl.

---

### SM-C1 — `MSG_STEALTH_TOKEN_POLICY=warn` default

**Status:** ACCEPTED for launch (prior audit P1-9); track to `enforce`  
**Severity:** Medium (anti-abuse), not anonymity  
**Refs:** `token_redeem.rs`, `fail_open.rs`, runbook

Under `warn`, missing/invalid/double-spent tokens still deliver. Empty wallet degrades abuse resistance only (invariant preserved: never force identified send).

**Gate to enforce:** healthy `construct_stealth_token_*` metrics + client replenish-and-retry proven; then flip compose default.

---

### SM-C2 — Token encryption + issuer key configuration surface

**Status:** MONITOR  
**Severity:** High if misconfigured  
**Refs:** `secret_hygiene`, runbook §6; `TOKEN_ISSUER_KEY` hex vs `SERVER_SIGNING_KEY` base64

- Absent keys → `NotConfigured` redeem result; under `warn` still delivers.  
- Malformed keys fail boot (good).  
- Confirm prod always has both issuer + token-enc static secret on messaging.

---

### SM-D1 — User blocklist ineffective on sealed path

**Status:** OPEN  
**Severity:** Medium (safety / abuse)  
**Refs:** `core.rs` block check requires parseable non-empty `sender_id`

Sealed design intentionally hides sender → server cannot enforce “recipient blocked sender” at ingress. Client-side ignore after unseal is the correct privacy-preserving control; document that server block is identified-path only.

**Do not “fix” by requiring sender on sealed.**

---

### SM-D2 — Fail-open on sealed anti-abuse Redis paths

**Status:** ACCEPTED (prior audit P1-1) + metered  
**Severity:** Policy  
**Controls:** `sealed_ip`, `delivery_tag`, PP `redis_error` under warn

Under Redis outage: IP RL and tag replay skip; under warn, PP errors allow. Document launch acceptance; alerts already in Grafana.

---

### SM-E1 — Server reassigns sealed `message_id` (good)

**Status:** POSITIVE — do not regress  
**Refs:** `dispatch_sealed_sender` generates new UUID; server-influence-minimization

E2E identity must live inside encrypted payload (KNST / MessageContent). Clients must not treat envelope id as semantic.

---

### SM-E2 — At-rest sealed hides sender; delivery paths strip sender

**Status:** POSITIVE — do not regress  
**Refs:** `from_sealed_sender`; `GetPendingMessages` / stream conversion; empty conversation_id on outbound proto

---

### SM-E3 — Delivery receipts must not re-link pairs

**Status:** FIXED client/server decision 2026-08-02  
**Refs:** `stream-delivery-receipt-deanonymized-sealed-sender.md`

Plaintext stream receipts carrying original sender id would undo sealed anonymity. Confirm no residual server path logs unhashed receipt routing pairs; E2E receipts only.

---

### SM-F1 — Connection / timing / size correlation

**Status:** OPEN (long-term)  
**Severity:** High against sophisticated operator  

Even with perfect sealed application layer:

- Shared H2/QUIC connection with authenticated RPCs correlates identity.  
- Message size + timing + recipient graph.  
- `sealed_ip` rate-limit key ties sends to IP.  
- APNs wake after sealed delivery is a side channel (recipient-side only; weaker).

Mitigations are transport/Veil/padding — not all server app bugs. Track as threat model, not single PR.

---

### SM-F2 — Protocol vs transport independence checklist

**Status:** IN PROGRESS (framework)  

Apply to every messaging feature:

| # | Check | Pass criteria |
|---|-------|---------------|
| 1 | Identity of message/edit/reply/reaction | Sender-generated id **inside** ciphertext only |
| 2 | No load-bearing outer envelope field | `conversation_id`, `content_type`, `edits_message_id`, timestamps not E2E-semantic |
| 3 | Sealed + identified delivery parity | Same client semantics whether path is sealed or not |
| 4 | Server may reassign transport ids | Clients ignore envelope message_id for E2E |
| 5 | Failure never forces deanonymizing fallback | PP/network errors → retry sealed or fail visible |
| 6 | Logs | Prefer hashed ids (`log_safe_id`); no raw pair dumps |

Prior audit closed auth/header trust; this audit owns items 1–6 for **messaging content**.

---

## Positive findings (do not regress)

- `SendSealedMessage` deliberately skips Bearer (Phase 2).  
- `from_sealed_sender` empty `sender_id` is load-bearing for receipt maps and block path.  
- PP redeem is typed (`TokenRejected` → `privacy_pass:{label}`); client must not downgrade.  
- Delivery-tag exact + seen caches; silent success on replay.  
- Blind push: no conversation_id.  
- Federation forwards `sealed_inner` opaquely on home server path.  
- Prior pre-publish auth fixes: Bearer required on user RPCs; no client header trust alone.

---

## Phase plan

```
Phase 0  Inventory + knowledge table              ← done 2026-08-02 (this file)
Phase 0b Server test matrix (unit+Redis/PG)        ← done 2026-08-02 (sealed_matrix_tests)
Phase 1  Dual-path sunset decision (A1/A2)         ← product + metrics (blocked on client flag)
Phase 2  SealedInner metadata minimization (B1/B2) ← proto comments done; client producers next
Phase 3  PP enforce readiness (C1/C2)              ← metrics + runbook flip
Phase 4  Safety docs: blocks/receipts on sealed    ← D1, E3 verification
Phase 5  Correlation / transport independence       ← F1/F2 threat write-up
Phase 6  Tests + smoke: sealed unauth, PP reject,  ← no sender in Redis/DB
         no delivery_pending for sealed
```

---

## Test matrix (Phase 1 — server-owned) — 2026-08-02

Infra: `docker-compose -f ops/docker-compose.dev.yml up -d`  
(Postgres `postgres:password@localhost/construct_test`, Redis `localhost:6379`).

```bash
cargo test -p construct-message from_sealed_sender
cargo test -p messaging-service sealed_matrix -- --nocapture
cargo test -p messaging-service all_token_rejected convert_sealed legacy_sealed
```

| ID | Invariant | Kind | Status | Where |
|----|-----------|------|--------|-------|
| U1 | `from_sealed_sender` → empty `sender_id`, sealed flag | unit | ✅ | `construct-message` types tests |
| U2 | proto convert hides sender + empty conversation_id | unit | ✅ | `messaging-service` main tests |
| U3 | all PP labels → `FailedPrecondition` `privacy_pass:{label}` | unit | ✅ | `grpc.rs` sealed_dispatch_error_tests |
| U4 | legacy sealed-on-SendMessage requires auth | unit | ✅ | `grpc.rs` (pre-existing) |
| I1 | warn + no token → deliver + stream XADD | integration | ✅ | `sealed_matrix_tests` |
| I2 | enforce + missing token → `TokenRejected{missing_token}` | integration | ✅ | `sealed_matrix_tests` |
| I3 | valid token once OK; same nonce → `double_spent` | integration | ✅ | `sealed_matrix_tests` |
| I4 | delivery_tag replay → success, no second stream entry | integration | ✅ | `sealed_matrix_tests` |
| I5 | no `receipt:sender:{id}` / no `delivery_pending` for sealed | integration | ✅ | `sealed_matrix_tests` |
| I6 | offline stream contains sealed envelope | integration | ✅ | `sealed_matrix_tests` |
| S1 | smoke `SendSealedMessage` without Bearer | smoke | ⏳ | needs running messaging binary |
| S3 | smoke sealed-on-`SendMessage` without Bearer → unauth | smoke | ⏳ | extend `scripts/smoke-test.sh` |

Integration tests **skip** (pass empty) if Redis/Postgres unreachable — no hard fail without infra.

---

## Recommended next concrete work

1. **Client (parallel, owns T2):** validate then flip `sealedSenderUnauthenticatedTransport` / `SEALED_UNAUTHENTICATED_TRANSPORT` — server already ready. Until then, keep dual ingress.  
2. **Server test matrix Phase 1:** ✅ unit + Redis/Postgres integration (2026-08-02). Remaining: smoke S1/S3 against compose stack.  
3. **Proto:** ✅ comments + deprecation notes (2026-08-02). **Client follow-up:** stop writing SealedInner `content_type`/`priority`/`ttl`; put **1-byte kind in E2E plaintext** (or rely on binary `SessionControl` / content protos after decrypt); one-release SealedInner fallback.  
4. **Confirm prod:** `MSG_STEALTH_TOKEN_POLICY`, `TOKEN_ISSUER_KEY`, token-enc secret; Grafana stealth panels.  
5. **After client unauth ON + traffic metrics:** server PR to reject sealed-on-`SendMessage` (identified-only exclusions remain).

---

## Residual ops from prior audit (not sealed-specific)

- [ ] Live `./scripts/smoke-test.sh` against deployed smoke/prod  
- [ ] Grafana dashboard provision reload for fail-open panels  

---

## Appendix — server knowledge one-pager

```
Identified SendMessage
  server sees:  sender ──► recipient  + type + size + time + auth
  at rest:      full pair

Legacy sealed on SendMessage (auth)
  server sees:  sender (JWT) ──► recipient + sealed blob + time
  at rest:      recipient + sealed blob (no sender field)

SendSealedMessage (unauth) + PP
  server sees:  ??? ──► recipient + sealed blob + time + IP + token spend
  at rest:      recipient + sealed blob
  anonymity:    real-time vs curious server ≈ yes (modulo F1 correlation)
  anti-abuse:   token + IP + tag (enforce required for strong spam posture)
```
