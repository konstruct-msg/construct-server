# MLS Groups & Channels — Implementation Roadmap

> **Source of truth:** `/Users/maximeliseyev/Documents/Konstruct/03_Server_Backend/Refactoring/GROUP_CHANNEL_SPEC.md`  
> **Last synced:** 2026-04-29  
> **Status:** Track implementation progress against the specification

---

## Legend

- `⬜` — Not started
- `🔄` — In progress (active development)
- `✅` — Complete (merged to main, tested)
- `⏸️` — Blocked (dependency on other phase)
- `❓` — Needs clarification/decision

---

## Phase 0: Foundation ✅ COMPLETE

### Proto Extensions (Migration 040)
- [x] Add `topic_id` to group messages
- [x] Topics RPCs in `mls_service.proto`
- [x] Invite Links RPCs in `mls_service.proto`
- [x] `SetGroupInvitePolicy` RPC

### Database (Migration 040)
- [x] `group_topics` table
- [x] `group_invite_links` table
- [x] `users.allow_group_invite` column (BOOLEAN DEFAULT FALSE)

### Notes
- Commit: `8abcd3b`
- All schema changes backward compatible

---

## Phase 1: KeyPackage Management ✅ COMPLETE

### Implementation
- [x] `PublishKeyPackage` — bulk upload with SHA-256 dedup
- [x] `ConsumeKeyPackage` — atomic DELETE-RETURNING
- [x] `GetKeyPackageCount` — with `recommended_minimum=20` and `cannot_be_invited` flag

### Database
- [x] `group_key_packages` table (Migration 023)
- [x] 30-day TTL on KeyPackages
- [x] Indexes: user_id, device_id, expires_at

### Code Location
- `mls-service/src/main.rs` lines 175-364

### Notes
- Commit: `4f27152`
- KeyPackages are single-use (consumed on invite)
- Client should maintain ≥20 KeyPackages at all times

---

## Phase 2: Group Lifecycle ✅ COMPLETE

### RPC Implementation
- [x] `CreateGroup` — initialize MLS group, caller becomes creator/admin
  - [x] Validate `initial_ratchet_tree` (non-empty)
  - [x] Insert into `mls_groups` with epoch=0
  - [x] Insert creator into `group_admins` (is_creator=true, role=FULL)
  - [x] Return group_id, epoch=0, created_at
  
- [x] `GetGroupState` — fetch ratchet tree + pending commits
  - [x] Verify caller is member
  - [x] If `known_epoch` provided: return commits since that epoch
  - [x] If no `known_epoch` or gap too large: return full `ratchet_tree`
  - [x] Return current `GroupSettings`
  
- [x] `DissolveGroup` — soft-delete with admin proof
  - [x] Validate Ed25519 signature over `"CONSTRUCT_DISSOLVE_GROUP:{group_id}:{timestamp}"`
  - [x] Check admin rights (creator or delegated admin)
  - [x] Set `dissolved_at = NOW()`
  - [ ] Push notification to all members via stream (deferred to Phase 5+)
  - [x] Hard-delete after 24h (cleanup job)

### Database
- [x] `mls_groups` table (Migration 023) — already exists
- [x] `group_admins` table — already exists
- [x] Verify `group_members` FK constraints work correctly

### Tests
- [x] Create group with valid initial ratchet tree
- [x] Create group with invalid ratchet tree → error
- [x] Get state as member vs non-member → auth check
- [ ] Get state with stale epoch → receive commits (needs integration test with commits)
- [x] Dissolve with valid admin proof
- [x] Dissolve with invalid signature → error
- [x] Dissolve as non-admin → error
- [x] Dissolve with expired timestamp → error
- [x] Dissolve already dissolved group → error

### Code Location
- `mls-service/src/main.rs` lines 57-430
- Helper functions: `verify_admin_proof`, `check_group_admin`, `check_group_member`
- Tests: `mls-service/src/main.rs` lines 895-1250

### Dependencies Added
- `ed25519-dalek` 2.1 — Ed25519 signature verification
- `rand` 0.8 — for test key generation
- `hex` 0.4 — for device_id generation in tests

### Notes
- Admin proof pattern: Ed25519 signature with ±5 min timestamp window
- Device verifying key loaded from `devices.verifying_key` column
- User impersonation check: `device_id` must belong to `x-user-id`

---

## Phase 3: Membership Management ✅ COMPLETE

### RPC Implementation
- [x] `InviteToGroup` — admin sends encrypted Welcome
  - [x] Verify admin rights
  - [x] Look up target device_id from KeyPackage ref
  - [x] Store `mls_welcome` in `group_invites` with 7-day expiry
  - [x] Check max_members limit
  - [x] Prevent duplicate pending invites
  - [x] Return invite_id, expires_at
  
- [x] `AcceptGroupInvite` — explicit consent with signature
  - [x] Verify invite exists and not expired
  - [x] Verify invite belongs to calling device
  - [x] Validate Ed25519 signature over `"CONSTRUCT_GROUP_JOIN:{group_id}:{invite_id}:{timestamp}"`
  - [x] Insert into `group_members` with `acceptance_signature`
  - [x] Assign sequential leaf_index
  - [x] Delete invite row (hard delete, no history)
  - [x] Return success + new epoch
  
- [x] `DeclineGroupInvite` — delete invite
  - [x] Verify invite belongs to caller
  - [x] Hard delete invite row
  
- [x] `GetPendingInvites` — list pending Welcomes
  - [x] Query `group_invites` by `target_device_id`
  - [x] Cursor-based pagination
  - [x] Filter expired invites
  
- [x] `LeaveGroup` — self-removal
  - [x] Verify membership
  - [x] Creator cannot leave (must dissolve instead)
  - [x] Hard delete from `group_members`
  - [x] Also remove from `group_admins`
  
- [x] `RemoveMember` — admin removal
  - [x] Verify admin rights
  - [x] Validate Ed25519 signature over `"CONSTRUCT_REMOVE_MEMBER:{group_id}:{target_device_id}:{timestamp}"`
  - [x] Cannot remove creator
  - [x] Hard delete from `group_members`
  - [x] Also remove from `group_admins`

### Database
- [x] `group_invites` table — already exists (Migration 023)
- [x] `group_members` table — already exists (Migration 023)
- [x] `group_key_packages` table — used for KeyPackage lookup

### Privacy Requirements
- [x] No membership history stored (hard delete on leave/remove)
- [x] Acceptance signature stored as consent proof
- [x] Former members leave no trace server-side

### Tests
- [x] InviteToGroup: success, non-admin error
- [x] AcceptGroupInvite: success, wrong device error
- [x] DeclineGroupInvite: success, wrong device error
- [x] GetPendingInvites: success with pagination
- [x] LeaveGroup: success, creator cannot leave error
- [x] RemoveMember: success, cannot remove creator error

### Code Location
- `mls-service/src/main.rs` lines 496-1137
- Helper: `publish_test_key_package` for tests

### Notes
- Two-step join is mandatory (no silent adds)
- Invite looked up via key_package_ref SHA-256 hash
- Creator cannot leave — must dissolve group instead
- Tests require PostgreSQL with migrations applied
- `allow_group_invite` user setting respected
- Invite links bypass discovery but still require two-step join

---

## Phase 4: Admin & MLS Sync ✅ COMPLETE

### RPC Implementation
- [x] `DelegateAdmin` — grant admin/moderator role
  - [x] Verify current admin rights
  - [x] Validate signature
  - [x] Insert/update `group_admins` row
  - [x] Distribute encrypted admin token

- [x] `TransferOwnership` — transfer creator rights to another admin (double consent)
  - [x] Verify current caller is creator (`is_creator = true`)
  - [x] Verify target is current FULL admin (`role = 1`)
  - [x] Validate owner signature: `CONSTRUCT_TRANSFER_OWNERSHIP:{group_id}:{new_owner}:{timestamp}`
  - [x] Validate new owner acceptance: `CONSTRUCT_ACCEPT_OWNERSHIP:{group_id}:{previous_owner}:{timestamp}`
  - [x] Atomic transaction: set `is_creator = false` for old owner, `is_creator = true` for new owner
  - [x] Old owner retains FULL admin role (cannot be stripped)
  - [x] New owner cannot be stripped (only self-resign)
  
- [x] `SubmitCommit` — push MLS commit
  - [x] Verify membership
  - [x] Validate epoch continuity (CAS: SELECT FOR UPDATE)
  - [x] Update `mls_groups.ratchet_tree`
  - [x] Increment epoch
  - [x] Store commit in `group_commits` with 30-day TTL
  - [x] Process Welcome deliveries validation
  
- [x] `FetchCommits` — stream commits since epoch
  - [x] Verify membership
  - [x] Stream all commits from `since_epoch` to current
  - [x] Include `ratchet_tree` snapshot in each commit

### Database
- [x] `group_commits` table — already exists (Migration 023)
- [x] `group_admins.is_creator` — already exists

### Tests
- [x] DelegateAdmin: success, non-admin error
- [x] TransferOwnership: success (both signatures), non-creator error
- [x] SubmitCommit: success, epoch mismatch (ABORTED), non-member error
- [x] FetchCommits: success with 3 commits, non-member error

### Code Location
- `mls-service/src/main.rs` lines 1139-1586
- Uses `futures-util::stream` for FetchCommits streaming
- Atomic epoch CAS via `SELECT ... FOR UPDATE`

### Dependencies Added
- `futures-util` 0.3 — streaming support for FetchCommits

### Notes
- SubmitCommit uses SELECT FOR UPDATE for epoch CAS (prevents race conditions)
- FetchCommits returns `Result<CommitEnvelope, Status>` stream
- DelegateAdmin supports encrypted_admin_token (optional)
- TransferOwnership requires double consent (owner + new owner signatures)

---

## Phase 5: Group Messaging ⬜ PLANNED

### RPC Implementation
- [ ] `SendGroupMessage` — store encrypted MLS ApplicationMessage
  - [ ] Verify membership
  - [ ] Validate epoch matches current
  - [ ] Generate sequence_number (atomic per group)
  - [ ] Calculate `expires_at` from retention_days
  - [ ] Insert into `group_messages`
  - [ ] Fan-out to Redis stream `group:{group_id}:{topic_id}`
  
- [ ] `FetchGroupMessages` — paginated pull
  - [ ] Verify membership
  - [ ] Query with `after_sequence` cursor
  - [ ] Filter by optional `topic_id`
  - [ ] Return paginated with next cursor
  
- [ ] `MessageStream` — bidirectional real-time
  - [ ] WebSocket-like over gRPC streaming
  - [ ] Subscribe to multiple groups
  - [ ] Heartbeat/ack for liveness
  - [ ] Push new messages, commits, invites, dissolve notices

### Redis Streams
- [ ] Design stream naming: `group:{group_id}:*`
- [ ] XREAD with cursor persistence on client
- [ ] One write, N readers (O(1) fan-out)

### Delivery Optimization
- [ ] Shared Redis stream vs delivery-worker
- [ ] No delivery-worker involvement (clients pull)
- [ ] Compare to DM delivery (which uses delivery-worker)

### Tests Needed
- [ ] Send message as member → success
- [ ] Send message as non-member → NOT_MEMBER error
- [ ] Send with epoch mismatch → EPOCH_MISMATCH error
- [ ] Fetch messages paginated
- [ ] Fetch by topic filter
- [ ] Real-time stream receives new messages
- [ ] Stream reconnect with cursor
- [ ] 1000 messages, verify sequence monotonic
- [ ] TTL cleanup deletes old messages

### Notes
- DM uses delivery-worker (1 write per device)
- Groups use shared stream (1 write total)
- Sequence numbers are monotonic per group

---

## Phase 6: Topics & Invite Links ⬜ PLANNED

### Topics Implementation
- [ ] `CreateTopic` — admin creates topic
  - [ ] Validate admin rights
  - [ ] Check < 50 topics per group
  - [ ] Store `encrypted_name` (opaque bytes)
  - [ ] Set `sort_order`
  
- [ ] `ListTopics` — list active/archived
  - [ ] Verify membership
  - [ ] Return topics with decrypted names (client-side)
  
- [ ] `ArchiveTopic` — hide from new members
  - [ ] Validate admin rights
  - [ ] Set `archived_at`

### Invite Links Implementation
- [ ] `CreateInviteLink` — generate token
  - [ ] Validate admin rights
  - [ ] Generate 32-char hex token
  - [ ] Optional `max_uses`, `expires_at`
  
- [ ] `RevokeInviteLink` — invalidate token
  - [ ] Validate admin rights
  - [ ] Set `revoked_at`
  
- [ ] `ResolveInviteLink` — public resolution
  - [ ] No auth required
  - [ ] Return `{group_id, member_count, valid}`
  - [ ] Check uses count, expiry, revoked

### Database
- [x] `group_topics` table — already exists
- [x] `group_invite_links` table — already exists

### Tests Needed
- [ ] Create topic as admin
- [ ] Create topic as member → NOT_ADMIN error
- [ ] Create 51st topic → limit error
- [ ] List topics include encrypted names
- [ ] Archive topic → not in default list
- [ ] Create invite link with max_uses
- [ ] Use invite link up to max → then invalid
- [ ] Resolve valid link
- [ ] Resolve expired link → invalid
- [ ] Revoke link → subsequent resolves invalid

### Notes
- Topics are routing labels, not separate MLS groups
- All topics share same ratchet tree and epoch
- Invite links don't bypass two-step join

---

## Phase 7: Infrastructure & Cleanup ⬜ PLANNED

### Background Jobs
- [ ] `cleanup_mls_expired()` PostgreSQL function
  - [ ] Delete expired messages (90d default)
  - [ ] Delete expired commits (30d)
  - [ ] Delete expired invites (7d)
  - [ ] Delete expired KeyPackages (30d)
  - [ ] Hard-delete dissolved groups (>24h)
  
- [ ] Scheduler (pg_cron or application)
  - [ ] Daily cleanup job
  - [ ] Metrics/logging

### Notifications
- [ ] Push notifications for invites
- [ ] Push notifications for new messages (respect quiet hours)
- [ ] Dissolve group notification

### Rate Limiting
- [ ] Group creation rate limit
- [ ] Message send rate limit per group
- [ ] Invite rate limit

### Metrics
- [ ] Groups created/deleted
- [ ] Messages sent per group
- [ ] Average group size
- [ ] KeyPackage replenish rate

### Tests Needed
- [ ] Cleanup job deletes expired data
- [ ] Cleanup updates `messages_deleted_before`
- [ ] Rate limits enforced
- [ ] Push notifications delivered

---

## Phase C0: Channels Schema ⬜ PLANNED

### Proto
- [ ] Create `channel_service.proto`
  - [ ] Channel lifecycle RPCs
  - [ ] Subscription RPCs
  - [ ] Post RPCs
  - [ ] Comment group RPCs (`GetCommentGroup`)
  - [ ] Invite link RPCs

### Database (Migration 041)
- [ ] `channels` table
  - `channel_id` UUID PRIMARY KEY
  - `visibility` ENUM('PUBLIC', 'PRIVATE')
  - `encrypted_metadata` BYTEA
  - `created_at`, `updated_at`
  
- [ ] `channel_subscribers` table
  - `(channel_id, device_id)` PK
  - `subscribed_at`, `role`
  
- [ ] `channel_posts` table
  - `post_id` UUID PRIMARY KEY
  - `channel_id` FK
  - `sequence_number` BIGINT
  - `ciphertext` BYTEA (Sender Key encrypted)
  - `sent_at`, `expires_at`
  
- [ ] `channel_sender_keys` table
  - `(channel_id, device_id)` PK
  - `encrypted_sender_key` BYTEA
  - `distributed_at`
  
- [ ] `channel_invite_links` table
  - `token` VARCHAR(32) PK
  - `channel_id` FK
  - `max_uses`, `use_count`
  - `expires_at`, `revoked_at`
  
- [ ] `channel_post_comment_groups` table
  - `post_id` UUID PK
  - `group_id` UUID FK → `mls_groups`

### New Service
- [ ] Create `channel-service/` directory
- [ ] `Cargo.toml` with dependencies
- [ ] `src/main.rs` with stub RPCs
- [ ] Port: 50061 (next available after signaling 50060)

---

## Phase C1: Channels Core ⬜ PLANNED

### RPC Implementation
- [ ] `CreateChannel`
  - [ ] PUBLIC or PRIVATE visibility
  - [ ] Owner becomes first admin
  
- [ ] `GetChannel` — public metadata
  - [ ] No auth required for PUBLIC
  - [ ] Private requires membership
  
- [ ] `SetChannelVisibility` — owner only
  - [ ] Toggle PUBLIC/PRIVATE
  
- [ ] `Subscribe` — instant subscribe
  - [ ] PUBLIC: anyone
  - [ ] PRIVATE: invite link required
  - [ ] Distribute encrypted Sender Key
  - [ ] Add to `channel_subscribers`
  
- [ ] `Unsubscribe` — instant leave
  - [ ] Remove from subscribers
  - [ ] (Optional) rotate Sender Key
  
- [ ] `PublishPost` — admin only
  - [ ] Encrypt with Sender Key
  - [ ] Store ciphertext
  - [ ] Fan-out to Redis stream
  - [ ] Generate sequence number
  
- [ ] `ListPosts` — paginated
  - [ ] Verify subscription
  - [ ] Cursor-based pagination

### Sender Key Management
- [ ] Generate Sender Key (admin)
- [ ] Encrypt per subscriber (using what key?)
- [ ] Distribute on subscribe
- [ ] Rotation on subscriber revocation

### Redis Streams
- [ ] Channel stream naming: `channel:{channel_id}`
- [ ] Broadcast to all subscribers

### Tests Needed
- [ ] Create PUBLIC channel
- [ ] Create PRIVATE channel
- [ ] Subscribe to PUBLIC (no auth)
- [ ] Subscribe to PRIVATE without link → error
- [ ] Receive Sender Key on subscribe
- [ ] Publish post as admin
- [ ] Publish post as subscriber → error
- [ ] List posts paginated
- [ ] Unsubscribe removes from list

---

## Phase C2: Channel Comments ⬜ PLANNED

### RPC Implementation
- [ ] `GetCommentGroup` — get or create MLS mini-group
  - [ ] Check if `post_id` already has comment group
  - [ ] If not: call `CreateGroup` internally (first commenter)
  - [ ] Return `group_id`
  - [ ] Client then does standard MLS join flow

### Integration with Groups
- [ ] Reuse `mls-service` for comment groups
- [ ] Comment groups are regular MLS groups
- [ ] Max 500 participants enforced at application level
- [ ] Link table: `channel_post_comment_groups`

### Flow
```
First commenter:
  GetCommentGroup(post_id) → creates MLS group internally
  ConsumeKeyPackage() for self
  InviteToGroup() for self
  AcceptGroupInvite()
  SendGroupMessage(comment)

Subsequent commenters:
  GetCommentGroup(post_id) → returns existing group_id
  Standard MLS join flow
```

### Tests Needed
- [ ] First commenter creates comment group
- [ ] Subsequent commenters join existing
- [ ] Max 500 commentators enforced
- [ ] Comment encrypted (server cannot read)
- [ ] Non-subscriber cannot comment

---

## Cross-Cutting Concerns

### Client SDK Impact
- [ ] Update Swift/Kotlin SDK for Group RPCs
- [ ] KeyPackage replenish logic
- [ ] Epoch sync logic
- [ ] Topic subscription management

### Federation Considerations
- [ ] Cross-server groups: how to invite federated users?
- [ ] Cross-server channels: subscription across domains
- [ ] Mark as out-of-scope for Phase 2-5?

### Migration Path
- [ ] Existing 1:1 conversations remain unchanged
- [ ] Groups are new feature (no migration needed)
- [ ] Channels are new feature

### Performance Targets
- [ ] Group create: < 100ms
- [ ] Message send (2048 members): < 50ms
- [ ] Message delivery: < 100ms (fan-out via Redis)
- [ ] KeyPackage consume: < 20ms
- [ ] Channel subscribe (100k): < 50ms

---

## Open Questions

1. **Sender Key encryption:** How exactly is the Sender Key encrypted for each subscriber? Using their device identity key?

2. **Federation scope:** Are cross-server groups in scope for initial release?

3. **Notification content:** What data can be in push notifications for groups/channels? Encrypted or just "new message"?

4. **KeyPackage rotation:** Should server notify clients when KeyPackage count is low?

5. **Rate limiting:** What are the specific limits for each operation?

6. **Backup/restore:** How do groups appear in encrypted backups?

---

## Refactor Direction: DB Access Layer

- Move repeated MLS SQL from `mls-service` handlers/helpers into a typed `construct-db::mls` API.
- Keep business rules, request validation, auth checks, and gRPC `Status` mapping inside `mls-service`.
- Prefer explicit typed helper functions over a generic SQL builder/DSL.
- Start with repeated lookups/checks (`group membership`, `admin access`, `device ownership`, `group state flags`) before extracting complex transactional write flows.
- Keep transaction orchestration in the service layer until a write workflow becomes clearly reusable and atomic enough to merit a higher-level DB primitive.
- Current extracted surfaces include shared group state reads, invite reads/deletes, admin-role updates, member/admin removals, ownership transfer, and commit persistence helpers.
- Remaining raw MLS SQL is now concentrated in `create_group`, duplicate-sensitive invite/member inserts, and `key_packages`-specific handlers.

---

## Related Files

| File | Purpose |
|------|---------|
| `shared/proto/services/mls_service.proto` | Group RPC definitions |
| `shared/proto/messaging/mls.proto` | MLS message types |
| `shared/migrations/023_mls_groups.sql` | Core MLS schema |
| `shared/migrations/040_group_topics_invite_links.sql` | Topics + invite links schema |
| `mls-service/src/handlers/*.rs` | MLS business logic + RPC handlers |
| `mls-service/src/helpers.rs` | MLS service-level validation and DB-to-Status mapping |
| `crates/construct-db/src/mls.rs` | Shared typed MLS data-access helpers |
| `GROUP_CHANNEL_SPEC.md` (external) | Full specification |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-04-29 | Extended DB access refactor: moved MLS state/invite/admin/member/commit helpers into `construct-db::mls`; remaining raw SQL narrowed to create-group, duplicate-sensitive inserts, and key-packages |
| 2026-04-29 | Started DB access refactor: documenting and moving repeated MLS lookups into `construct-db::mls` |
| 2026-04-29 | Phase 4 complete: DelegateAdmin, TransferOwnership, SubmitCommit, FetchCommits |
| 2026-04-29 | Added TransferOwnership RPC to Phase 4 (proto + stub + spec) |
| 2026-04-29 | Phase 3 complete: InviteToGroup, AcceptGroupInvite, DeclineGroupInvite, GetPendingInvites, LeaveGroup, RemoveMember |
| 2026-04-29 | Phase 2 complete: CreateGroup, GetGroupState, DissolveGroup implemented with tests |
| 2026-04-29 | Initial roadmap creation based on GROUP_CHANNEL_SPEC.md |
