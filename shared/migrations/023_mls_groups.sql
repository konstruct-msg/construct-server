-- ============================================================================
-- Migration 023: MLS Group Infrastructure
-- ============================================================================
--
-- Implements server-side storage for RFC 9420 (MLS) group messaging.
--
-- Privacy model:
--   - Server stores ENCRYPTED ratchet tree (group public state blob)
--   - Server does NOT store plaintext member list or message content
--   - group_members maps device_id → group_id for routing/auth only
--     (accepted tradeoff: needed for delivery and access control)
--   - Former members are HARD-DELETED from group_members (no history)
--   - Messages auto-deleted after retention period (default 90 days)
--   - Invites: encrypted Welcome blob, only invitee can decrypt
--   - Consent: client acceptance_signature stored to prove voluntary join
--
-- Tables created:
--   mls_groups          - Group metadata and encrypted ratchet tree
--   group_members       - Device membership for routing (no history)
--   group_messages      - Encrypted MLS ApplicationMessages with TTL
--   group_commits       - MLS Commits for state sync (offline catch-up)
--   group_invites       - Pending encrypted Welcome messages
--   group_key_packages  - MLS KeyPackages for group invitations
--   group_admins        - Admin role assignments
--
-- ============================================================================

-- ============================================================================
-- mls_groups: Core group state
-- ============================================================================

CREATE TABLE mls_groups (
    -- Client-generated UUID (not sequential to prevent enumeration)
    group_id UUID PRIMARY KEY,

    -- Current MLS epoch (increments on every Commit)
    -- Used to detect stale clients and validate SubmitCommit
    epoch BIGINT NOT NULL DEFAULT 0,

    -- Encrypted MLS ratchet tree (current state)
    -- Opaque to server: contains all member public keys in tree structure
    -- Updated atomically on every SubmitCommit
    ratchet_tree BYTEA NOT NULL,

    -- Group metadata encrypted with group epoch key
    -- Contains: name, description, avatar_hash
    -- Server cannot read; only group members can decrypt
    encrypted_group_context BYTEA NOT NULL,

    -- Maximum members (1-2048, enforced on InviteToGroup)
    max_members SMALLINT NOT NULL DEFAULT 2048
        CHECK (max_members BETWEEN 1 AND 2048),

    -- Message retention in days (default 90, max 365)
    -- Messages older than this are deleted by cleanup job
    message_retention_days SMALLINT NOT NULL DEFAULT 90
        CHECK (message_retention_days BETWEEN 1 AND 365),

    -- Thread support flag (controls thread_id indexing on messages)
    threads_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Set when admin calls DissolveGroup; group becomes read-only then deleted
    dissolved_at TIMESTAMPTZ,

    -- Tracks when last TTL cleanup ran (for client info via GetGroupState)
    messages_deleted_before TIMESTAMPTZ
);

CREATE INDEX idx_mls_groups_active ON mls_groups(group_id)
    WHERE dissolved_at IS NULL;

-- ============================================================================
-- group_members: Device ↔ Group mapping (routing/auth only)
-- ============================================================================
-- NOTE: No soft-delete. When a member leaves or is removed, row is DELETED.
-- This prevents membership history from being stored server-side.
-- The ratchet_tree update (via SubmitCommit) is the canonical record.

CREATE TABLE group_members (
    group_id  UUID         NOT NULL REFERENCES mls_groups(group_id)  ON DELETE CASCADE,
    device_id VARCHAR(32)  NOT NULL REFERENCES devices(device_id)    ON DELETE CASCADE,

    -- Position in the MLS ratchet tree leaf array (0-based)
    -- Required by admin for targeted Remove Proposals
    leaf_index INT NOT NULL,

    -- Cryptographic proof that this device explicitly accepted the invite
    -- Ed25519 signature over "CONSTRUCT_GROUP_JOIN:{group_id}:{invite_id}:{ts}"
    -- NULL only for group creator (they don't need to accept their own creation)
    acceptance_signature BYTEA,

    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (group_id, device_id)
);

CREATE INDEX idx_group_members_device ON group_members(device_id);

-- ============================================================================
-- group_messages: Encrypted MLS ApplicationMessages
-- ============================================================================

CREATE TABLE group_messages (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    group_id UUID NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,

    -- MLS epoch when message was sent (for client key ratcheting)
    epoch BIGINT NOT NULL,

    -- MLS ApplicationMessage ciphertext (fully E2EE, server cannot read)
    mls_ciphertext BYTEA NOT NULL,

    -- Monotonically increasing per-group sequence number
    -- Used as pagination cursor (FetchGroupMessages after_sequence)
    sequence_number BIGINT NOT NULL,

    -- Optional thread grouping (NULL = top-level message)
    -- Feature gated by mls_groups.threads_enabled
    thread_id UUID,

    sent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Computed from sent_at + group retention_days at insert time
    -- Background job deletes WHERE expires_at < NOW()
    expires_at TIMESTAMPTZ NOT NULL
);

-- Sequence-based pagination (primary fetch pattern)
CREATE INDEX idx_group_messages_seq
    ON group_messages(group_id, sequence_number);

-- TTL cleanup (background job)
CREATE INDEX idx_group_messages_expires
    ON group_messages(expires_at);

-- Thread fetching (future use)
CREATE INDEX idx_group_messages_thread
    ON group_messages(group_id, thread_id)
    WHERE thread_id IS NOT NULL;

-- Enforce monotonic sequence per group
CREATE UNIQUE INDEX idx_group_messages_unique_seq
    ON group_messages(group_id, sequence_number);

-- Sequence generator function (atomic increment per group)
CREATE SEQUENCE group_message_seq_global START 1;

-- ============================================================================
-- group_commits: MLS Commits for offline state sync
-- ============================================================================
-- Clients use FetchCommits to catch up after being offline.
-- Kept for COMMIT_RETENTION_DAYS (30) to allow offline sync.
-- After that, offline client must fetch full ratchet_tree from mls_groups.

CREATE TABLE group_commits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    group_id   UUID    NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
    epoch_from BIGINT  NOT NULL,
    epoch_to   BIGINT  NOT NULL,

    -- MLS Commit message (encrypted)
    mls_commit BYTEA NOT NULL,

    -- Ratchet tree state AFTER applying this commit
    -- Stored to allow catch-up without replaying all commits
    ratchet_tree_snapshot BYTEA NOT NULL,

    committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Commits expire after 30 days; client must do full resync after that
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),

    -- Epoch must strictly increment
    CONSTRAINT chk_epoch_increment CHECK (epoch_to = epoch_from + 1)
);

CREATE INDEX idx_group_commits_epoch   ON group_commits(group_id, epoch_from);
CREATE INDEX idx_group_commits_expires ON group_commits(expires_at);

-- ============================================================================
-- group_invites: Pending encrypted Welcome messages
-- ============================================================================
-- Invite is created by InviteToGroup, consumed by AcceptGroupInvite/Decline.
-- Row is DELETED after accept or decline (no invite history stored).

CREATE TABLE group_invites (
    invite_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    group_id        UUID         NOT NULL REFERENCES mls_groups(group_id)  ON DELETE CASCADE,
    target_device_id VARCHAR(32) NOT NULL REFERENCES devices(device_id)    ON DELETE CASCADE,

    -- MLS Welcome message encrypted with target's KeyPackage
    -- Only target device can decrypt this
    mls_welcome BYTEA NOT NULL,

    -- KeyPackage reference (hash) used to construct this Welcome
    key_package_ref BYTEA NOT NULL,

    -- Epoch at time of invite (client validates on accept)
    epoch BIGINT NOT NULL,

    invited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Max 7 days; expired invites cleaned by background job
    expires_at TIMESTAMPTZ NOT NULL
        CHECK (expires_at <= invited_at + INTERVAL '7 days'),

    -- One pending invite per device per group at a time
    UNIQUE (group_id, target_device_id)
);

CREATE INDEX idx_group_invites_device  ON group_invites(target_device_id);
CREATE INDEX idx_group_invites_expires ON group_invites(expires_at);

-- ============================================================================
-- group_key_packages: MLS KeyPackages (for group invitations)
-- ============================================================================
-- Analogous to one_time_prekeys but for MLS groups.
-- Each KeyPackage is single-use: consumed atomically when admin invites someone.

CREATE TABLE group_key_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id   UUID        NOT NULL REFERENCES users(id)             ON DELETE CASCADE,
    device_id VARCHAR(32) NOT NULL REFERENCES devices(device_id)    ON DELETE CASCADE,

    -- MLS KeyPackage blob (RFC 9420 §10)
    -- Opaque to server; used by inviting admin to construct Welcome
    key_package BYTEA NOT NULL,

    -- SHA-256 hash of key_package for cross-referencing with Welcome/Commit
    key_package_ref BYTEA NOT NULL UNIQUE,

    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- KeyPackages expire after 30 days; client should refresh periodically
    expires_at TIMESTAMPTZ NOT NULL
        DEFAULT (NOW() + INTERVAL '30 days')
);

-- Fetch available (non-expired) KeyPackages for a user
CREATE INDEX idx_group_key_packages_user
    ON group_key_packages(user_id, expires_at DESC);

CREATE INDEX idx_group_key_packages_device
    ON group_key_packages(device_id);

CREATE INDEX idx_group_key_packages_expires
    ON group_key_packages(expires_at);

-- ============================================================================
-- group_admins: Admin role assignments
-- ============================================================================

CREATE TABLE group_admins (
    group_id  UUID         NOT NULL REFERENCES mls_groups(group_id)  ON DELETE CASCADE,
    device_id VARCHAR(32)  NOT NULL REFERENCES devices(device_id)    ON DELETE CASCADE,

    -- 1 = FULL (invite, remove, delegate, dissolve)
    -- 2 = MODERATOR (remove only)
    role SMALLINT NOT NULL DEFAULT 1
        CHECK (role IN (1, 2)),

    -- True for the device that called CreateGroup
    -- Creator admin cannot be stripped (only self-resign)
    is_creator BOOLEAN NOT NULL DEFAULT FALSE,

    -- Encrypted admin capabilities token
    -- Encrypted with this admin device's identity key
    encrypted_admin_token BYTEA,

    -- Who granted this admin role (NULL for creator)
    granted_by_device_id VARCHAR(32) REFERENCES devices(device_id) ON DELETE SET NULL,

    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (group_id, device_id)
);

CREATE INDEX idx_group_admins_device ON group_admins(device_id);

-- ============================================================================
-- Cleanup function: delete expired messages, invites, commits, key packages
-- ============================================================================
-- Call periodically (e.g., daily via pg_cron or application scheduler)

CREATE OR REPLACE FUNCTION cleanup_mls_expired() RETURNS void
    LANGUAGE plpgsql AS $$
BEGIN
    -- Delete expired messages
    DELETE FROM group_messages WHERE expires_at < NOW();

    -- Delete expired commits (clients must do full resync after this)
    DELETE FROM group_commits WHERE expires_at < NOW();

    -- Delete expired invites
    DELETE FROM group_invites WHERE expires_at < NOW();

    -- Delete expired KeyPackages
    DELETE FROM group_key_packages WHERE expires_at < NOW();

    -- Update messages_deleted_before on affected groups
    UPDATE mls_groups
    SET messages_deleted_before = NOW()
    WHERE group_id IN (
        SELECT DISTINCT group_id FROM group_messages WHERE expires_at < NOW()
    );

    -- Hard-delete dissolved groups older than 24h
    DELETE FROM mls_groups
    WHERE dissolved_at IS NOT NULL
      AND dissolved_at < NOW() - INTERVAL '24 hours';
END;
$$;
