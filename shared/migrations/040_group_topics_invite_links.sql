-- ============================================================================
-- Migration 040: Group Topics, Invite Links, topic_id on messages, allow_group_invite
-- ============================================================================
--
-- Extends the MLS group infrastructure (migration 023) with:
--
--   group_topics        - Slack-style encrypted channels within a group
--   group_invite_links  - Token-based shareable join links (admin creates)
--   group_messages.topic_id  - Route messages to a specific topic
--   users.allow_group_invite - Privacy flag: who can send InviteToGroup
--
-- Privacy notes:
--   - topic encrypted_name: server stores ciphertext only (group epoch key encrypts)
--   - invite link: server knows token → group_id, NOT who clicks the link
--   - allow_group_invite default FALSE: opt-in model (privacy-first)
--
-- ============================================================================

-- ============================================================================
-- group_topics: Slack-style channels within a group
-- ============================================================================

CREATE TABLE group_topics (
    topic_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id   UUID NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,

    -- Topic name encrypted with current group epoch key.
    -- Server cannot read it; only group members can decrypt.
    encrypted_name BYTEA NOT NULL,

    -- Client-controlled sort order (0-based, max 49 = 50 topics per group)
    sort_order SMALLINT NOT NULL DEFAULT 0
        CHECK (sort_order BETWEEN 0 AND 49),

    -- Device that created this topic (for audit; NULL if device deleted)
    created_by_device_id VARCHAR(32) REFERENCES devices(device_id) ON DELETE SET NULL,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- NULL = active. Archived topics are hidden from new members; messages kept until TTL.
    archived_at TIMESTAMPTZ
);

-- Primary fetch: list active topics for a group
CREATE INDEX idx_group_topics_group_active
    ON group_topics(group_id, sort_order)
    WHERE archived_at IS NULL;

-- Enforce max 50 topics per group (active only)
-- Note: enforced at application level as well
CREATE INDEX idx_group_topics_group_all
    ON group_topics(group_id);

-- ============================================================================
-- group_invite_links: Token-based shareable join links
-- ============================================================================

CREATE TABLE group_invite_links (
    -- 32-char hex token (random, not sequential — prevents enumeration)
    token   VARCHAR(32) PRIMARY KEY,

    group_id UUID NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,

    -- Device that created this link (NULL if device deleted)
    created_by_device_id VARCHAR(32) REFERENCES devices(device_id) ON DELETE SET NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- NULL = unlimited uses
    max_uses  INTEGER CHECK (max_uses > 0),

    -- Incremented atomically on each successful ResolveInviteLink (leading to join)
    use_count INTEGER NOT NULL DEFAULT 0
        CHECK (use_count >= 0),

    -- NULL = no expiry
    expires_at TIMESTAMPTZ,

    -- Set by RevokeInviteLink; revoked links return invalid on resolve
    revoked_at TIMESTAMPTZ
);

-- Active links per group (admin management view)
CREATE INDEX idx_invite_links_group_active
    ON group_invite_links(group_id)
    WHERE revoked_at IS NULL;

-- ============================================================================
-- Add topic_id to group_messages
-- ============================================================================

ALTER TABLE group_messages
    ADD COLUMN topic_id UUID REFERENCES group_topics(topic_id) ON DELETE SET NULL;

-- NULL = default/general topic; fetching a specific topic filters on this column
CREATE INDEX idx_group_messages_topic
    ON group_messages(group_id, topic_id, sequence_number)
    WHERE topic_id IS NOT NULL;

-- ============================================================================
-- Add allow_group_invite to users
-- ============================================================================
-- Default FALSE: privacy-first — nobody can add you to a group without your
-- explicit action (either flipping this flag, or clicking an invite link).
-- When TRUE, contacts who know your user_id can call InviteToGroup for you.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS allow_group_invite BOOLEAN NOT NULL DEFAULT FALSE;
