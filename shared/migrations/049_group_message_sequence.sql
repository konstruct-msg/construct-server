-- ============================================================================
-- Migration 049: Group Message Sequence Counter + Idempotency
-- ============================================================================
--
-- Adds two things:
--   1. last_sequence counter on mls_groups for atomic per-group sequencing
--   2. client_message_id on group_messages for send idempotency
--
-- The last_sequence approach:
--   UPDATE mls_groups SET last_sequence = last_sequence + 1 RETURNING last_sequence
--   is a single atomic write — no separate sequence object or SELECT + INSERT race.
--

-- Per-group monotonic counter; starts at -1 so first message gets sequence 0.
ALTER TABLE mls_groups ADD COLUMN last_sequence BIGINT NOT NULL DEFAULT -1;

-- Client-generated opaque ID (UUID string, max 64 chars) used to detect
-- duplicate sends (e.g. retry after network timeout).
ALTER TABLE group_messages ADD COLUMN client_message_id VARCHAR(64);

-- Prevents double-insertion for the same client_message_id within a group.
CREATE UNIQUE INDEX idx_group_messages_client_id
    ON group_messages(group_id, client_message_id)
    WHERE client_message_id IS NOT NULL;
