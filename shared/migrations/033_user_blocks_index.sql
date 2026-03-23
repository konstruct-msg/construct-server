-- Migration 033: Add missing index on user_blocks(blocked_user_id)
--
-- Migration 019 created the user_blocks table with a composite PRIMARY KEY
-- (blocker_user_id, blocked_user_id), which indexes only the left column.
-- Queries of the form "who has blocked me?" (looking up by blocked_user_id)
-- require a full sequential scan without this index.
--
-- Used by: is_blocked_by() in shared/src/db.rs

CREATE INDEX IF NOT EXISTS idx_user_blocks_blocked
    ON user_blocks(blocked_user_id);
