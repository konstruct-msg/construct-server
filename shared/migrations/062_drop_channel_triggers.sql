-- Replace three channel triggers with Rust-side logic.
--
-- 1. channel_post_sequence_trigger: MAX(sequence_number)+1 was racy.
--    Replaced by last_post_sequence column + atomic UPDATE ... RETURNING (CTE).
-- 2. channel_update_subscriber_count: now bumped explicitly in Rust after
--    INSERT/DELETE on channel_subscribers.
-- 3. channel_update_timestamp: redundant — every UPDATE channels in Rust
--    already sets updated_at = NOW() explicitly.

-- Atomic sequence counter (mirrors mls_groups.last_sequence)
ALTER TABLE channels ADD COLUMN last_post_sequence BIGINT NOT NULL DEFAULT 0;

-- Backfill from actual max per channel (0 for channels with no posts)
UPDATE channels c
SET last_post_sequence = COALESCE(
    (SELECT MAX(sequence_number) FROM channel_posts WHERE channel_id = c.channel_id),
    0
);

DROP TRIGGER IF EXISTS trg_channel_post_sequence      ON channel_posts;
DROP TRIGGER IF EXISTS trg_channel_subscriber_count   ON channel_subscribers;
DROP TRIGGER IF EXISTS trg_channel_update_timestamp   ON channels;

DROP FUNCTION IF EXISTS channel_post_sequence_trigger();
DROP FUNCTION IF EXISTS channel_update_subscriber_count();
DROP FUNCTION IF EXISTS channel_update_timestamp();

DROP SEQUENCE IF EXISTS channel_post_sequence;
