-- Migration 047: Allow multiple kt_leaves entries per device (key rotation support)
--
-- The original schema had a UNIQUE INDEX on device_id, making the log
-- idempotent per device but preventing key rotation from being recorded.
-- This migration drops that constraint so key changes append a new leaf,
-- keeping the full rotation history in the log.
--
-- The fast lookup index is replaced with a non-unique one.
-- db_ensure_leaf() now inserts a new row only when the leaf_hash changes.

DROP INDEX IF EXISTS kt_leaves_device_id;

-- Efficient lookup: latest leaf for a device (ORDER BY id DESC LIMIT 1)
CREATE INDEX kt_leaves_device_id_idx ON kt_leaves (device_id, id DESC);
