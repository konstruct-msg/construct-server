-- Tighten message retention: default 90→30 days, max 365→90 days.
-- Existing rows with retention_days > 90 are clamped to 90 (single-VPS storage budget).

-- mls_groups
ALTER TABLE mls_groups
    ALTER COLUMN message_retention_days SET DEFAULT 30;

ALTER TABLE mls_groups
    DROP CONSTRAINT IF EXISTS mls_groups_message_retention_days_check,
    ADD CONSTRAINT mls_groups_message_retention_days_check
        CHECK (message_retention_days BETWEEN 1 AND 90);

UPDATE mls_groups SET message_retention_days = 90 WHERE message_retention_days > 90;

-- channels
ALTER TABLE channels
    ALTER COLUMN retention_days SET DEFAULT 30;

ALTER TABLE channels
    DROP CONSTRAINT IF EXISTS chk_retention_days,
    ADD CONSTRAINT chk_retention_days
        CHECK (retention_days >= 1 AND retention_days <= 90);

UPDATE channels SET retention_days = 90 WHERE retention_days > 90;
