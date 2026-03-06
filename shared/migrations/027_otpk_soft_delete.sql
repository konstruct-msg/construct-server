-- ============================================================================
-- Migration 027: Soft-delete for One-Time Pre-Keys
-- ============================================================================
--
-- Problem:
--   When a client calls UploadPreKeys with replace_existing=true (e.g. after a
--   session reset or app reinstall), the server immediately deletes ALL existing
--   OTPKs for the device. This can lose keys that were already fetched by senders
--   but whose prekey messages haven't been delivered yet.
--
-- Fix:
--   Instead of hard-deleting, mark old keys as expired with a timestamp.
--   Keys are only hard-deleted after a TTL (48 hours), matching signed_prekey_archive.
--   GetPreKeyBundle skips expired keys. Cleanup runs on a schedule.
--
-- Parallels signed_prekey_archive (migration 022) which already uses this pattern.
-- ============================================================================

ALTER TABLE one_time_prekeys
    ADD COLUMN IF NOT EXISTS is_expired  BOOLEAN      NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS expired_at  TIMESTAMPTZ;

-- Fast lookup of active (non-expired) keys for a device
CREATE INDEX IF NOT EXISTS idx_otp_device_active
ON one_time_prekeys(device_id)
WHERE is_expired = false;

-- Cleanup job: find expired keys ready for hard-delete
CREATE INDEX IF NOT EXISTS idx_otp_expired_at
ON one_time_prekeys(expired_at)
WHERE is_expired = true;

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'one_time_prekeys' AND column_name = 'is_expired'
    ) THEN
        RAISE EXCEPTION 'Migration 027 failed: is_expired column not added';
    END IF;

    RAISE NOTICE 'Migration 027 completed successfully!';
    RAISE NOTICE '  ✓ one_time_prekeys.is_expired column added';
    RAISE NOTICE '  ✓ one_time_prekeys.expired_at column added';
    RAISE NOTICE '  ✓ Partial indexes for active and expired keys created';
END $$;
