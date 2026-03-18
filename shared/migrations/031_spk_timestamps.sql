-- ============================================================================
-- Migration 031: SPK upload timestamps and rotation epochs
-- ============================================================================
--
-- Adds server-recorded timestamps and monotonic counters for SPK rotations.
-- These are returned in GetPreKeyBundle responses so clients can:
--   1. Reject stale SPK bundles (age > 8 days)
--   2. Detect SPK replay attacks (epoch must be monotonically increasing)
--
-- Fully backward-compatible: spk_uploaded_at = NULL means legacy device,
-- client falls back to generated_at (field 9) in PreKeyBundle.
-- ============================================================================

ALTER TABLE devices ADD COLUMN IF NOT EXISTS spk_uploaded_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS spk_rotation_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS kyber_spk_uploaded_at TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS kyber_spk_rotation_epoch INTEGER NOT NULL DEFAULT 0;

-- Backfill existing devices: use key_updated_at (or registered_at) as spk_uploaded_at
UPDATE devices SET spk_uploaded_at = COALESCE(key_updated_at, registered_at)
WHERE spk_uploaded_at IS NULL;

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'spk_rotation_epoch'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.spk_rotation_epoch not added';
    END IF;

    RAISE NOTICE '✅ Migration 031: SPK timestamps and rotation epochs added to devices';
END $$;
