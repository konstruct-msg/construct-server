-- ============================================================================
-- Migration 030: Restore key_updated_at on devices
-- ============================================================================
--
-- Migration 013 dropped key_updated_at as a "metadata leak", but this column
-- is server-internal only — never exposed to other users or clients.
-- It is required by key-service for:
--   - upload_kyber_signed_prekey(): track when Kyber SPK was last rotated
--   - rotate_signed_prekey(): track classic SPK rotation time
--   - Prekey rotation scheduling (warmup logic)
-- ============================================================================

ALTER TABLE devices ADD COLUMN IF NOT EXISTS key_updated_at TIMESTAMPTZ;

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'key_updated_at'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.key_updated_at not added';
    END IF;

    RAISE NOTICE '✅ Migration 030: key_updated_at restored on devices';
END $$;
