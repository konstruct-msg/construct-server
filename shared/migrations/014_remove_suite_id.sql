-- ============================================================================
-- Migration 014: Remove suite_id column (replaced by crypto_suites)
-- ============================================================================
--
-- Purpose: Complete privacy simplification by removing suite_id column
--
-- Reason: crypto_suites JSONB array replaced suite_id VARCHAR
-- - suite_id was single crypto suite (e.g., "Curve25519+Ed25519")
-- - crypto_suites supports multiple suites for crypto agility
-- - suite_id column is now redundant
--
-- Related: Migration 013, DEVICE_AUTH_BACKEND_SPEC.md
-- ============================================================================

-- Drop suite_id column (replaced by crypto_suites JSONB)
ALTER TABLE devices DROP COLUMN IF EXISTS suite_id;

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    -- Verify suite_id was removed
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'suite_id'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.suite_id still exists';
    END IF;

    -- Verify crypto_suites still exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'crypto_suites'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.crypto_suites removed!';
    END IF;

    RAISE NOTICE '✅ Migration 014: Removed suite_id (using crypto_suites only)';
END $$;
