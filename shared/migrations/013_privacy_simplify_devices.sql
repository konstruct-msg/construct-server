-- ============================================================================
-- Migration 013: Simplify devices table (Privacy-First Design)
-- ============================================================================
--
-- Purpose: Remove metadata leaks from devices table
--
-- Privacy violations to remove:
-- - username (device display name) - metadata leak
-- - device_name ("iPhone 15 Pro") - device fingerprinting
-- - platform ("iOS", "Android") - OS leak
-- - registered_at - timing metadata
-- - protocol_version - crypto metadata (use crypto_suites only)
--
-- Changes:
-- - DROP username column
-- - DROP device_name column  
-- - DROP platform column
-- - DROP registered_at column
-- - DROP protocol_version column
-- - UPDATE crypto_suites format: ["0x01"] → ["Curve25519+Ed25519"]
--
-- Related: DEVICE_AUTH_BACKEND_SPEC.md
-- ============================================================================

-- Drop privacy-leaking columns (keep registered_at for warmup logic)
ALTER TABLE devices DROP COLUMN IF EXISTS username;
ALTER TABLE devices DROP COLUMN IF EXISTS device_name;
ALTER TABLE devices DROP COLUMN IF EXISTS platform;
ALTER TABLE devices DROP COLUMN IF EXISTS last_active_at;
ALTER TABLE devices DROP COLUMN IF EXISTS protocol_version;
ALTER TABLE devices DROP COLUMN IF EXISTS key_updated_at;
ALTER TABLE devices DROP COLUMN IF EXISTS key_update_reason;
ALTER TABLE devices DROP COLUMN IF EXISTS suite_id; -- Replaced by crypto_suites JSONB

-- Update crypto_suites format for existing records
-- Old: ["0x01"] → New: ["Curve25519+Ed25519"]
UPDATE devices 
SET crypto_suites = '["Curve25519+Ed25519"]'::jsonb
WHERE crypto_suites = '["0x01"]'::jsonb;

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    -- Verify columns were removed
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'username'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.username still exists';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'device_name'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.device_name still exists';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'platform'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.platform still exists';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'protocol_version'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.protocol_version still exists';
    END IF;

    -- Verify required columns still exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'device_id'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.device_id removed!';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'crypto_suites'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.crypto_suites removed!';
    END IF;

    RAISE NOTICE '✅ Migration 013: Privacy-focused devices table';
    RAISE NOTICE '  ✓ Removed: username, device_name, platform';
    RAISE NOTICE '  ✓ Removed: protocol_version (kept registered_at for warmup)';
    RAISE NOTICE '  ✓ Updated: crypto_suites format';
    RAISE NOTICE '  ✓ Privacy-first design complete';
END $$;
