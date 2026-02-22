-- ============================================================================
-- Migration 012: Add crypto capability fields to devices
-- ============================================================================
--
-- Purpose: Move protocol_version and crypto_suites from users to devices
--
-- Background:
-- - Migration 008 added these to users table
-- - Migration 011 dropped users table entirely (passwordless redesign)
-- - These fields are device-specific, not user-specific
-- - Each device can support different crypto suites
--
-- Changes:
-- - Add protocol_version to devices (1 = classic, 2 = hybrid PQ)
-- - Add crypto_suites to devices (JSONB array of supported suites)
-- - Add index for protocol_version filtering
--
-- Related: Phase 5 crypto-agility, PHASE_5_CRYPTO_COORDINATED.md
-- ============================================================================

-- Add protocol version to devices
-- 1 = Classic X25519 + Ed25519
-- 2 = Hybrid PQ (ML-KEM + Dilithium)
ALTER TABLE devices 
  ADD COLUMN IF NOT EXISTS protocol_version INTEGER DEFAULT 1 NOT NULL;

-- Add supported crypto suites (JSONB array of suite IDs)
-- Default: ["0x01"] = Classic X25519 + ChaCha20
-- Examples:
--   ["0x01"] = Classic only
--   ["0x01", "0x02"] = Classic + Hybrid PQ
--   ["0x02"] = PQ only (future)
ALTER TABLE devices 
  ADD COLUMN IF NOT EXISTS crypto_suites JSONB DEFAULT '["0x01"]'::jsonb NOT NULL;

-- Index for filtering devices by protocol version
-- Used for: finding compatible devices, protocol upgrade monitoring
CREATE INDEX IF NOT EXISTS idx_devices_protocol_version 
  ON devices(protocol_version);

-- GIN index for crypto_suites JSONB queries
-- Used for: finding devices that support specific suites
CREATE INDEX IF NOT EXISTS idx_devices_crypto_suites 
  ON devices USING GIN (crypto_suites);

-- ============================================================================
-- COMMENTS (Documentation)
-- ============================================================================

COMMENT ON COLUMN devices.protocol_version IS 
  'Protocol version: 1=classic X25519, 2=hybrid PQ. Device-specific.';

COMMENT ON COLUMN devices.crypto_suites IS 
  'JSONB array of supported crypto suite IDs (e.g., ["0x01", "0x02"]). Device-specific.';

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    -- Verify protocol_version column exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'protocol_version'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.protocol_version not created';
    END IF;

    -- Verify crypto_suites column exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'crypto_suites'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.crypto_suites not created';
    END IF;

    -- Verify protocol_version index exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_devices_protocol_version'
    ) THEN
        RAISE EXCEPTION 'Migration failed: idx_devices_protocol_version not created';
    END IF;

    -- Verify crypto_suites index exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_devices_crypto_suites'
    ) THEN
        RAISE EXCEPTION 'Migration failed: idx_devices_crypto_suites not created';
    END IF;

    RAISE NOTICE 'Migration 012 completed successfully!';
    RAISE NOTICE '  ✓ devices.protocol_version added (default: 1)';
    RAISE NOTICE '  ✓ devices.crypto_suites added (default: ["0x01"])';
    RAISE NOTICE '  ✓ Indexes created for both fields';
END $$;
