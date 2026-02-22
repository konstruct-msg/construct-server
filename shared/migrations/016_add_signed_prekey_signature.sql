-- ============================================================================
-- Migration 016: Add signed_prekey_signature to devices
-- ============================================================================
--
-- Purpose: Store Ed25519 signature of signed_prekey for session initialization
--
-- Background:
-- - X3DH protocol requires signedPrekeySignature for session init
-- - This signature proves the signed_prekey was created by the device owner
-- - Without it, clients cannot establish secure sessions
--
-- Format: Ed25519 signature (64 bytes) over:
--   prologue || signed_prekey_public
-- Where prologue = "KonstruktX3DH-v1" || suite_id (2 bytes BE)
--
-- Related: KEY_BUNDLE_SERVER_EXPECTATIONS.md
-- ============================================================================

-- Add signed_prekey_signature column (64 bytes Ed25519 signature)
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS signed_prekey_signature BYTEA;

-- Note: Column is nullable for backward compatibility with existing devices
-- Existing devices will need to re-upload their key bundle to populate this field
-- New registrations should always include this signature

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON COLUMN devices.signed_prekey_signature IS
  'Ed25519 signature of (prologue || signed_prekey_public), 64 bytes. Required for X3DH session initialization.';

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    -- Verify column exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'signed_prekey_signature'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.signed_prekey_signature not created';
    END IF;

    RAISE NOTICE 'Migration 016 completed successfully!';
    RAISE NOTICE '  ✓ devices.signed_prekey_signature added (nullable for backward compat)';
    RAISE NOTICE '  ⚠ Existing devices need to re-upload key bundle to populate this field';
END $$;
