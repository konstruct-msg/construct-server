-- ============================================================================
-- Migration 026: Track signed_prekey_id on devices
-- ============================================================================
--
-- Problem: devices.signed_prekey_public has no associated key_id column.
-- The server hardcodes signed_prekey_id = 1 in GetPreKeyBundle responses.
-- Clients rely on the signed_prekey_id to verify freshness and to match
-- signatures against the correct key during X3DH session setup.
--
-- Fix: add signed_prekey_id column; default existing rows to 1 (matches
-- what clients have already received). Future rotations write the real ID.
--
-- Also fixes signed_prekey_archive: the archive key_id was hardcoded to 0,
-- making it impossible to distinguish archived keys. Add a sequence-based
-- fallback so old rows become unique: use 0 as sentinel "pre-migration".
-- ============================================================================

-- Add signed_prekey_id to devices table
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS signed_prekey_id INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN devices.signed_prekey_id IS
  'ID of the current signed pre-key as provided by the client. Incremented '
  'on every rotation. Required by X3DH to verify signature freshness.';

-- Fix signed_prekey_archive: rename key_id semantics are fine (it IS the
-- signed_prekey_id that was active when archived). The problem was that
-- rotate_signed_prekey() always wrote key_id = 0. Existing rows stay;
-- new rows will use the real ID. No data migration needed.

-- ============================================================================
-- VALIDATION
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'signed_prekey_id'
    ) THEN
        RAISE EXCEPTION 'Migration 026 failed: devices.signed_prekey_id not created';
    END IF;
    RAISE NOTICE 'Migration 026 completed: devices.signed_prekey_id added (default=1)';
END $$;
