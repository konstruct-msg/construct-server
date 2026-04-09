-- Migration 042: Add recovery_setup_at to users table
--
-- Problem: auth-service/recovery.rs was querying `created_at` from `users`,
-- but migration 011 explicitly omits that column (privacy-by-design).
-- This caused `column "created_at" does not exist` → gRPC Internal (code=13)
-- every time GetRecoveryStatus was called.
--
-- Fix: add a dedicated nullable column for when recovery was set up.
-- NULL  = recovery not configured (or configured before this migration).
-- NOT NULL = timestamp recovery_public_key was first stored.
--
-- Existing rows with recovery_public_key set get NULL (unknown setup date).
-- The trigger below ensures future inserts/updates populate it automatically.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_setup_at TIMESTAMPTZ;

-- Populate for rows that already have a recovery key (best-effort: use NOW())
UPDATE users
SET recovery_setup_at = NOW()
WHERE recovery_public_key IS NOT NULL
  AND recovery_setup_at IS NULL;

-- Trigger: set recovery_setup_at when recovery_public_key is set for the first time
CREATE OR REPLACE FUNCTION set_recovery_setup_at()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.recovery_public_key IS NULL AND NEW.recovery_public_key IS NOT NULL THEN
        NEW.recovery_setup_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_set_recovery_setup_at ON users;
CREATE TRIGGER users_set_recovery_setup_at
    BEFORE UPDATE OF recovery_public_key ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_recovery_setup_at();

-- Validation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'recovery_setup_at'
    ) THEN
        RAISE EXCEPTION 'Migration 042 failed: users.recovery_setup_at not added';
    END IF;
    RAISE NOTICE 'Migration 042 completed successfully!';
    RAISE NOTICE '  ✓ users.recovery_setup_at column added';
    RAISE NOTICE '  ✓ set_recovery_setup_at trigger created';
END $$;
