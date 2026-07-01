-- Migration 064: Add identity_public_key column for pubkey-as-identity (Epic E)
--
-- Adds a per-user public key that serves as the global user identity.
-- This is distinct from:
--   - devices.verifying_key (per-device auth key)
--   - users.recovery_public_key (account recovery key)
--   - devices.identity_public (per-device X3DH/X25519 identity)
--
-- Identity key type encoding:
--   1 = Ed25519 (32 bytes)
--   2 = ML-DSA-65 (1952 bytes)
--   3 = Hybrid Ed25519+ML-DSA (32 + 1952 = 1984 bytes)
--
-- route_id = SHA-256(identity_key_type || identity_public_key) is computed
-- at the application layer. The type is included in the hash to prevent
-- algorithm confusion attacks and ensure different algorithms produce
-- distinct route_ids.
--
-- Existing recovery_public_key values (Ed25519) are copied into the new
-- column so current users have an identity key without re-registering.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS identity_public_key BYTEA
    CONSTRAINT identity_public_key_length CHECK (
        identity_public_key IS NULL OR length(identity_public_key) = 32
        OR length(identity_public_key) = 1952
        OR length(identity_public_key) = 1984
    );

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS identity_key_type SMALLINT NOT NULL DEFAULT 1;

-- Copy existing recovery_public_key values into identity_public_key
UPDATE users
SET identity_public_key = recovery_public_key
WHERE recovery_public_key IS NOT NULL
  AND identity_public_key IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_identity_pubkey
    ON users(identity_public_key)
    WHERE identity_public_key IS NOT NULL;

-- Validation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'identity_public_key'
    ) THEN
        RAISE EXCEPTION 'Migration 064 failed: users.identity_public_key not added';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'identity_key_type'
    ) THEN
        RAISE EXCEPTION 'Migration 064 failed: users.identity_key_type not added';
    END IF;
    RAISE NOTICE 'Migration 064 completed successfully!';
    RAISE NOTICE '  ✓ users.identity_public_key column added';
    RAISE NOTICE '  ✓ users.identity_key_type column added (default 1 = Ed25519)';
    RAISE NOTICE '  ✓ idx_users_identity_pubkey unique partial index created';
    RAISE NOTICE '  ✓ recovery_public_key values migrated';
END $$;
