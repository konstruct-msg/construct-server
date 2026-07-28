-- Migration 065: Store optional encrypted recovery backup blob
--
-- Client may upload a sealed recovery backup with SetRecoveryKey.
-- Server stores it opaquely and never decrypts. Size-capped in application
-- code (see identity-service recovery::MAX_RECOVERY_BACKUP_BYTES).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS recovery_encrypted_backup BYTEA;

COMMENT ON COLUMN users.recovery_encrypted_backup IS
    'Client-encrypted recovery backup blob (opaque to server). NULL if not provided.';
