-- Remove the enterprise key-management subsystem (construct-key-management crate).
--
-- It required HashiCorp Vault and was never wired into any real signing/encryption
-- path: JWT signing uses static RS256 config keys (construct-auth), federation uses
-- Ed25519 from config (construct-federation). With Vault removed from the single-VPS
-- deployment, KeyManagementSystem failed open to None — i.e. it managed nothing.
--
-- Drops the tables, the partitioned audit log (CASCADE removes its monthly
-- partitions), and the rotation/audit PL/pgSQL functions. User account-recovery
-- functions (can_user_recover, check_recovery_key_immutable, set_recovery_setup_at)
-- are intentionally left — they are unrelated to server key rotation.

-- Functions are not overloaded, so drop by bare name (PG 10+).
DROP FUNCTION IF EXISTS get_active_key CASCADE;
DROP FUNCTION IF EXISTS get_valid_keys CASCADE;
DROP FUNCTION IF EXISTS start_key_rotation CASCADE;
DROP FUNCTION IF EXISTS complete_key_rotation CASCADE;
DROP FUNCTION IF EXISTS emergency_revoke_key CASCADE;
DROP FUNCTION IF EXISTS cleanup_old_key_data CASCADE;

DROP TABLE IF EXISTS key_access_log CASCADE;   -- CASCADE drops monthly partitions
DROP TABLE IF EXISTS key_rotation_audit CASCADE;
DROP TABLE IF EXISTS master_keys CASCADE;
