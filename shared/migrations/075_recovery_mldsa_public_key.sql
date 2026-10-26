-- The ML-DSA-65 half of an account's recovery key.
--
-- The recovery key was Ed25519 alone, and its public half is stored here — so a dump of this table
-- and a quantum computer recover any account. Since construct-core 0.59.0 the phrase also yields an
-- ML-DSA-65 key and the two sign as one hybrid key (both halves must verify). The Ed25519 half is
-- the key `recovery_public_key` already holds and stays there: it is the account's address
-- (`route_id`, construct-docs decisions/pubkey-as-identity.md). This column holds the other half.
--
-- Set once, by a hybrid SetRecoveryKey or a hybrid RecoverAccount whose Ed25519 half is the stored
-- key, and never changed after — like the key it completes. An account with it set takes only
-- hybrid claims: accepting an Ed25519-only claim there would hand the quantum adversary back what
-- the upgrade took away. construct-docs todo/222-recovery-key-hybrid-pq.md.

ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_mldsa_public_key BYTEA;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_recovery_mldsa_public_key_len;
ALTER TABLE users
    ADD CONSTRAINT users_recovery_mldsa_public_key_len
    CHECK (recovery_mldsa_public_key IS NULL
           OR (octet_length(recovery_mldsa_public_key) = 1952 AND recovery_public_key IS NOT NULL));

CREATE OR REPLACE FUNCTION check_recovery_mldsa_key_immutable()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.recovery_mldsa_public_key IS NOT NULL AND
       NEW.recovery_mldsa_public_key IS DISTINCT FROM OLD.recovery_mldsa_public_key THEN
        RAISE EXCEPTION 'Recovery key cannot be changed once set';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_recovery_mldsa_key_immutable ON users;
CREATE TRIGGER users_recovery_mldsa_key_immutable
    BEFORE UPDATE OF recovery_mldsa_public_key ON users
    FOR EACH ROW
    EXECUTE FUNCTION check_recovery_mldsa_key_immutable();

COMMENT ON COLUMN users.recovery_mldsa_public_key IS
    'ML-DSA-65 half (1952 bytes) of the hybrid recovery key whose Ed25519 half is '
    'recovery_public_key. Set once; when set, RecoverAccount takes only hybrid claims.';
