-- PQXDH v2: ML-KEM-1024 Kyber keys, a signed creation time on each, and the one-time key's
-- signatures kept so they can be served.
--
-- Until now every Kyber key a client uploaded was an ML-KEM-768 key (1184 bytes), stored beside
-- comments that called it ML-KEM-1024, and signed over "KonstruktX3DH-v1" || 0x00 0x10 || pk.
-- PQXDH v2 (construct-core) puts the ML-KEM secret into the session's initial key and signs every
-- Kyber key over
--
--     "KonstruktX3DH-v1" || 0x00 0x11 || created_at (u64 BE, unix seconds) || pk (1568 bytes)
--
-- with the Ed25519 identity and with the hybrid identity key. An initiator checks both, and
-- refuses a signed pre-key older than 30 days by that signed time. So the server now keeps:
--
--   devices.kyber_signed_pre_key_created_at    the signed time, served as PreKeyBundle field 25
--   kyber_one_time_pre_keys.created_at          the same for a one-time key (field 27)
--   kyber_one_time_pre_keys.hybrid_signature    the hybrid signature (field 28)
--
-- and serves kyber_one_time_pre_keys.signature (field 26), which it has always verified on upload
-- and then dropped from the bundle.
--
-- ## The old keys are deleted, not migrated
--
-- A v2 core can do nothing with a 768 key or a 0x10 signature, and there is no way to convert
-- either: the key would need a new keypair, the signature the device's private key. The cutover is
-- without compatibility by decision (construct-docs decisions/pqxdh-v2-mandatory-pq-cutover.md).
-- Every device re-uploads through the core once it runs a v2 build.
--
-- Deploy this in the same window as the v2 clients. After it runs, clients on older builds cannot
-- upload Kyber keys (the key-service rejects 1184-byte keys and 0x10 signatures) and their peers
-- get bundles with no Kyber keys at all.
--
-- Design: construct-docs cryptocore/PQXDH_V2_DESIGN.md §5.2, §5.7.

-- 1. Remove every pre-v2 Kyber key. Selected by size, the one property that tells them apart.
DELETE FROM kyber_one_time_pre_keys
WHERE octet_length(public_key) <> 1568;

UPDATE devices
SET kyber_signed_pre_key                  = NULL,
    kyber_signed_pre_key_id               = NULL,
    kyber_signed_pre_key_signature        = NULL,
    kyber_signed_pre_key_hybrid_signature = NULL,
    kyber_spk_uploaded_at                 = NULL
    -- kyber_spk_rotation_epoch is kept: it only ever increases, and the next upload continues it.
WHERE kyber_signed_pre_key IS NOT NULL
  AND octet_length(kyber_signed_pre_key) <> 1568;

-- 2. What v2 keys carry. Nullable in the schema; the key-service refuses a key without them.
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS kyber_signed_pre_key_created_at BIGINT;

ALTER TABLE kyber_one_time_pre_keys
    ADD COLUMN IF NOT EXISTS created_at       BIGINT,
    ADD COLUMN IF NOT EXISTS hybrid_signature BYTEA;

COMMENT ON COLUMN devices.kyber_signed_pre_key IS
    'ML-KEM-1024 public key of the Kyber signed pre-key, exactly 1568 bytes (PQXDH v2).';
COMMENT ON COLUMN devices.kyber_signed_pre_key_signature IS
    'Ed25519 signature (64 bytes) over "KonstruktX3DH-v1" || 0x00 0x11 || created_at (u64 BE) || kyber_signed_pre_key.';
COMMENT ON COLUMN devices.kyber_signed_pre_key_hybrid_signature IS
    'Hybrid signature (3373 bytes) over the same v2 sign-message as kyber_signed_pre_key_signature.';
COMMENT ON COLUMN devices.kyber_signed_pre_key_created_at IS
    'Signed creation time of the Kyber signed pre-key, unix seconds. Under both of its signatures.';
COMMENT ON COLUMN kyber_one_time_pre_keys.public_key IS
    'ML-KEM-1024 public key, exactly 1568 bytes (PQXDH v2).';
COMMENT ON COLUMN kyber_one_time_pre_keys.signature IS
    'Ed25519 signature (64 bytes) over "KonstruktX3DH-v1" || 0x00 0x11 || created_at (u64 BE) || public_key.';
COMMENT ON COLUMN kyber_one_time_pre_keys.created_at IS
    'Signed creation time, unix seconds.';
COMMENT ON COLUMN kyber_one_time_pre_keys.hybrid_signature IS
    'Hybrid signature (3373 bytes) over the same v2 sign-message as signature.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'kyber_one_time_pre_keys' AND column_name = 'hybrid_signature'
    ) THEN
        RAISE EXCEPTION 'Migration 071 failed: kyber_one_time_pre_keys.hybrid_signature not added';
    END IF;
    IF EXISTS (
        SELECT 1 FROM kyber_one_time_pre_keys WHERE octet_length(public_key) <> 1568
    ) THEN
        RAISE EXCEPTION 'Migration 071 failed: pre-v2 Kyber one-time keys remain';
    END IF;
END $$;
