-- ============================================================================
-- Migration 028: Post-Quantum Cryptography — ML-KEM-1024 (Kyber) Key Storage
-- ============================================================================
--
-- Phase 1: Server accepts and stores Kyber keys but does NOT require them.
-- Classic X3DH clients are fully backward compatible — no existing rows change.
--
-- Architecture (PQXDH hybrid):
--   master_secret = HKDF(DH1 || DH2 || DH3 || SS_kem)
--   where SS_kem = ML-KEM-1024.Decaps(kem_ciphertext, kyber_spk_private)
--
-- Key sizes:
--   ML-KEM-1024 public key  = exactly 1184 bytes
--   ML-KEM-1024 ciphertext  = exactly 1568 bytes
--   Ed25519 signature       = exactly 64 bytes
--
-- References:
--   NIST FIPS 203 (ML-KEM standard)
--   Signal PQXDH spec (September 2023)
--   PQC_ML_KEM_MIGRATION_CHECKLIST.md
-- ============================================================================

-- ============================================================================
-- 1. Add Kyber signed pre-key columns to devices table
-- ============================================================================
--
-- Nullable — old devices simply have NULL here. Server returns Kyber fields
-- in GetPreKeyBundle only when kyber_signed_pre_key IS NOT NULL.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS kyber_signed_pre_key           BYTEA,
    ADD COLUMN IF NOT EXISTS kyber_signed_pre_key_id        INTEGER,
    ADD COLUMN IF NOT EXISTS kyber_signed_pre_key_signature BYTEA;

COMMENT ON COLUMN devices.kyber_signed_pre_key IS
    'ML-KEM-1024 public key for Kyber signed pre-key. Exactly 1184 bytes when present.';
COMMENT ON COLUMN devices.kyber_signed_pre_key_id IS
    'Client-assigned ID for the Kyber signed pre-key. Incremented on rotation.';
COMMENT ON COLUMN devices.kyber_signed_pre_key_signature IS
    'Ed25519 signature over kyber_signed_pre_key (64 bytes).';

-- ============================================================================
-- 2. Kyber one-time pre-keys table
-- ============================================================================
--
-- Mirrors one_time_prekeys but for ML-KEM-1024 keys.
-- Soft-delete pattern matches migration 027 (is_expired + expired_at).
-- Keys are consumed by GetPreKeyBundle: marked is_expired = true.
-- Hard-deleted by cleanup job after 48h (same as classic OTPK policy).

CREATE TABLE IF NOT EXISTS kyber_one_time_pre_keys (
    -- ========================================================================
    -- PRIMARY KEY
    -- ========================================================================

    -- Composite primary key: device + key_id
    device_id   VARCHAR(32)  NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id      INTEGER      NOT NULL,

    -- ========================================================================
    -- KEY DATA
    -- ========================================================================

    -- ML-KEM-1024 public key (exactly 1184 bytes, enforced in application layer)
    public_key  BYTEA        NOT NULL,

    -- Ed25519 signature over public_key (exactly 64 bytes)
    signature   BYTEA        NOT NULL,

    -- ========================================================================
    -- LIFECYCLE (soft-delete, same as migration 027 for classic OTPK)
    -- ========================================================================

    -- When this key was uploaded
    uploaded_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Soft-delete: true after key is consumed by GetPreKeyBundle
    is_expired  BOOLEAN      NOT NULL DEFAULT false,

    -- When the key was consumed / marked expired
    expired_at  TIMESTAMPTZ,

    PRIMARY KEY (device_id, key_id)
);

-- Fast lookup of available (non-expired) Kyber OTPKs for a device
CREATE INDEX IF NOT EXISTS idx_kyber_otp_device_active
ON kyber_one_time_pre_keys(device_id)
WHERE is_expired = false;

-- Cleanup job: find expired keys ready for hard-delete
CREATE INDEX IF NOT EXISTS idx_kyber_otp_expired_at
ON kyber_one_time_pre_keys(expired_at)
WHERE is_expired = true;

COMMENT ON TABLE kyber_one_time_pre_keys IS
    'ML-KEM-1024 one-time pre-keys for PQXDH hybrid key exchange. '
    'Each key is consumed once (soft-deleted) during GetPreKeyBundle. '
    'Hard-deleted after 48h by cleanup_expired_kyber_otpks().';

COMMENT ON COLUMN kyber_one_time_pre_keys.public_key IS
    'ML-KEM-1024 encapsulation key, exactly 1184 bytes. Validated in application layer.';
COMMENT ON COLUMN kyber_one_time_pre_keys.signature IS
    'Ed25519 signature over public_key using device identity key. 64 bytes.';

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    -- Check kyber_signed_pre_key column on devices
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'kyber_signed_pre_key'
    ) THEN
        RAISE EXCEPTION 'Migration 028 failed: devices.kyber_signed_pre_key not added';
    END IF;

    -- Check kyber_one_time_pre_keys table
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'kyber_one_time_pre_keys'
    ) THEN
        RAISE EXCEPTION 'Migration 028 failed: kyber_one_time_pre_keys table not created';
    END IF;

    RAISE NOTICE 'Migration 028 completed successfully!';
    RAISE NOTICE '  ✓ devices.kyber_signed_pre_key column added (nullable)';
    RAISE NOTICE '  ✓ devices.kyber_signed_pre_key_id column added (nullable)';
    RAISE NOTICE '  ✓ devices.kyber_signed_pre_key_signature column added (nullable)';
    RAISE NOTICE '  ✓ kyber_one_time_pre_keys table created';
    RAISE NOTICE '  ✓ Partial indexes for active and expired Kyber OTPKs created';
    RAISE NOTICE '  ℹ Classic X3DH clients unaffected (all new columns nullable)';
END $$;
