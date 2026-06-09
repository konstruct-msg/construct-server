-- ============================================================================
-- Migration 053: Hybrid PQ identity signatures (Ed25519 + ML-DSA-65)
-- ============================================================================
--
-- Purpose: Store the device's hybrid post-quantum identity key and the hybrid
-- signatures over its signed pre-keys, so the server can serve them in
-- PreKeyBundle (fields 20-23) and verify them on upload.
--
-- Binding model (IMPORTANT):
--   The hybrid identity key has an INDEPENDENT Ed25519 half — it is NOT the
--   device's existing Ed25519 identity (`verifying_key`). The two are bound by a
--   cross-signature: hybrid_identity_signature = Ed25519.sign(device_identity,
--   "KonstruktHybridId-v1" || hybrid_identity_key), verifiable with `verifying_key`.
--   There is therefore NO `hybrid_identity_key[0..32] == verifying_key` invariant.
--
-- Sizes:
--   hybrid_identity_key                   1984 B = [ed25519_pk(32)] [mldsa65_pk(1952)]
--   hybrid_identity_signature               64 B = Ed25519 cross-signature
--   signed_prekey_hybrid_signature        3373 B = [ed25519_sig(64)] [mldsa65_sig(3309)]
--   kyber_signed_pre_key_hybrid_signature 3373 B = hybrid sig over the Kyber SPK
--
-- All columns are nullable: Ed25519-only devices and pre-hybrid clients leave
-- them NULL. Published via UploadPreKeys (covers both new and existing accounts).
-- ============================================================================

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS hybrid_identity_key                   BYTEA,
  ADD COLUMN IF NOT EXISTS hybrid_identity_signature             BYTEA,
  ADD COLUMN IF NOT EXISTS signed_prekey_hybrid_signature        BYTEA,
  ADD COLUMN IF NOT EXISTS kyber_signed_pre_key_hybrid_signature BYTEA;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON COLUMN devices.hybrid_identity_key IS
  'Hybrid PQ identity public key (Ed25519+ML-DSA-65), 1984 bytes. Independent Ed25519 half, bound to the device identity by hybrid_identity_signature. NULL for Ed25519-only devices.';
COMMENT ON COLUMN devices.hybrid_identity_signature IS
  'Ed25519 cross-signature over ("KonstruktHybridId-v1" || hybrid_identity_key), 64 bytes, verifiable with devices.verifying_key. NULL when no hybrid key.';
COMMENT ON COLUMN devices.signed_prekey_hybrid_signature IS
  'Hybrid (Ed25519+ML-DSA-65) signature over the SPK X3DH sign-message, 3373 bytes. Kept in lockstep with signed_prekey_public. NULL when no hybrid key.';
COMMENT ON COLUMN devices.kyber_signed_pre_key_hybrid_signature IS
  'Hybrid signature over the Kyber SPK X3DH sign-message, 3373 bytes. Kept in lockstep with kyber_signed_pre_key. NULL when no hybrid key.';

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'devices' AND column_name = 'hybrid_identity_key'
    ) THEN
        RAISE EXCEPTION 'Migration failed: devices.hybrid_identity_key not created';
    END IF;

    RAISE NOTICE 'Migration 053 completed successfully!';
    RAISE NOTICE '  ✓ devices hybrid PQ identity columns added (nullable, backward compatible)';
END $$;
