-- ============================================================================
-- Migration 022: One-Time Pre-Keys for X3DH
-- ============================================================================
--
-- Purpose: Store one-time pre-keys for forward secrecy in X3DH key exchange
--
-- Background:
-- - X3DH uses one-time pre-keys for perfect forward secrecy
-- - Each key can only be used once, then must be deleted
-- - Clients should keep ~100 pre-keys on server
-- - When count drops below 20, client uploads more
--
-- Key lifecycle:
-- 1. Client generates batch of one-time pre-keys
-- 2. Client uploads public keys to server
-- 3. Initiator fetches bundle (consuming one pre-key)
-- 4. Server deletes consumed key
-- 5. If no one-time keys available, session still works (less forward secrecy)
--
-- Related: key_service.proto, X3DH protocol spec
-- ============================================================================

-- One-time pre-keys storage
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    -- ========================================================================
    -- PRIMARY KEY
    -- ========================================================================
    
    -- Composite primary key: device + key_id
    device_id VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    
    -- ========================================================================
    -- KEY DATA
    -- ========================================================================
    
    -- X25519 public key (32 bytes)
    public_key BYTEA NOT NULL,
    
    -- ========================================================================
    -- METADATA
    -- ========================================================================
    
    -- When this key was uploaded
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Composite primary key
    PRIMARY KEY (device_id, key_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Fast lookup of available keys for a device
CREATE INDEX IF NOT EXISTS idx_otp_device 
ON one_time_prekeys(device_id);

-- Cleanup old keys (if needed)
CREATE INDEX IF NOT EXISTS idx_otp_uploaded 
ON one_time_prekeys(uploaded_at);

-- ============================================================================
-- SIGNED PRE-KEY HISTORY (for message recovery)
-- ============================================================================

-- When rotating signed pre-keys, keep old ones briefly for in-flight messages
CREATE TABLE IF NOT EXISTS signed_prekey_archive (
    -- ========================================================================
    -- PRIMARY KEY
    -- ========================================================================
    
    device_id VARCHAR(32) NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    
    -- ========================================================================
    -- KEY DATA
    -- ========================================================================
    
    -- X25519 public key (32 bytes)
    public_key BYTEA NOT NULL,
    
    -- Ed25519 signature (64 bytes)
    signature BYTEA NOT NULL,
    
    -- ========================================================================
    -- METADATA
    -- ========================================================================
    
    -- When this key was archived (replaced)
    archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- When this key should be deleted (48 hours after archival)
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '48 hours',
    
    -- Reason for rotation
    rotation_reason VARCHAR(50),
    
    PRIMARY KEY (device_id, key_id)
);

-- Cleanup expired archived keys
CREATE INDEX IF NOT EXISTS idx_spk_archive_expires 
ON signed_prekey_archive(expires_at);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE one_time_prekeys IS 
  'One-time pre-keys for X3DH forward secrecy. Each key used once then deleted.';
  
COMMENT ON COLUMN one_time_prekeys.key_id IS 
  'Client-generated key ID, unique per device';

COMMENT ON TABLE signed_prekey_archive IS 
  'Archive of rotated signed pre-keys, kept 48h for in-flight messages';

-- ============================================================================
-- VALIDATION
-- ============================================================================

DO $$
BEGIN
    -- Verify one_time_prekeys table exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'one_time_prekeys'
    ) THEN
        RAISE EXCEPTION 'Migration failed: one_time_prekeys table not created';
    END IF;

    -- Verify signed_prekey_archive table exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'signed_prekey_archive'
    ) THEN
        RAISE EXCEPTION 'Migration failed: signed_prekey_archive table not created';
    END IF;

    RAISE NOTICE 'Migration 022 completed successfully!';
    RAISE NOTICE '  ✓ one_time_prekeys table created';
    RAISE NOTICE '  ✓ signed_prekey_archive table created';
END $$;
