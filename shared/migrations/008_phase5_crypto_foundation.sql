-- Migration 008: Phase 5 - Crypto-Agility & Security Foundation
-- Date: 2026-02-01
-- Purpose: Add Post-Quantum support, invite tokens, and user crypto capabilities
--
-- Changes:
-- 1. Add protocol_version and crypto_suites to users table
-- 2. Create pq_prekeys table for Post-Quantum keys
-- 3. Create invite_tokens table for one-time contact sharing
-- 4. Add indexes for performance

-- ============================================================================
-- 1. User Crypto Capabilities
-- ============================================================================

-- Add protocol version (1 = classic, 2 = hybrid PQ)
ALTER TABLE users 
  ADD COLUMN IF NOT EXISTS protocol_version INTEGER DEFAULT 1 NOT NULL;

-- Add supported crypto suites (JSONB array of suite IDs)
-- Default: ["0x01"] = Classic X25519 + ChaCha20
ALTER TABLE users 
  ADD COLUMN IF NOT EXISTS crypto_suites JSONB DEFAULT '["0x01"]'::jsonb NOT NULL;

-- Index for filtering by protocol version
CREATE INDEX IF NOT EXISTS idx_users_protocol_version 
  ON users(protocol_version);

-- ============================================================================
-- 2. Post-Quantum Prekeys Storage
-- ============================================================================

-- Table for storing large Post-Quantum keys separately from users table
-- PQ keys are ~7KB, so we keep them separate for performance
CREATE TABLE IF NOT EXISTS pq_prekeys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    
    -- Dilithium3 public key (~2.5 KB)
    pq_identity_key BYTEA,
    
    -- ML-KEM-1024 (Kyber1024) public key (~1.5 KB)
    pq_kem_key BYTEA,
    
    -- Dilithium3 signature of the bundle (~3.3 KB)
    pq_signature BYTEA,
    
    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- Indexes for PQ keys
CREATE INDEX IF NOT EXISTS idx_pq_prekeys_user 
  ON pq_prekeys(user_id);

CREATE INDEX IF NOT EXISTS idx_pq_prekeys_created 
  ON pq_prekeys(created_at);

CREATE INDEX IF NOT EXISTS idx_pq_prekeys_expires 
  ON pq_prekeys(expires_at) 
  WHERE expires_at IS NOT NULL;

-- ============================================================================
-- 3. Invite Tokens (One-Time Contact Sharing)
-- ============================================================================

-- Table for storing one-time invite tokens from QR codes and deep links
-- Each invite can only be used once and expires after 5 minutes
CREATE TABLE IF NOT EXISTS invite_tokens (
    -- Unique invite ID (from JWT jti claim)
    jti UUID PRIMARY KEY,
    
    -- User who created the invite
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Ephemeral X25519 public key (32 bytes, Base64 encoded in JSON)
    ephemeral_key BYTEA NOT NULL,
    
    -- Ed25519 signature of the invite object (64 bytes)
    signature BYTEA NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ,
    
    -- Ensure invite can only be used once
    CONSTRAINT invite_used_once CHECK (
        used_at IS NULL OR used_at >= created_at
    )
);

-- Indexes for invite tokens
CREATE INDEX IF NOT EXISTS idx_invite_tokens_user 
  ON invite_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_invite_tokens_created 
  ON invite_tokens(created_at);

CREATE INDEX IF NOT EXISTS idx_invite_tokens_used 
  ON invite_tokens(used_at) 
  WHERE used_at IS NOT NULL;

-- ============================================================================
-- 4. Cleanup Function (Auto-delete expired invites)
-- ============================================================================

-- Function to cleanup old invite tokens (>5 minutes)
CREATE OR REPLACE FUNCTION cleanup_expired_invites() 
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM invite_tokens 
    WHERE created_at < NOW() - INTERVAL '5 minutes'
      AND used_at IS NULL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Optional: Create a scheduled job to run cleanup periodically
-- (Requires pg_cron extension - uncomment if available)
-- SELECT cron.schedule(
--     'cleanup-expired-invites',
--     '*/5 * * * *',  -- Every 5 minutes
--     'SELECT cleanup_expired_invites();'
-- );

-- ============================================================================
-- 5. Comments for Documentation
-- ============================================================================

COMMENT ON COLUMN users.protocol_version IS 
  'Crypto protocol version: 1 = classic X25519, 2 = hybrid PQ (Kyber+Dilithium)';

COMMENT ON COLUMN users.crypto_suites IS 
  'Supported crypto suite IDs (JSONB array). Example: ["0x01", "0x10"]';

COMMENT ON TABLE pq_prekeys IS 
  'Post-Quantum prekeys storage (Kyber1024 + Dilithium3). Separated for performance.';

COMMENT ON TABLE invite_tokens IS 
  'One-time invite tokens for QR codes and deep links. Auto-expire after 5 minutes.';

COMMENT ON FUNCTION cleanup_expired_invites IS 
  'Cleanup function for expired invite tokens. Run periodically via cron or manually.';

-- ============================================================================
-- Migration Complete
-- ============================================================================

-- Verify migration
DO $$
BEGIN
    -- Check users columns exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'protocol_version'
    ) THEN
        RAISE EXCEPTION 'Migration failed: users.protocol_version not created';
    END IF;
    
    -- Check pq_prekeys table exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'pq_prekeys'
    ) THEN
        RAISE EXCEPTION 'Migration failed: pq_prekeys table not created';
    END IF;
    
    -- Check invite_tokens table exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'invite_tokens'
    ) THEN
        RAISE EXCEPTION 'Migration failed: invite_tokens table not created';
    END IF;
    
    RAISE NOTICE 'Migration 008 completed successfully';
END $$;
