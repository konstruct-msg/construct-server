-- ============================================================================
-- Migration 015: Dynamic Invites v2 Support
-- ============================================================================
--
-- Purpose: Track used invites (JTI) for one-time use enforcement
--
-- Features:
-- - v1/v2 invite support (optional device_id)
-- - JTI uniqueness constraint
-- - Auto-cleanup of expired entries
--
-- Related: INVITE_V2_MIGRATION.md
-- ============================================================================

-- Create table for tracking used invites
CREATE TABLE IF NOT EXISTS used_invites (
    -- One-time JWT ID (prevents replay attacks)
    jti UUID PRIMARY KEY,
    
    -- User who created the invite
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Device ID (v2 only, NULL for v1 invites)
    device_id VARCHAR(32),
    
    -- When invite was used
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Expiration time (for auto-cleanup)
    -- TTL: 180 seconds (3 minutes)
    expires_at TIMESTAMPTZ NOT NULL
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Cleanup index (for cron job DELETE WHERE expires_at < NOW())
-- Regular B-tree index on expires_at - no partial index needed
CREATE INDEX IF NOT EXISTS idx_used_invites_expires_at
ON used_invites(expires_at);

-- User lookup (who created this invite?)
CREATE INDEX IF NOT EXISTS idx_used_invites_user_id
ON used_invites(user_id);

-- Device lookup (v2 invites)
CREATE INDEX IF NOT EXISTS idx_used_invites_device_id
ON used_invites(device_id)
WHERE device_id IS NOT NULL;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE used_invites IS 'Tracks used Dynamic Invites for one-time use enforcement (v1/v2)';
COMMENT ON COLUMN used_invites.jti IS 'One-time JWT ID (UUIDv4) - prevents replay attacks';
COMMENT ON COLUMN used_invites.user_id IS 'User who created the invite';
COMMENT ON COLUMN used_invites.device_id IS 'Device ID (v2 only, NULL for v1 backwards compat)';
COMMENT ON COLUMN used_invites.expires_at IS 'Expiration time (TTL: 180 seconds = 3 minutes)';
