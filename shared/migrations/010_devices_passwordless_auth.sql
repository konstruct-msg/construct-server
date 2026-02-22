-- ============================================================================
-- Devices Table - Passwordless Device-Based Authentication (Phase 1)
-- ============================================================================
--
-- Purpose: Implement passwordless authentication where each device is an identity
-- 
-- Key Concepts:
-- - device_id = PRIMARY identifier
-- - Each device has its own Ed25519 signing key
-- - Multi-device support built-in
--
-- Related: SERVER_PASSWORDLESS_AUTH_SPEC.md
-- ============================================================================

-- Devices table - Core identity for passwordless auth
CREATE TABLE IF NOT EXISTS devices (
    -- ========================================================================
    -- IDENTITY (Primary)
    -- ========================================================================
    
    -- Device ID = first 16 bytes of SHA256(identity_public_key)
    -- Format: lowercase hex string, exactly 16 chars
    -- Example: "a1b2c3d4e5f6g7h8"
    device_id VARCHAR(32) PRIMARY KEY,
    
    -- Server hostname for federation
    -- Example: "ams.konstruct.cc", "msk.konstruct.cc"
    server_hostname VARCHAR(255) NOT NULL,
    
    -- Link to existing users table (optional, for migration)
    -- NULL during registration, populated after password→device migration
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        
    -- ========================================================================
    -- CRYPTOGRAPHY (Required for Authentication + E2EE)
    -- ========================================================================
    
    -- Ed25519 verifying key for request signature verification (32 bytes)
    -- This is used to authenticate API requests via X-Signature header
    -- Base64-encoded when stored/transmitted
    verifying_key BYTEA NOT NULL,
    
    -- ML-KEM/Curve25519 identity public key for E2EE (varies by suite)
    -- Base64-encoded when stored/transmitted
    identity_public BYTEA NOT NULL,
    
    -- Signed prekey public (for Double Ratchet)
    -- Base64-encoded when stored/transmitted
    signed_prekey_public BYTEA NOT NULL,
    
    -- Crypto suite identifier
    -- Examples: "ML-KEM-768+Ed25519", "Curve25519+Ed25519"
    suite_id VARCHAR(50) NOT NULL DEFAULT 'Curve25519+Ed25519',
    
    -- ========================================================================
    -- METADATA
    -- ========================================================================
    
    -- When device was first registered
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Last time device made an authenticated request
    last_active_at TIMESTAMPTZ,
    
    -- ========================================================================
    -- KEY MANAGEMENT
    -- ========================================================================
    
    -- When verifying_key was last updated (for security auditing)
    key_updated_at TIMESTAMPTZ,
    
    -- Reason for key update (e.g., "registration_bug_fix", "security_rotation")
    key_update_reason VARCHAR(100),
    
    -- ========================================================================
    -- DEVICE STATUS
    -- ========================================================================
    
    -- Whether device is active (can be disabled by user or server)
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Platform info (optional, for admin)
    -- Examples: "ios", "android", "web", "macos"
    platform VARCHAR(20),
    
    -- Device name (user-provided, optional)
    -- Example: "iPhone 15 Pro", "MacBook Air"
    device_name VARCHAR(100)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Federation lookups
CREATE INDEX IF NOT EXISTS idx_devices_server 
ON devices(server_hostname);

-- User migration lookups (when linking devices to existing users)
CREATE INDEX IF NOT EXISTS idx_devices_user_id 
ON devices(user_id) 
WHERE user_id IS NOT NULL;

-- Active devices only (for performance)
CREATE INDEX IF NOT EXISTS idx_devices_active 
ON devices(device_id) 
WHERE is_active = TRUE;

-- Recent activity tracking
CREATE INDEX IF NOT EXISTS idx_devices_last_active 
ON devices(last_active_at DESC) 
WHERE is_active = TRUE;

-- ============================================================================
-- PROOF OF WORK CHALLENGES (Temporary Storage)
-- ============================================================================

-- PoW challenges to prevent bot registration
-- These are short-lived (5 minute TTL)
CREATE TABLE IF NOT EXISTS pow_challenges (
    -- Random challenge string (server-generated)
    challenge VARCHAR(64) PRIMARY KEY,
    
    -- Difficulty level (number of leading zeros required)
    -- Typical range: 4-6 for mobile devices
    difficulty SMALLINT NOT NULL,
    
    -- When challenge was created
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- When challenge expires (typically created_at + 5 minutes)
    expires_at TIMESTAMPTZ NOT NULL,
    
    -- Whether challenge has been used (one-time use only)
    used BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Which IP requested this challenge (for rate limiting)
    requester_ip INET
);

-- Index for cleanup jobs
CREATE INDEX IF NOT EXISTS idx_pow_expires 
ON pow_challenges(expires_at) 
WHERE NOT used;

-- Cleanup job (run every minute):
-- DELETE FROM pow_challenges WHERE expires_at < NOW() - INTERVAL '1 hour';

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE devices IS 'Device-based identity for passwordless authentication';
COMMENT ON COLUMN devices.device_id IS 'Primary identifier: SHA256(identity_public)[0..16]';
COMMENT ON COLUMN devices.verifying_key IS 'Ed25519 public key for request signature verification';
COMMENT ON COLUMN devices.user_id IS 'Optional link to users table (for password→device migration)';

COMMENT ON TABLE pow_challenges IS 'Proof-of-work challenges to prevent bot registration (5 min TTL)';
COMMENT ON COLUMN pow_challenges.difficulty IS 'Number of leading zeros required in SHA256 hash';
