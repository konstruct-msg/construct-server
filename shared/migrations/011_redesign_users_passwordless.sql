-- ============================================================================
-- Migration 011: Redesign users table for passwordless auth
-- ============================================================================
--
-- Purpose: Transform users from password-based to device-group container
--
-- Changes:
-- - Remove password_hash (passwordless!)
-- - Remove unique username constraint (moved to optional field)
-- - Add display_name with auto-generation flag
-- - Add optional username for search/discovery
-- - Minimal server-side data (privacy first)
--
-- Related: USERS_TABLE_DESIGN.md
-- ============================================================================

-- Drop old users table (backup first!)
-- WARNING: This will cascade to all foreign keys
-- Run this ONLY after migration script is ready

-- Step 1: Backup existing data
CREATE TABLE users_legacy AS SELECT * FROM users;

-- Step 2: Drop old users table and recreate
DROP TABLE IF EXISTS users CASCADE;

-- Step 3: Create new minimal users table
CREATE TABLE users (
    -- ========================================================================
    -- IDENTITY
    -- ========================================================================
    
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- ========================================================================
    -- USERNAME (optional, for search/discovery)
    -- ========================================================================
    
    -- Username - optional handle for search (@alice)
    -- NULL = maximum privacy (only QR/invite links)
    -- NOT NULL = searchable via @username lookup
    -- Format: lowercase alphanumeric + underscore, 3-20 chars
    username VARCHAR(20) UNIQUE CHECK (
        username IS NULL OR 
        (username ~ '^[a-z0-9_]{3,20}$')
    ),
    
    -- ========================================================================
    -- ACCOUNT RECOVERY (optional)
    -- ========================================================================
    
    -- Ed25519 public key derived from user's 24-word seed phrase
    -- NULL = recovery not enabled (user skipped setup)
    -- NOT NULL = account can be recovered with seed phrase
    -- Can be set ONCE (on first setup), cannot be changed
    recovery_public_key BYTEA UNIQUE CHECK (
        recovery_public_key IS NULL OR 
        length(recovery_public_key) = 32
    ),
    
    -- When recovery was last used (for cooldown protection)
    -- NULL = never used recovery
    -- NOT NULL = timestamp of last recovery attempt
    last_recovery_at TIMESTAMPTZ,
    
    -- ========================================================================
    -- DEVICE MANAGEMENT
    -- ========================================================================
    
    -- Primary device (first registered device)
    -- Used for: determining account age (anti-spam), recovery coordination
    primary_device_id VARCHAR(32) REFERENCES devices(device_id) ON DELETE SET NULL
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Username search (only for non-NULL usernames)
CREATE INDEX idx_users_username ON users(username) WHERE username IS NOT NULL;

-- Primary device lookup (for warmup age check)
CREATE INDEX idx_users_primary_device ON users(primary_device_id);

-- Recovery key lookup (for account recovery)
CREATE INDEX idx_users_recovery_key ON users(recovery_public_key) 
    WHERE recovery_public_key IS NOT NULL;

-- Recovery cooldown check
CREATE INDEX idx_users_recovery_cooldown ON users(last_recovery_at) 
    WHERE last_recovery_at IS NOT NULL;

-- ============================================================================
-- RESERVED USERNAMES (prevent squatting)
-- ============================================================================

CREATE TABLE reserved_usernames (
    username VARCHAR(20) PRIMARY KEY,
    reason TEXT NOT NULL,
    reserved_at TIMESTAMPTZ DEFAULT NOW()
);

-- Reserve system usernames
INSERT INTO reserved_usernames (username, reason) VALUES
    ('admin', 'System reserved'),
    ('administrator', 'System reserved'),
    ('support', 'System reserved'),
    ('help', 'System reserved'),
    ('konstruct', 'Brand protection'),
    ('official', 'System reserved'),
    ('system', 'System reserved'),
    ('bot', 'System reserved'),
    ('root', 'System reserved'),
    ('moderator', 'System reserved'),
    ('null', 'Reserved keyword'),
    ('undefined', 'Reserved keyword'),
    ('test', 'System reserved'),
    ('demo', 'System reserved')
ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- CONSTRAINTS & TRIGGERS
-- ============================================================================

-- Prevent setting reserved usernames
CREATE OR REPLACE FUNCTION check_username_not_reserved()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.username IS NOT NULL AND EXISTS (
        SELECT 1 FROM reserved_usernames WHERE username = NEW.username
    ) THEN
        RAISE EXCEPTION 'Username % is reserved', NEW.username;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_username_not_reserved
    BEFORE INSERT OR UPDATE OF username ON users
    FOR EACH ROW
    EXECUTE FUNCTION check_username_not_reserved();

-- Prevent changing recovery_public_key once set (can only set once)
CREATE OR REPLACE FUNCTION check_recovery_key_immutable()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.recovery_public_key IS NOT NULL AND 
       NEW.recovery_public_key IS DISTINCT FROM OLD.recovery_public_key THEN
        RAISE EXCEPTION 'Recovery key cannot be changed once set';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_recovery_key_immutable
    BEFORE UPDATE OF recovery_public_key ON users
    FOR EACH ROW
    EXECUTE FUNCTION check_recovery_key_immutable();

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Check if user account is in warmup period (anti-spam)
-- Returns true if account < 24-48 hours old
CREATE OR REPLACE FUNCTION is_user_in_warmup(user_uuid UUID)
RETURNS BOOLEAN AS $$
DECLARE
    primary_device_registered_at TIMESTAMPTZ;
BEGIN
    -- Get registration time of primary device
    SELECT d.registered_at INTO primary_device_registered_at
    FROM users u
    JOIN devices d ON d.device_id = u.primary_device_id
    WHERE u.id = user_uuid;
    
    IF primary_device_registered_at IS NULL THEN
        -- No primary device = treat as new (cautious approach)
        RETURN true;
    END IF;
    
    -- Check if < 48 hours ago (can be configured: 24-48h)
    RETURN (NOW() - primary_device_registered_at) < INTERVAL '48 hours';
END;
$$ LANGUAGE plpgsql;

-- Get account age in hours (for rate limiting logic)
CREATE OR REPLACE FUNCTION get_user_account_age_hours(user_uuid UUID)
RETURNS NUMERIC AS $$
DECLARE
    primary_device_registered_at TIMESTAMPTZ;
BEGIN
    SELECT d.registered_at INTO primary_device_registered_at
    FROM users u
    JOIN devices d ON d.device_id = u.primary_device_id
    WHERE u.id = user_uuid;
    
    IF primary_device_registered_at IS NULL THEN
        RETURN 0;
    END IF;
    
    RETURN EXTRACT(EPOCH FROM (NOW() - primary_device_registered_at)) / 3600;
END;
$$ LANGUAGE plpgsql;

-- Check if user can use recovery (cooldown check)
-- Returns true if last recovery was > 7 days ago (or never used)
CREATE OR REPLACE FUNCTION can_user_recover(user_uuid UUID)
RETURNS BOOLEAN AS $$
DECLARE
    last_recovery TIMESTAMPTZ;
BEGIN
    SELECT last_recovery_at INTO last_recovery
    FROM users
    WHERE id = user_uuid;
    
    IF last_recovery IS NULL THEN
        -- Never used recovery = allowed
        RETURN true;
    END IF;
    
    -- Check if > 7 days ago
    RETURN (NOW() - last_recovery) > INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE users IS 'User accounts - minimal metadata, maximum privacy';
COMMENT ON COLUMN users.id IS 'User UUID - groups multiple devices together';
COMMENT ON COLUMN users.username IS 'Optional @username for search (NULL = Signal-like privacy, no search)';
COMMENT ON COLUMN users.recovery_public_key IS 'Ed25519 public key from 24-word seed (NULL = recovery disabled, immutable once set)';
COMMENT ON COLUMN users.last_recovery_at IS 'Last successful account recovery timestamp (for 7-day cooldown)';
COMMENT ON COLUMN users.primary_device_id IS 'First registered device (used ONLY for warmup age check via devices.registered_at)';

-- ============================================================================
-- DATA NOT STORED ON SERVER (E2EE / Client-side)
-- ============================================================================
--
-- The following data is NOT in this table (privacy by design):
--
-- ❌ display_name     → Stored ONLY on client, shared via E2EE messages
-- ❌ avatar_url       → Stored locally, shared via E2EE (media service)
-- ❌ bio              → Stored locally, shared via E2EE messages
-- ❌ created_at       → Not tracked! Use devices.registered_at via JOIN for anti-spam
-- ❌ last_seen        → Not tracked (privacy)
-- ❌ last_active_at   → Not tracked (privacy)
-- ❌ online_status    → Not tracked (privacy)
-- ❌ account_status   → No soft deletes (hard delete only)
-- ❌ warmup_status    → Calculated dynamically via is_user_in_warmup(), not stored
-- ❌ privacy_settings → Stored on client device
-- ❌ contacts_list    → Stored on client device (encrypted)
-- ❌ read_receipts    → Handled client-side
-- ❌ recovery_seed    → NEVER stored! Client-only (24 words)
--
-- Minimal metadata for security only:
-- ✅ username → ONLY for optional search (like Signal username)
-- ✅ last_recovery_at → Only for 7-day cooldown (anti-abuse)
-- ✅ primary_device_id → Used to check account age via devices.registered_at (anti-spam)
--
-- Server knows: user exists, optional @username, devices, recovery enabled?
-- Hard delete: DELETE FROM users → cascades to all devices (permanent)
-- ============================================================================
