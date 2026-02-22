-- Device tokens for APNs push notifications
-- Privacy-first design: encrypted tokens, minimal metadata, opt-in only
--
-- Philosophy:
-- - Notifications are OFF by default (like Option A: Pull-Only from docs)
-- - Users explicitly opt-in to Silent Push (Option B: background sync)
-- - No tracking metadata (no last_used_at, no updated_at timestamps)
-- - Encrypted device_token prevents spam if DB is compromised
-- - Encrypted device_name protects PII

CREATE TABLE IF NOT EXISTS device_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- APNs device token - ENCRYPTED for privacy
    -- Hash for deduplication, encrypted blob for actual use
    device_token_hash BYTEA NOT NULL,
    device_token_encrypted BYTEA NOT NULL,

    -- Device name - ENCRYPTED to protect PII
    -- Optional: user can identify their devices ("iPhone", "iPad")
    -- Never store raw names like "Alice's iPhone" or "Maxim's MacBook"
    device_name_encrypted BYTEA,

    -- Push notification preferences
    -- 'silent' = Silent push (Option B: background sync)
    -- 'visible_all' = All messages (opt-in visible notifications)
    -- 'visible_dm' = Direct messages only
    -- 'visible_mentions' = Mentions only
    -- 'visible_contacts' = From contacts only
    notification_filter TEXT NOT NULL DEFAULT 'silent',

    -- Whether push notifications are enabled for this device
    -- Default TRUE since registration implies opt-in
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Minimal metadata: only creation date (no time for privacy)
    created_date DATE NOT NULL DEFAULT CURRENT_DATE,

    -- NO updated_at - no tracking of preference changes
    -- NO last_used_at - no activity profiling
    -- NO timestamps with time - only dates to minimize metadata

    -- Ensure one user can't register same token multiple times
    UNIQUE(user_id, device_token_hash)
);

-- Index for faster lookups by user_id (only enabled devices)
CREATE INDEX IF NOT EXISTS idx_device_tokens_user_enabled
ON device_tokens(user_id)
WHERE enabled = TRUE;

-- Index for token hash lookups (for deduplication)
CREATE INDEX IF NOT EXISTS idx_device_tokens_hash
ON device_tokens(device_token_hash);

-- No trigger needed - we don't track updates for privacy!

-- Privacy notes:
-- 1. Device tokens are encrypted with server key (stored in env)
-- 2. If DB is compromised, attacker cannot:
--    - Send spam pushes (token is encrypted)
--    - Identify users by device names (encrypted)
--    - Profile activity (no timestamps)
-- 3. Only date (not time) stored to minimize metadata leakage
-- 4. Users must explicitly register token (opt-in, not opt-out)
