-- Migration 025: Add device_id, push_provider, push_environment to device_tokens
--
-- device_id: stable identifier from iOS Keychain (identifierForVendor or custom UUID).
--   Used for upsert — when APNs rotates a token, we update the existing row rather
--   than creating a duplicate.
--
-- push_provider: 'apns' | 'fcm' (FCM reserved for future Android support)
--
-- push_environment: 'sandbox' | 'production'
--   sandbox  → api.sandbox.push.apple.com (debug/development builds)
--   production → api.push.apple.com (App Store / TestFlight production)
--
-- Privacy note: device_id is stored as-is (not encrypted) because it is not a PII
-- identifier — it cannot be used to identify the user or the device outside this server.

ALTER TABLE device_tokens
    ADD COLUMN IF NOT EXISTS device_id TEXT,
    ADD COLUMN IF NOT EXISTS push_provider TEXT NOT NULL DEFAULT 'apns',
    ADD COLUMN IF NOT EXISTS push_environment TEXT NOT NULL DEFAULT 'sandbox';

-- Unique constraint on (user_id, device_id) for upsert when device_id is provided.
-- Partial index: only rows with a non-null device_id participate.
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_tokens_user_device_id
    ON device_tokens (user_id, device_id)
    WHERE device_id IS NOT NULL;

-- Index for environment-filtered push queries (send only to matching environment)
CREATE INDEX IF NOT EXISTS idx_device_tokens_env
    ON device_tokens (user_id, push_environment)
    WHERE enabled = TRUE;
