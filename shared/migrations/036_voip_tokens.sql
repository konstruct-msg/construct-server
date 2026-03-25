-- Migration 036: VoIP tokens for APNs VoIP pushes (incoming calls / CallKit)
--
-- Privacy-first design:
-- - Token is encrypted at rest
-- - Only minimal metadata (date, platform, environment, device_id)
-- - No timestamps with time / no last_used_at

CREATE TABLE IF NOT EXISTS voip_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Stable device ID for upsert (Keychain UUID)
    device_id TEXT NOT NULL,

    -- APNs VoIP token — encrypted
    voip_token_hash BYTEA NOT NULL,
    voip_token_encrypted BYTEA NOT NULL,

    -- Minimal metadata
    platform TEXT NOT NULL DEFAULT 'ios',          -- "ios" | "macos"
    push_environment TEXT NOT NULL DEFAULT 'sandbox', -- "sandbox" | "production"
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_date DATE NOT NULL DEFAULT CURRENT_DATE,

    UNIQUE(user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_voip_tokens_user_enabled
ON voip_tokens(user_id)
WHERE enabled = TRUE;

