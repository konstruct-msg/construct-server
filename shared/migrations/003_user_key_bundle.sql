CREATE TABLE IF NOT EXISTS user_key_bundles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    identity_public TEXT NOT NULL,
    signed_prekey_public TEXT NOT NULL,
    signature TEXT NOT NULL,
    verifying_key TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_key_bundles_expires ON user_key_bundles(expires_at);
CREATE INDEX idx_key_bundles_updated_at ON user_key_bundles(updated_at);
