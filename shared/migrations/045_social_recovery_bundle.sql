ALTER TABLE users ADD COLUMN IF NOT EXISTS social_recovery_bundle BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS social_recovery_bundle_set_at TIMESTAMPTZ;
