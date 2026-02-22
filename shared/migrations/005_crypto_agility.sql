-- Migration 005: Crypto-Agility Support (API v3)
-- This migration updates the database schema to support multiple cipher suites

-- 1. Drop the unused prekeys table
DROP TABLE IF EXISTS prekeys;

-- 2. Create new table for crypto-agile key bundles
CREATE TABLE IF NOT EXISTS key_bundles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

    -- Master identity key used to verify the signature (Ed25519, 32 bytes)
    master_identity_key BYTEA NOT NULL,

    -- Serialized BundleData (JSON format, contains all supported suites)
    bundle_data BYTEA NOT NULL,

    -- Ed25519 signature of bundle_data (64 bytes)
    signature BYTEA NOT NULL,

    -- Timestamps
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_key_bundles_updated_at ON key_bundles(updated_at);

-- 4. Migrate data from old user_key_bundles to new key_bundles table
-- Note: This migration assumes that existing data uses the classic X25519 suite (suite_id = 1)
-- The migration creates a BundleData structure for each existing bundle
INSERT INTO key_bundles (user_id, master_identity_key, bundle_data, signature, registered_at, updated_at)
SELECT
    user_id,
    -- Decode base64 verifying_key from TEXT to BYTEA (Ed25519, 32 bytes)
    decode(verifying_key, 'base64'),
    -- Create a BundleData JSON structure with suite_id = 1 (CLASSIC_X25519)
    -- Format: {"userId":"...","timestamp":"...","supportedSuites":[{"suiteId":1,"identityKey":"...","signedPrekey":"...","oneTimePrekeys":[]}]}
    convert_to(
        jsonb_build_object(
            'userId', user_id::TEXT,
            'timestamp', to_char(registered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'supportedSuites', jsonb_build_array(
                jsonb_build_object(
                    'suiteId', 1,
                    'identityKey', identity_public,
                    'signedPrekey', signed_prekey_public,
                    'oneTimePrekeys', '[]'::jsonb
                )
            )
        )::TEXT,
        'UTF8'
    ),
    -- Decode base64 signature from TEXT to BYTEA (Ed25519, 64 bytes)
    decode(signature, 'base64'),
    registered_at,
    COALESCE(updated_at, registered_at)
FROM user_key_bundles
ON CONFLICT (user_id) DO NOTHING;

-- 5. Drop the old user_key_bundles table
DROP TABLE IF EXISTS user_key_bundles;
