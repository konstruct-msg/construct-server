-- ============================================================================
-- Key Management Schema for Production
-- ============================================================================
--
-- Supports:
-- - Versioned keys with automatic rotation
-- - Audit logging for compliance (SOC 2, GDPR)
-- - Grace periods for seamless transitions
-- - Emergency revocation
--
-- ============================================================================

-- Master encryption key metadata (actual key in Vault)
-- This table tracks which Vault key version is active
CREATE TABLE IF NOT EXISTS master_keys (
    id SERIAL PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL,  -- 'jwt', 'apns', 'federation', 'backup'
    vault_path VARCHAR(255) NOT NULL,  -- e.g., 'transit/keys/jwt-signing'
    vault_version INTEGER NOT NULL,

    -- Lifecycle
    status VARCHAR(20) NOT NULL DEFAULT 'active',  -- 'active', 'rotating', 'deprecated', 'revoked'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,  -- When became primary for signing
    deprecated_at TIMESTAMPTZ,  -- When stopped using for signing (still valid for verify)
    revoked_at TIMESTAMPTZ,  -- Emergency revocation (immediately invalid)
    expires_at TIMESTAMPTZ,  -- Scheduled expiration

    -- Metadata
    key_id VARCHAR(64) UNIQUE NOT NULL,  -- For JWT 'kid' header
    algorithm VARCHAR(20) NOT NULL,  -- 'RS256', 'Ed25519', 'ChaCha20-Poly1305'
    key_size_bits INTEGER,

    -- Rotation info
    rotation_reason VARCHAR(100),  -- 'scheduled', 'emergency', 'compromise', 'policy'
    rotated_by VARCHAR(255),  -- 'system:scheduler', 'user:admin@example.com'
    previous_key_id VARCHAR(64) REFERENCES master_keys(key_id),

    CONSTRAINT valid_status CHECK (status IN ('active', 'rotating', 'deprecated', 'revoked')),
    CONSTRAINT valid_algorithm CHECK (algorithm IN ('RS256', 'RS384', 'RS512', 'Ed25519', 'ChaCha20-Poly1305', 'AES-256-GCM'))
);

-- Only one active key per type
CREATE UNIQUE INDEX idx_master_keys_active
    ON master_keys(key_type)
    WHERE status = 'active';

-- For finding keys by kid (JWT verification)
CREATE INDEX idx_master_keys_key_id ON master_keys(key_id);

-- For finding valid keys (active or deprecated within grace period)
CREATE INDEX idx_master_keys_valid
    ON master_keys(key_type, status, deprecated_at)
    WHERE status IN ('active', 'deprecated');

-- ============================================================================
-- Key Rotation Audit Log
-- ============================================================================

CREATE TABLE IF NOT EXISTS key_rotation_audit (
    id BIGSERIAL PRIMARY KEY,

    -- What was rotated
    key_type VARCHAR(50) NOT NULL,
    old_key_id VARCHAR(64),
    new_key_id VARCHAR(64),

    -- When and who
    event_type VARCHAR(50) NOT NULL,  -- 'rotation_started', 'rotation_completed', 'rotation_failed', 'emergency_revoke'
    event_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    initiated_by VARCHAR(255) NOT NULL,  -- 'system:scheduler', 'user:admin@example.com', 'system:emergency'

    -- Context
    reason TEXT,
    ip_address INET,
    user_agent TEXT,

    -- Result
    success BOOLEAN NOT NULL,
    error_code VARCHAR(50),
    error_message TEXT,
    duration_ms INTEGER,

    -- Additional context (JSON)
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_key_rotation_audit_time ON key_rotation_audit(event_at DESC);
CREATE INDEX idx_key_rotation_audit_key_type ON key_rotation_audit(key_type, event_at DESC);

-- ============================================================================
-- Encrypted Data Registry (for re-encryption tracking)
-- ============================================================================

CREATE TABLE IF NOT EXISTS encrypted_data_registry (
    id BIGSERIAL PRIMARY KEY,

    -- What data
    table_name VARCHAR(100) NOT NULL,
    record_id BIGINT NOT NULL,
    column_name VARCHAR(100) NOT NULL,

    -- Encryption info
    key_type VARCHAR(50) NOT NULL,
    key_version INTEGER NOT NULL,
    encrypted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Re-encryption tracking
    needs_reencryption BOOLEAN NOT NULL DEFAULT FALSE,
    reencryption_scheduled_at TIMESTAMPTZ,
    reencrypted_at TIMESTAMPTZ,

    UNIQUE (table_name, record_id, column_name)
);

CREATE INDEX idx_encrypted_data_needs_reencrypt
    ON encrypted_data_registry(key_type, needs_reencryption)
    WHERE needs_reencryption = TRUE;

-- ============================================================================
-- Key Access Log (for security monitoring)
-- ============================================================================

CREATE TABLE IF NOT EXISTS key_access_log (
    id BIGSERIAL,
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE,

    key_id VARCHAR(64) NOT NULL,
    operation VARCHAR(20) NOT NULL,  -- 'sign', 'verify', 'encrypt', 'decrypt'
    service_name VARCHAR(100) NOT NULL,

    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    error_code VARCHAR(50),

    -- For anomaly detection
    request_count INTEGER DEFAULT 1,  -- Aggregated per minute

    -- PRIMARY KEY must include partition_date for partitioned tables
    PRIMARY KEY (id, partition_date)
) PARTITION BY RANGE (partition_date);

-- Create partitions for the next 12 months
DO $$
DECLARE
    start_date DATE := DATE_TRUNC('month', CURRENT_DATE);
    end_date DATE;
    partition_name TEXT;
BEGIN
    FOR i IN 0..11 LOOP
        end_date := start_date + INTERVAL '1 month';
        partition_name := 'key_access_log_' || TO_CHAR(start_date, 'YYYY_MM');

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF key_access_log
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );

        start_date := end_date;
    END LOOP;
END $$;

-- ============================================================================
-- Functions
-- ============================================================================

-- Get current active key for a type
CREATE OR REPLACE FUNCTION get_active_key(p_key_type VARCHAR)
RETURNS TABLE (
    key_id VARCHAR(64),
    vault_path VARCHAR(255),
    vault_version INTEGER,
    algorithm VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT mk.key_id, mk.vault_path, mk.vault_version, mk.algorithm
    FROM master_keys mk
    WHERE mk.key_type = p_key_type
      AND mk.status = 'active'
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE;

-- Get all valid keys for verification (active + deprecated within grace period)
CREATE OR REPLACE FUNCTION get_valid_keys(p_key_type VARCHAR, p_grace_period INTERVAL DEFAULT '7 days')
RETURNS TABLE (
    key_id VARCHAR(64),
    vault_path VARCHAR(255),
    vault_version INTEGER,
    algorithm VARCHAR(20),
    is_primary BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        mk.key_id,
        mk.vault_path,
        mk.vault_version,
        mk.algorithm,
        (mk.status = 'active') as is_primary
    FROM master_keys mk
    WHERE mk.key_type = p_key_type
      AND (
          mk.status = 'active'
          OR (mk.status = 'deprecated' AND mk.deprecated_at > NOW() - p_grace_period)
      )
      AND mk.revoked_at IS NULL
    ORDER BY mk.status = 'active' DESC, mk.activated_at DESC;
END;
$$ LANGUAGE plpgsql STABLE;

-- Start key rotation (atomic)
CREATE OR REPLACE FUNCTION start_key_rotation(
    p_key_type VARCHAR,
    p_new_key_id VARCHAR,
    p_vault_path VARCHAR,
    p_vault_version INTEGER,
    p_algorithm VARCHAR,
    p_initiated_by VARCHAR,
    p_reason TEXT DEFAULT 'scheduled'
) RETURNS VARCHAR AS $$
DECLARE
    v_old_key_id VARCHAR(64);
BEGIN
    -- Get current active key
    SELECT key_id INTO v_old_key_id
    FROM master_keys
    WHERE key_type = p_key_type AND status = 'active';

    -- Mark old key as rotating
    UPDATE master_keys
    SET status = 'rotating'
    WHERE key_type = p_key_type AND status = 'active';

    -- Insert new key as active
    INSERT INTO master_keys (
        key_type, vault_path, vault_version, status,
        activated_at, key_id, algorithm,
        rotation_reason, rotated_by, previous_key_id
    ) VALUES (
        p_key_type, p_vault_path, p_vault_version, 'active',
        NOW(), p_new_key_id, p_algorithm,
        p_reason, p_initiated_by, v_old_key_id
    );

    -- Log the event
    INSERT INTO key_rotation_audit (
        key_type, old_key_id, new_key_id,
        event_type, initiated_by, reason, success
    ) VALUES (
        p_key_type, v_old_key_id, p_new_key_id,
        'rotation_started', p_initiated_by, p_reason, TRUE
    );

    RETURN p_new_key_id;
END;
$$ LANGUAGE plpgsql;

-- Complete key rotation (mark old as deprecated)
CREATE OR REPLACE FUNCTION complete_key_rotation(
    p_key_type VARCHAR,
    p_initiated_by VARCHAR
) RETURNS VOID AS $$
BEGIN
    -- Mark rotating keys as deprecated
    UPDATE master_keys
    SET status = 'deprecated',
        deprecated_at = NOW()
    WHERE key_type = p_key_type AND status = 'rotating';

    -- Log completion
    INSERT INTO key_rotation_audit (
        key_type,
        new_key_id,
        event_type,
        initiated_by,
        success
    )
    SELECT
        p_key_type,
        key_id,
        'rotation_completed',
        p_initiated_by,
        TRUE
    FROM master_keys
    WHERE key_type = p_key_type AND status = 'active';
END;
$$ LANGUAGE plpgsql;

-- Emergency key revocation
CREATE OR REPLACE FUNCTION emergency_revoke_key(
    p_key_id VARCHAR,
    p_initiated_by VARCHAR,
    p_reason TEXT
) RETURNS VOID AS $$
DECLARE
    v_key_type VARCHAR(50);
BEGIN
    -- Get key type
    SELECT key_type INTO v_key_type
    FROM master_keys
    WHERE key_id = p_key_id;

    IF v_key_type IS NULL THEN
        RAISE EXCEPTION 'Key not found: %', p_key_id;
    END IF;

    -- Revoke the key
    UPDATE master_keys
    SET status = 'revoked',
        revoked_at = NOW()
    WHERE key_id = p_key_id;

    -- Log the emergency revocation
    INSERT INTO key_rotation_audit (
        key_type, old_key_id,
        event_type, initiated_by, reason, success,
        metadata
    ) VALUES (
        v_key_type, p_key_id,
        'emergency_revoke', p_initiated_by, p_reason, TRUE,
        jsonb_build_object('severity', 'critical', 'requires_immediate_rotation', true)
    );

    -- Notify (this would trigger an alert in production)
    PERFORM pg_notify('key_emergency_revocation', p_key_id);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Cleanup old data (run periodically)
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_key_data(p_retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    v_deleted INTEGER := 0;
BEGIN
    -- Delete old access logs (keep partition management separate)
    -- Access logs are partitioned, so we drop old partitions instead

    -- Delete old audit logs beyond retention
    DELETE FROM key_rotation_audit
    WHERE event_at < NOW() - (p_retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    -- Clean up fully reencrypted registry entries
    DELETE FROM encrypted_data_registry
    WHERE reencrypted_at < NOW() - INTERVAL '30 days';

    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;
