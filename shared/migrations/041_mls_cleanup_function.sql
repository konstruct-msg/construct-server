-- Migration 041: MLS Cleanup Function + Rate Limit Events
-- Purpose: Automated cleanup of expired MLS data + Rate limiting support
-- Run daily via pg_cron or application scheduler

-- Rate limit events table (for DB-based rate limiting)
CREATE TABLE IF NOT EXISTS rate_limit_events (
    id BIGSERIAL PRIMARY KEY,
    key VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_rate_limit_events_key_created 
ON rate_limit_events(key, created_at);

-- Auto-cleanup old rate limit events (older than 7 days)
CREATE OR REPLACE FUNCTION cleanup_rate_limit_events()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM rate_limit_events
    WHERE created_at < NOW() - INTERVAL '7 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Cleanup expired group messages
CREATE OR REPLACE FUNCTION cleanup_expired_group_messages()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM group_messages
        WHERE expires_at < NOW()
        RETURNING group_id, expires_at
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    -- Update cleanup tracking
    UPDATE mls_groups
    SET messages_deleted_before = (
        SELECT MIN(expires_at) FROM deleted
    )
    WHERE group_id IN (SELECT DISTINCT group_id FROM deleted);
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Cleanup expired commits (older than 30 days)
CREATE OR REPLACE FUNCTION cleanup_expired_group_commits()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM group_commits
        WHERE created_at < NOW() - INTERVAL '30 days'
        RETURNING group_id
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Cleanup expired invites (older than 7 days)
CREATE OR REPLACE FUNCTION cleanup_expired_group_invites()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM group_invites
        WHERE expires_at < NOW()
        RETURNING group_id
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Cleanup expired KeyPackages (older than 30 days)
CREATE OR REPLACE FUNCTION cleanup_expired_key_packages()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM group_key_packages
        WHERE expires_at < NOW()
        RETURNING user_id
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Hard-delete dissolved groups (older than 24 hours)
CREATE OR REPLACE FUNCTION cleanup_dissolved_groups()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- First delete child records
    DELETE FROM group_messages
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    DELETE FROM group_commits
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    DELETE FROM group_invites
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    DELETE FROM group_members
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    DELETE FROM group_admins
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    DELETE FROM group_topics
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    DELETE FROM group_invite_links
    WHERE group_id IN (
        SELECT group_id FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
    );
    
    -- Finally delete the group itself
    WITH deleted AS (
        DELETE FROM mls_groups
        WHERE dissolved_at < NOW() - INTERVAL '24 hours'
        RETURNING group_id
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Master cleanup function (calls all cleanup functions)
CREATE OR REPLACE FUNCTION cleanup_mls_expired()
RETURNS TABLE (
    operation TEXT,
    deleted_count INTEGER
) AS $$
BEGIN
    RETURN QUERY SELECT 'group_messages'::TEXT, cleanup_expired_group_messages();
    RETURN QUERY SELECT 'group_commits'::TEXT, cleanup_expired_group_commits();
    RETURN QUERY SELECT 'group_invites'::TEXT, cleanup_expired_group_invites();
    RETURN QUERY SELECT 'key_packages'::TEXT, cleanup_expired_key_packages();
    RETURN QUERY SELECT 'dissolved_groups'::TEXT, cleanup_dissolved_groups();
END;
$$ LANGUAGE plpgsql;

-- Optional: Schedule with pg_cron if available
-- SELECT cron.schedule('mls-cleanup-daily', '0 3 * * *', 'SELECT * FROM cleanup_mls_expired()');
