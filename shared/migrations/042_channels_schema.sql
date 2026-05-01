-- Migration 042: Channels Schema
-- Purpose: Public/Private broadcast channels with Sender Key encryption

-- Channel visibility enum
CREATE TYPE channel_visibility AS ENUM ('PUBLIC', 'PRIVATE');

-- Channels table
CREATE TABLE channels (
    channel_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_device_id VARCHAR(64) NOT NULL,
    visibility channel_visibility NOT NULL DEFAULT 'PUBLIC',
    encrypted_metadata BYTEA NOT NULL,
    max_subscribers INTEGER DEFAULT 0, -- 0 = unlimited
    retention_days INTEGER DEFAULT 90,
    subscriber_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    CONSTRAINT chk_max_subscribers CHECK (max_subscribers >= 0 AND max_subscribers <= 100000),
    CONSTRAINT chk_retention_days CHECK (retention_days >= 1 AND retention_days <= 365)
);

CREATE INDEX idx_channels_visibility ON channels(visibility);
CREATE INDEX idx_channels_owner ON channels(owner_device_id);
CREATE INDEX idx_channels_created ON channels(created_at);

-- Channel subscribers
CREATE TABLE channel_subscribers (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    device_id VARCHAR(64) NOT NULL,
    subscribed_at TIMESTAMPTZ DEFAULT NOW(),
    role VARCHAR(32) DEFAULT 'SUBSCRIBER', -- SUBSCRIBER, ADMIN
    is_owner BOOLEAN DEFAULT FALSE,
    
    PRIMARY KEY (channel_id, device_id)
);

CREATE INDEX idx_channel_subscribers_device ON channel_subscribers(device_id);
CREATE INDEX idx_channel_subscribers_role ON channel_subscribers(role);

-- Channel admins (denormalized for fast lookup)
CREATE TABLE channel_admins (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    device_id VARCHAR(64) NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    granted_by VARCHAR(64) NOT NULL,
    
    PRIMARY KEY (channel_id, device_id)
);

-- Sender Keys (one per channel per device)
CREATE TABLE channel_sender_keys (
    channel_id UUID NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    encrypted_sender_key BYTEA NOT NULL,
    distributed_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    
    PRIMARY KEY (channel_id, device_id),
    FOREIGN KEY (channel_id) REFERENCES channels(channel_id) ON DELETE CASCADE
);

-- Channel posts
CREATE TABLE channel_posts (
    post_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    sender_device_id VARCHAR(64) NOT NULL,
    sequence_number BIGINT NOT NULL,
    ciphertext BYTEA NOT NULL, -- Sender Key encrypted
    thread_id UUID, -- For replies
    client_message_id VARCHAR(64), -- For dedup
    sent_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    
    CONSTRAINT unique_channel_sequence UNIQUE (channel_id, sequence_number)
);

CREATE INDEX idx_channel_posts_channel_seq ON channel_posts(channel_id, sequence_number);
CREATE INDEX idx_channel_posts_thread ON channel_posts(thread_id);
CREATE INDEX idx_channel_posts_sent ON channel_posts(sent_at);
CREATE INDEX idx_channel_posts_expires ON channel_posts(expires_at);
CREATE INDEX idx_channel_posts_client_msg ON channel_posts(client_message_id);

-- Channel invite links (for PRIVATE channels)
CREATE TABLE channel_invite_links (
    token VARCHAR(32) PRIMARY KEY,
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    created_by VARCHAR(64) NOT NULL,
    max_uses INTEGER, -- NULL = unlimited
    use_count INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT chk_max_uses CHECK (max_uses IS NULL OR max_uses > 0),
    CONSTRAINT chk_use_count CHECK (use_count >= 0)
);

CREATE INDEX idx_channel_invite_links_channel ON channel_invite_links(channel_id);
CREATE INDEX idx_channel_invite_links_expires ON channel_invite_links(expires_at);

-- Post comment groups (link to MLS groups)
CREATE TABLE channel_post_comment_groups (
    post_id UUID PRIMARY KEY REFERENCES channel_posts(post_id) ON DELETE CASCADE,
    group_id UUID NOT NULL, -- References mls_groups.group_id
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(64) NOT NULL
);

-- Auto-increment sequence per channel
CREATE SEQUENCE IF NOT EXISTS channel_post_sequence;

-- Trigger to auto-increment sequence_number per channel
CREATE OR REPLACE FUNCTION channel_post_sequence_trigger()
RETURNS TRIGGER AS $$
BEGIN
    SELECT COALESCE(MAX(sequence_number), 0) + 1
    INTO NEW.sequence_number
    FROM channel_posts
    WHERE channel_id = NEW.channel_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_channel_post_sequence
    BEFORE INSERT ON channel_posts
    FOR EACH ROW
    EXECUTE FUNCTION channel_post_sequence_trigger();

-- Trigger to update subscriber count
CREATE OR REPLACE FUNCTION channel_update_subscriber_count()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE channels SET subscriber_count = subscriber_count + 1
        WHERE channel_id = NEW.channel_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE channels SET subscriber_count = GREATEST(0, subscriber_count - 1)
        WHERE channel_id = OLD.channel_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_channel_subscriber_count
    AFTER INSERT OR DELETE ON channel_subscribers
    FOR EACH ROW
    EXECUTE FUNCTION channel_update_subscriber_count();

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION channel_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_channel_update_timestamp
    BEFORE UPDATE ON channels
    FOR EACH ROW
    EXECUTE FUNCTION channel_update_timestamp();

-- Cleanup function for expired posts
CREATE OR REPLACE FUNCTION cleanup_expired_channel_posts()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM channel_posts
        WHERE expires_at < NOW()
        RETURNING channel_id
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Cleanup for deleted channels (older than 30 days)
CREATE OR REPLACE FUNCTION cleanup_deleted_channels()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- First delete child records (FK handles most, but clean comment groups)
    DELETE FROM channel_post_comment_groups
    WHERE post_id IN (
        SELECT post_id FROM channel_posts
        WHERE channel_id IN (
            SELECT channel_id FROM channels
            WHERE deleted_at < NOW() - INTERVAL '30 days'
        )
    );
    
    -- Delete the channels
    WITH deleted AS (
        DELETE FROM channels
        WHERE deleted_at < NOW() - INTERVAL '30 days'
        RETURNING channel_id
    )
    SELECT COUNT(*)::INTEGER INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Master cleanup for channels
CREATE OR REPLACE FUNCTION cleanup_channels_expired()
RETURNS TABLE (
    operation TEXT,
    deleted_count INTEGER
) AS $$
BEGIN
    RETURN QUERY SELECT 'channel_posts'::TEXT, cleanup_expired_channel_posts();
    RETURN QUERY SELECT 'deleted_channels'::TEXT, cleanup_deleted_channels();
END;
$$ LANGUAGE plpgsql;
