-- Migration: Add media_files table for MediaService
-- Phase: 2.6 (gRPC Migration)
-- Created: 2026-02-22

-- ============================================================================
-- Media Files Storage Metadata
-- ============================================================================
--
-- Design Principles:
-- - Minimal metadata (privacy-first)
-- - No user_id (files are E2E encrypted, server doesn't know owner)
-- - No mime_type (client responsibility)
-- - Auto-cleanup after TTL (15 days)
--
-- Storage Backends:
-- - local: Local filesystem (staging/dev)
-- - spaces: DigitalOcean Spaces (production)
-- - r2: CloudFlare R2 (production alternative)
-- - s3: AWS S3 (if needed)
--
-- ============================================================================

CREATE TABLE IF NOT EXISTS media_files (
    -- Unique media identifier (UUID v4)
    media_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- File size in bytes
    -- Limits: 25MB images, 500MB videos, 100MB docs
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 524288000), -- 500MB max
    
    -- Storage backend type
    -- Values: 'local', 'spaces', 'r2', 's3'
    storage_backend VARCHAR(50) NOT NULL CHECK (storage_backend IN ('local', 'spaces', 'r2', 's3')),
    
    -- Storage key (S3 object key or local filesystem path)
    -- For S3: "media/{media_id}"
    -- For local: "/var/media_storage/{media_id}"
    storage_key VARCHAR(500) NOT NULL,
    
    -- SHA-256 checksum for integrity verification
    file_hash VARCHAR(64) NOT NULL CHECK (length(file_hash) = 64),
    
    -- Creation timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Expiration timestamp (auto-delete after 15 days)
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 days'),
    
    -- All files are E2E encrypted (always true)
    encrypted BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Metadata constraints
    CONSTRAINT valid_expiration CHECK (expires_at > created_at)
);

-- ============================================================================
-- Indexes for Performance
-- ============================================================================

-- Index for cleanup task (queries expired files)
CREATE INDEX IF NOT EXISTS idx_media_expires_at ON media_files(expires_at);

-- Index for storage backend queries (useful for migration)
CREATE INDEX IF NOT EXISTS idx_media_storage_backend ON media_files(storage_backend);

-- Index for creation time (useful for analytics)
CREATE INDEX IF NOT EXISTS idx_media_created_at ON media_files(created_at DESC);

-- ============================================================================
-- Comments for Documentation
-- ============================================================================

COMMENT ON TABLE media_files IS 'Metadata for E2E encrypted media files. Privacy-first design with minimal metadata.';
COMMENT ON COLUMN media_files.media_id IS 'Unique media identifier (UUID v4). Used in download URLs.';
COMMENT ON COLUMN media_files.size_bytes IS 'File size in bytes. Max 500MB (videos), 25MB (images), 100MB (docs).';
COMMENT ON COLUMN media_files.storage_backend IS 'Storage backend type: local, spaces (DigitalOcean), r2 (CloudFlare), s3 (AWS).';
COMMENT ON COLUMN media_files.storage_key IS 'Storage-specific key. For S3: object key. For local: filesystem path.';
COMMENT ON COLUMN media_files.file_hash IS 'SHA-256 checksum for integrity verification.';
COMMENT ON COLUMN media_files.expires_at IS 'Auto-delete after this timestamp. Default: 15 days from creation.';
COMMENT ON COLUMN media_files.encrypted IS 'All files are E2E encrypted on client before upload. Always true.';

-- ============================================================================
-- Cleanup Function (Optional - for automated cleanup)
-- ============================================================================

-- This function can be called by a cron job or background worker
-- to delete expired media files from the database
-- (Actual file deletion from storage is handled by media-service cleanup task)

CREATE OR REPLACE FUNCTION cleanup_expired_media()
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    deleted BIGINT;
BEGIN
    DELETE FROM media_files
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN QUERY SELECT deleted;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION cleanup_expired_media() IS 'Delete expired media metadata from database. Called by cleanup task.';
