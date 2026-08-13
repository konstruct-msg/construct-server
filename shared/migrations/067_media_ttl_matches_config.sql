-- Media retention: one number, not two.
--
-- Migration 021 set `expires_at DEFAULT (NOW() + INTERVAL '15 days')`, and the
-- INSERT in media-service never supplied a value — so 15 days was the retention
-- that actually ran. Meanwhile MediaConfig::file_ttl_seconds defaulted to 7
-- days, MEDIA_FILE_TTL_SECONDS was read into it, the docs said 7 days, and the
-- iOS MediaSendCache was given a 6-day TTL specifically to stay below the
-- server's. Every one of those reasoned about a number with no effect.
--
-- The INSERT now passes the configured TTL explicitly, which makes the config
-- authoritative. This default is only reachable by a writer that forgets to
-- supply the column, so it is aligned to the same 7 days: if the fallback is
-- ever used, it should not quietly grant more than twice the intended
-- retention.
--
-- Existing rows are left alone. Their 15-day expiry was the real promise made
-- when they were uploaded, and shortening it now would delete media that the
-- sending client still believes is fetchable.

ALTER TABLE media_files
    ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '7 days');

COMMENT ON COLUMN media_files.expires_at IS
    'Auto-delete after this timestamp. Written explicitly by media-service from '
    'MEDIA_FILE_TTL_SECONDS (default 7 days); this column default is a fallback '
    'for writers that omit it.';
