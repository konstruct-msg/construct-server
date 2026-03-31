-- Migration 038: Add opt-in user discoverability flag
--
-- Privacy model:
--   - Default is FALSE (not discoverable). Server-side default, no client action required.
--   - User must explicitly opt in to appear in search results.
--   - Search only returns users with searchable = TRUE.
--   - The server returns identical "not found" for both "doesn't exist" and
--     "exists but searchable = FALSE" — prevents username existence oracle attacks.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS searchable BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial index: only index rows where the user opted in.
-- Keeps the index tiny and makes it obvious no anonymous user appears here.
CREATE INDEX IF NOT EXISTS idx_users_searchable_username_hash
    ON users (username_hash)
    WHERE searchable = TRUE AND username_hash IS NOT NULL;

COMMENT ON COLUMN users.searchable IS
    'Opt-in discoverability flag. TRUE = user can be found via FindUser RPC. Default FALSE.';
