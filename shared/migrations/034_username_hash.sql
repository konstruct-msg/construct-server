-- Migration 034: Replace plaintext username with HMAC hash
--
-- Privacy model: the server stores HMAC-SHA256(server_secret, normalized_username).
-- The plaintext username is never persisted — it exists only in memory during the
-- request that sets it. At rest (DB dump), only the hash is present and cannot be
-- reversed without the server secret.
--
-- Lookup flow: client sends plaintext username → server normalises (trim+lowercase) →
-- computes HMAC → equality check on username_hash column.
--
-- Recovery flow: client sends plaintext username as identifier → same hash → lookup.
--
-- Side-effect: substring search (@max → @maxim) is no longer possible.
-- Exact-match only — acceptable for a privacy-first messenger.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS username_hash BYTEA;

-- Unique index: one username hash per user, NULL allowed (anonymous accounts).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_hash
    ON users (username_hash)
    WHERE username_hash IS NOT NULL;

-- The old plaintext index is no longer needed (queries use username_hash).
-- We keep the username column temporarily so existing data is not lost before
-- a one-time server-side migration fills username_hash from the plaintext values.
-- Migration 035 will drop the username column once all rows have username_hash set.
DROP INDEX IF EXISTS idx_users_username;
