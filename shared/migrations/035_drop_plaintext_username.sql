-- Migration 035: Remove plaintext username column
--
-- Prerequisites:
--   - Migration 034 must have run (username_hash column exists)
--   - user-service startup backfill must have run at least once
--     (all rows with username set now have username_hash set too)
--
-- Safety: this migration will FAIL if any row still has username IS NOT NULL
-- AND username_hash IS NULL, protecting against data loss.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM users
        WHERE username IS NOT NULL
          AND username_hash IS NULL
        LIMIT 1
    ) THEN
        RAISE EXCEPTION
            'Migration 035 aborted: some users still have plaintext username '
            'but no username_hash. Run user-service once to trigger backfill first.';
    END IF;
END;
$$;

-- Drop trigger and function that guarded the now-removed username column.
DROP TRIGGER IF EXISTS users_username_not_reserved ON users;
DROP FUNCTION IF EXISTS check_username_not_reserved();

ALTER TABLE users DROP COLUMN IF EXISTS username;
