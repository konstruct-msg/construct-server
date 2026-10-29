-- Migration 076: the MLS cleanup functions from 050, made to run.
--
-- `cleanup_mls_expired()` has failed on every call since 050: its first step,
-- `cleanup_expired_group_messages()`, read the CTE `deleted` from a second statement, where it
-- does not exist ("relation \"deleted\" does not exist"), and `cleanup_expired_group_commits()`
-- filtered on a `created_at` column that group_commits does not have. The worker in
-- group-service logged the error once a day and deleted nothing — no expired group message,
-- commit, invite or KeyPackage, no dissolved group.
--
-- Messages: the second statement wrote `mls_groups.messages_deleted_before`, which nothing
-- reads (GetGroupState sends 0). It is dropped rather than repaired.
-- Commits: a commit row carries its own `expires_at` (30 days after commit by default), the
-- same rule the other functions follow.

CREATE OR REPLACE FUNCTION cleanup_expired_group_messages()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM group_messages
    WHERE expires_at < NOW();

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_expired_group_commits()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM group_commits
    WHERE expires_at < NOW();

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
