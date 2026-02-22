-- Remove backup table created during passwordless hard-cut migration.
-- The canonical account table is `users`; `users_legacy` is no longer used.
DROP TABLE IF EXISTS users_legacy;
