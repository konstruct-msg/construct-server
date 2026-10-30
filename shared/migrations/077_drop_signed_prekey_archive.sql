-- signed_prekey_archive (migration 022) was written on every signed pre-key rotation and
-- read by nothing: the server never decrypts, and a client keeps the private half of its old
-- key itself. Its sweep, cleanup_expired_archives, was never scheduled, so it only grew
-- (143 rows, 137 past expires_at, on 2026-10-30). The write is gone in the same change.
-- construct-docs todo/233.
DROP TABLE IF EXISTS signed_prekey_archive;
