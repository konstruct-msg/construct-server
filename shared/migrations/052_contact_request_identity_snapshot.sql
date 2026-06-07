-- Migration 052: Contact request identity snapshot
--
-- Adds from_identity_enc to store an envelope-encrypted identity snapshot
-- (username + display_name) at request time. This lets recipients see
-- who is contacting them before accepting, without the server storing
-- plaintext profile data.
--
-- Wire format: ChaCha20Poly1305 envelope of JSON: {"username":"...","display_name":"..."}
-- NULL for legacy rows created before rollout.

ALTER TABLE contact_requests
    ADD COLUMN IF NOT EXISTS from_identity_enc BYTEA NULL;

-- Validation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'contact_requests' AND column_name = 'from_identity_enc'
    ) THEN
        RAISE EXCEPTION 'Migration 052 failed: from_identity_enc column not added';
    END IF;
    RAISE NOTICE 'Migration 052 completed successfully!';
    RAISE NOTICE '  + from_identity_enc BYTEA NULL added to contact_requests';
END $$;
