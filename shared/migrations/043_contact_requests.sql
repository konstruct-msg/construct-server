-- Migration 043: Privacy-preserving contact requests
--
-- Design: same two-layer protection as contact_links (037):
--   - from_hmac / to_hmac : HMAC-SHA256(contact_hmac_secret, user_id_bytes)
--     → table dump without CONTACT_HMAC_SECRET reveals no UUID pairs
--   - from_enc : ChaCha20Poly1305(request_envelope_key, from_user_id_bytes)
--     → sender identity encrypted at rest; decrypted only for authenticated recipient
--   - to_user_id is NOT stored — push is delivered synchronously from process memory
--
-- Queries:
--   Recipient inbox  : WHERE to_hmac = $1 AND status = 'pending'
--   Sender sent list : WHERE from_hmac = $1
--   Dedup guard      : UNIQUE (from_hmac, to_hmac)

CREATE TABLE IF NOT EXISTS contact_requests (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    from_hmac   BYTEA       NOT NULL,
    to_hmac     BYTEA       NOT NULL,
    -- ChaCha20Poly1305: nonce(12) || ciphertext(16) || tag(16) = 44 bytes
    from_enc    BYTEA       NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,

    PRIMARY KEY (id),
    UNIQUE (from_hmac, to_hmac),
    CHECK (octet_length(from_hmac) = 32),
    CHECK (octet_length(to_hmac)   = 32),
    CHECK (status IN ('pending', 'accepted', 'declined_blocked', 'spam_blocked'))
);

CREATE INDEX IF NOT EXISTS idx_contact_requests_to
    ON contact_requests(to_hmac, status);

CREATE INDEX IF NOT EXISTS idx_contact_requests_from
    ON contact_requests(from_hmac);

-- Validation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'contact_requests'
    ) THEN
        RAISE EXCEPTION 'Migration 043 failed: contact_requests table not created';
    END IF;
    RAISE NOTICE 'Migration 043 completed successfully!';
    RAISE NOTICE '  ✓ contact_requests table created (privacy-preserving: HMAC + ChaCha20 envelope)';
    RAISE NOTICE '  ✓ UNIQUE (from_hmac, to_hmac) dedup constraint';
    RAISE NOTICE '  ✓ Indexes on to_hmac and from_hmac';
END $$;
