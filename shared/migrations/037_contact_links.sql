-- Privacy-preserving contact links (mutual contacts enforcement for calls)
--
-- Server stores directional "user has contact" edges in a blinded form:
--   user_hmac = HMAC-SHA256(CONTACT_HMAC_SECRET, user_id_bytes)
--   peer_hmac = HMAC-SHA256(CONTACT_HMAC_SECRET, peer_user_id_bytes)
--
-- This avoids persisting explicit social-graph edges (user_id -> peer_id) in plaintext.
-- Mutual contacts are enforced by requiring both directions to exist.

CREATE TABLE IF NOT EXISTS contact_links (
    user_hmac BYTEA NOT NULL,
    peer_hmac BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_hmac, peer_hmac),
    CHECK (octet_length(user_hmac) = 32),
    CHECK (octet_length(peer_hmac) = 32)
);

CREATE INDEX IF NOT EXISTS idx_contact_links_user
    ON contact_links(user_hmac);

CREATE INDEX IF NOT EXISTS idx_contact_links_peer
    ON contact_links(peer_hmac);

