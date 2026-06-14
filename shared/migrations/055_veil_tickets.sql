-- ============================================================================
-- Migration 055: VEIL capabilities — issued access-token accounting
-- ============================================================================
--
-- The backend is the issuer of veil-front capabilities (decisions/veil-ticket-
-- provisioning-system.md, B2). A capability = ticket fields (ticket_id, auth_key,
-- validity window, suite) + relay scope, signed by the issuer Ed25519 key. The
-- relay validates the signature OFFLINE with the issuer public key — it never reads
-- this table. This table exists for *accounting* (who has which capability) and
-- *revocation* (short TTL is the primary mechanism; `revoked` supports a future CRL).
--
-- auth_key is a SECRET (the relay derives the session authcode from it via the
-- presented capability). Never log it.
-- ============================================================================

CREATE TABLE IF NOT EXISTS veil_tickets (
    -- Opaque 16-byte capability/ticket id.
    ticket_id    BYTEA PRIMARY KEY,
    -- Per-capability PSK (32 bytes). SECRET.
    auth_key     BYTEA NOT NULL,
    -- Owning user (NULL for seeded/bootstrap capabilities not tied to an account).
    user_id      UUID,
    -- Relay scope the capability is valid on (matches the relay's --relay-scope;
    -- empty string = any scope).
    relay_scope  TEXT NOT NULL DEFAULT '',
    -- Validity window, unix seconds.
    not_before   BIGINT NOT NULL,
    not_after    BIGINT NOT NULL,
    -- Crypto suite selector (CLASSIC v1 = 1).
    suite_id     SMALLINT NOT NULL DEFAULT 1,
    -- Explicit revocation (future CRL; B2 relies primarily on short TTL).
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE veil_tickets IS
  'Issued VEIL-front capabilities (accounting + revocation). Relays validate offline via the issuer pubkey and never read this table. auth_key is secret.';

-- Per-user lookup (rotation accounting / revoke-by-user).
CREATE INDEX IF NOT EXISTS veil_tickets_user_idx ON veil_tickets (user_id);
-- Expiry sweeps.
CREATE INDEX IF NOT EXISTS veil_tickets_not_after_idx ON veil_tickets (not_after);
