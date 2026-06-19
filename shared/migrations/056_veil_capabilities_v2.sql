-- ============================================================================
-- Migration 056: VEIL key-bound capabilities (B1) — issued access-token accounting
-- ============================================================================
--
-- B1 (decisions/veil-ticket-provisioning-system.md): a capability binds the
-- holder's veil_pk (Ed25519 public key) instead of carrying a bearer auth_key.
-- The relay verifies the holder's own signature over the TLS exporter
-- (AuthRecordV3) — it never reads this table, and there is NO secret here:
-- veil_pk is public, the matching private key never leaves the holder's device.
--
-- `role` distinguishes end-user capabilities (0) from chaining-relay
-- capabilities (1) issued to a relay_domestic operator for its upstream hop
-- (decisions/veil-relay-topology.md §3/§4).
--
-- This is a separate table from `veil_tickets` (B2) rather than an ALTER,
-- because the B2 table's `auth_key` column is a secret with its own handling
-- expectations (never logged, etc.) — keeping the two formats in distinct
-- tables avoids a nullable-secret column and makes "this row has no secret"
-- a property of the table, not a runtime check.
-- ============================================================================

CREATE TABLE IF NOT EXISTS veil_capabilities_v2 (
    -- Opaque 16-byte capability/ticket id (accounting only).
    ticket_id    BYTEA PRIMARY KEY,
    -- Holder's Ed25519 public key (32 bytes). NOT a secret.
    veil_pk      BYTEA NOT NULL,
    -- 0 = ROLE_USER, 1 = ROLE_RELAY.
    role         SMALLINT NOT NULL DEFAULT 0,
    -- Owning user (NULL for relay-operator capabilities not tied to an end-user account).
    user_id      UUID,
    -- Relay scope the capability is valid on (matches the relay's --relay-scope;
    -- empty string = any scope).
    relay_scope  TEXT NOT NULL DEFAULT '',
    -- Validity window, unix seconds.
    not_before   BIGINT NOT NULL,
    not_after    BIGINT NOT NULL,
    -- Crypto suite selector (CLASSIC v1 = 1).
    suite_id     SMALLINT NOT NULL DEFAULT 1,
    -- Explicit revocation (primary revocation mechanism is short TTL + non-renewal;
    -- this column supports a future CRL if ever needed).
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE veil_capabilities_v2 IS
  'Issued key-bound VEIL-front capabilities (B1, accounting only — no secret material). Relays validate offline via the issuer pubkey + the holder''s own signature and never read this table.';

CREATE INDEX IF NOT EXISTS veil_capabilities_v2_user_idx ON veil_capabilities_v2 (user_id);
CREATE INDEX IF NOT EXISTS veil_capabilities_v2_not_after_idx ON veil_capabilities_v2 (not_after);
CREATE INDEX IF NOT EXISTS veil_capabilities_v2_role_idx ON veil_capabilities_v2 (role);
