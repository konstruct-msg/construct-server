-- Tracing + issuance quota for user-vouched VEIL bootstrap (B2 bearer).
-- No auth_key (TTL is the burn). No redeemer identity.

CREATE TABLE veil_bootstrap_vouchers (
    ticket_id       BYTEA PRIMARY KEY,
    issuer_user_id  UUID NOT NULL,
    pool            TEXT NOT NULL DEFAULT 'user-voucher',
    relay_address   TEXT NOT NULL,
    not_after       BIGINT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX veil_bootstrap_vouchers_issuer_issued_idx
    ON veil_bootstrap_vouchers (issuer_user_id, issued_at);
CREATE INDEX veil_bootstrap_vouchers_not_after_idx
    ON veil_bootstrap_vouchers (not_after);
