-- A bootstrap voucher is shared with a friend, burns in 45 minutes and is not recorded
-- (owner, 2026-11-13). veil_bootstrap_vouchers (069) kept each voucher's ticket_id next to
-- the issuer's user_id for "tracing": the friend presents that ticket_id to a relay, so the
-- row tied the friend's IP to the issuer's account. What stays is the 24h issuance quota:
-- who minted one, and when. The voucher's relay and expiry go too (nothing read them).
-- construct-docs decisions/veil-relay-sees-no-stable-device-id.md, todo/311.
ALTER TABLE veil_bootstrap_vouchers
    DROP COLUMN ticket_id,
    DROP COLUMN relay_address,
    DROP COLUMN not_after,
    DROP COLUMN pool;
