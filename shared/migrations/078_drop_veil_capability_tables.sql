-- veil_tickets (055) and veil_capabilities_v2 (056) were written on every VEIL capability
-- issuance and read by nothing: the relay validates offline, and per-device revocation was
-- given up (owner, 2026-11-13). Each row tied the presented access (ticket_id, veil_pk —
-- and in veil_tickets the bearer auth_key itself) to user_id, which is what turns a relay's
-- log into an account's IP history. The writes are gone in the same change.
-- construct-docs decisions/veil-relay-sees-no-stable-device-id.md §2, todo/311.
DROP TABLE IF EXISTS veil_capabilities_v2;
DROP TABLE IF EXISTS veil_tickets;
