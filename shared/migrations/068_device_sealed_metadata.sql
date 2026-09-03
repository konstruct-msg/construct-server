-- One column for the "Linked devices" screen, chosen so that it is not the one
-- migration 013 removed.
--
-- ## What 013 decided, and why it still holds
--
-- Migration 013 dropped `device_name`, `platform` and `last_active_at` from
-- `devices` as "device fingerprinting", "OS leak" and "timing metadata". That
-- judgement was right about what plaintext columns cost: a database dump, a
-- subpoena or a compromised host reads "iPhone 15 Pro", "ios", and an activity
-- trace for every device on the server, none of which the server needs in order
-- to route a message.
--
-- What the device list still needs is a way to tell one row from another. It is
-- the only place a person can see that their account has grown a device they did
-- not add, and over the 1-3 Sep 2026 stand one Mac passed through three device
-- ids from re-linking; a revoked one went on working for a day, and its
-- handshakes archived a neighbouring device's session at 41 of 42
-- correspondents. In a list where every row shows the same synthesised name,
-- that is invisible.
--
-- ## sealed_metadata, which the server cannot read
--
-- The device's own name and platform, encrypted by the client under a key the
-- server does not hold. The server stores the blob and hands it back to the
-- account that owns it; it never parses it, and nothing branches on its content.
-- That is the difference from `device_name VARCHAR(100)`: the screen gets its
-- names and icons back, and a dump yields ciphertext.
--
-- Precedent for the shape is already in the schema — `device_tokens.device_name_encrypted`
-- from migration 006, which has been NULL in every row since.
--
-- ## What this migration deliberately does not add
--
-- `last_active_at`. An earlier draft of this work restored it truncated to the
-- hour, on the reasoning that a coarse bucket answers "is this device still in
-- use" while leaking less than a per-second trace. It is still the timing
-- metadata 013 removed, only rounder, and a column that exists is a column that
-- gets read. Liveness is a question the clients answer between themselves from
-- what actually gets delivered; the server does not keep the answer.
-- `DeviceInfo.last_seen` therefore stays 0 on this server.
--
-- ## Why 4 KiB
--
-- The blob is not one sealed name. `SealedDeviceMetadata` carries one copy per
-- active device of the account, each sealed to that device's X25519 identity key,
-- because the account has no shared key to seal under — every device holds its own
-- pair and linking establishes nothing between them. So the size scales with the
-- device count: roughly 105-165 bytes per copy (ephemeral public key, nonce, AEAD
-- tag, and a name), which puts 1 KiB — the figure an earlier draft used, when the
-- blob was going to be a single sealed name — at a ceiling of six to nine devices.
-- That is a refusal a real person could hit, and hitting it means the device list
-- stops naming anything.
--
-- 4 KiB is still a cap and not a budget: around twenty-five to forty copies, far
-- past any plausible account, and small enough that the column cannot become
-- storage for something else. identity-service rejects anything larger with
-- INVALID_ARGUMENT rather than truncating.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS sealed_metadata BYTEA;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_sealed_metadata_len;
ALTER TABLE devices
    ADD CONSTRAINT devices_sealed_metadata_len
    CHECK (sealed_metadata IS NULL OR octet_length(sealed_metadata) <= 4096);

COMMENT ON COLUMN devices.sealed_metadata IS
    'Client-encrypted device name and platform. Opaque to the server: stored, returned '
    'to the owning account in DeviceInfo.sealed_metadata, never parsed. Max 4 KiB.';
