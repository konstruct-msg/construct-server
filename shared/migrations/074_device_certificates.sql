-- A device of an account vouching for another device of the same account.
--
-- Which devices belong to an account was the server's word alone, and a server that adds a device
-- of its own receives every later message to that account. The account's devices now say it
-- instead: when the owner links a device, the old one signs the new one's keys and publishes the
-- certificate here (DeviceService.PublishDeviceCertificate); key-service serves it next to the
-- device's bundle (DevicePreKeyBundle.device_certificate). Peers verify it in construct-core and
-- alarm on a device nobody vouched for.
-- construct-docs decisions/devices-of-an-account-sign-each-other.md.
--
-- The server stores and serves the bytes and never verifies the signature: it is not the party
-- that has to be convinced. A certificate it drops or alters reads to peers as an unsigned
-- device, the safe side. What it does check on publish (identity-service) is cheap and
-- structural — the subject is an active device of the caller's account, not the caller, and the
-- certificate names the caller as its signer — so one account cannot write into another's rows.
--
-- One per device: a later certificate replaces the earlier one. Exactly 5382 bytes — version,
-- signer id, issued_at, the signer's hybrid key and a hybrid signature
-- (construct-protos conformance/knst_device_certificate.json).

ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_certificate BYTEA;

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_device_certificate_len;
ALTER TABLE devices
    ADD CONSTRAINT devices_device_certificate_len
    CHECK (device_certificate IS NULL OR octet_length(device_certificate) = 5382);

COMMENT ON COLUMN devices.device_certificate IS
    'Certificate by which another device of the same account vouches for this one. Opaque to '
    'the server: stored on PublishDeviceCertificate, served in DevicePreKeyBundle, never verified.';
