-- Migration 044: Key Transparency log
--
-- Append-only Merkle leaf log for identity key auditing.
-- Each row records one device's identity key as it was at registration time.
-- The `tree_index` (= id - 1, 0-based) is the leaf's position in the Merkle tree.

CREATE TABLE kt_leaves (
    -- Sequential 64-bit ID; tree_index = id - 1 (0-based)
    id               BIGSERIAL      PRIMARY KEY,
    device_id        VARCHAR(32)    NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    -- leaf_hash = SHA-256(0x00 || device_id_utf8 || identity_key_raw)
    -- 32 bytes stored as binary
    leaf_hash        BYTEA          NOT NULL,
    appended_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- Fast lookup: given a device_id, find its leaf position
CREATE UNIQUE INDEX kt_leaves_device_id ON kt_leaves (device_id);

-- Comment: rows are never deleted or updated (append-only invariant).
-- DO NOT add UPDATE or DELETE permissions to the application role on this table.
