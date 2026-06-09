-- ============================================================================
-- Migration 054: Key Transparency — hybrid identity key leaf kind
-- ============================================================================
--
-- Adds a second leaf KIND to the append-only KT log so the hybrid PQ identity key
-- gets its own transparency entry, without disturbing the existing identity leaves.
--
-- The Merkle tree is still built over ALL leaves (both kinds) ordered by id, so the
-- two leaf kinds share one tree and one Signed Tree Head. Domain separation is in the
-- leaf-hash preimage (NOT changing the identity leaf, which would re-root the tree):
--   identity leaf (kind 0): SHA-256(0x00 || device_id_utf8 || identity_key_raw)   [unchanged]
--   hybrid   leaf (kind 1): SHA-256(0x02 || device_id_utf8 || hybrid_identity_key)
-- 0x02 distinguishes the hybrid leaf payload from the identity leaf (0x00) and the
-- internal node hash (0x01).
--
-- Existing rows default to kind 0 (identity) → existing leaves and their inclusion
-- proofs stay valid. The log remains append-only.
-- ============================================================================

ALTER TABLE kt_leaves
  ADD COLUMN IF NOT EXISTS leaf_kind SMALLINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN kt_leaves.leaf_kind IS
  'KT leaf kind: 0 = Ed25519 identity key, 1 = hybrid PQ identity key. Domain-separated in the leaf-hash preimage (0x00 vs 0x02).';

-- The latest-leaf lookup in db_ensure_leaf is now per (device_id, leaf_kind).
DROP INDEX IF EXISTS kt_leaves_device_id_idx;
CREATE INDEX IF NOT EXISTS kt_leaves_device_kind_idx ON kt_leaves (device_id, leaf_kind, id DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'kt_leaves' AND column_name = 'leaf_kind'
    ) THEN
        RAISE EXCEPTION 'Migration failed: kt_leaves.leaf_kind not created';
    END IF;
    RAISE NOTICE 'Migration 054 completed: kt_leaves.leaf_kind added (existing rows = 0/identity)';
END $$;
