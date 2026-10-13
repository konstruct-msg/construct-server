-- A Key Transparency leaf's position in the Merkle tree, as a stored fact.
--
-- Until now the position was computed twice: the inclusion proof used `id - 1`, while the tree it
-- proves against is the leaves in `id` order — a leaf's position is its rank, not its id. The two
-- agree only while the `id` sequence has no holes, and a Postgres sequence makes holes (a rolled-
-- back insert, a restart after a crash). After the first hole every later leaf was proved at a
-- position holding another leaf: a valid proof, for the wrong leaf, which every client rejected.
--
-- The backfill writes each leaf's rank, which is the position the tree already gave it. No leaf
-- moves, no root changes: tree heads handed out before this migration stay valid.

ALTER TABLE kt_leaves ADD COLUMN IF NOT EXISTS tree_index BIGINT;

UPDATE kt_leaves AS k
SET tree_index = ranked.position
FROM (SELECT id, row_number() OVER (ORDER BY id) - 1 AS position FROM kt_leaves) AS ranked
WHERE k.id = ranked.id;

ALTER TABLE kt_leaves ALTER COLUMN tree_index SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS kt_leaves_tree_index ON kt_leaves (tree_index);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM (
            SELECT tree_index, row_number() OVER (ORDER BY id) - 1 AS position FROM kt_leaves
        ) AS checked
        WHERE checked.tree_index <> checked.position
    ) THEN
        RAISE EXCEPTION 'Migration 073 failed: kt_leaves.tree_index differs from the leaf rank';
    END IF;
END $$;
