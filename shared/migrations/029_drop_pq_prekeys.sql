-- ============================================================================
-- Migration 029: Drop legacy pq_prekeys table
-- ============================================================================
--
-- The pq_prekeys table was created in migration 008 as an early placeholder
-- for post-quantum identity keys. It was never wired up — no RPC writes to it.
--
-- The actual PQC key storage (Phase 1, ML-KEM-1024) is handled by:
--   - devices.kyber_signed_pre_key (migration 028)
--   - kyber_one_time_pre_keys table (migration 028)
--
-- Safe to drop: no service reads or writes pq_prekeys.
-- ============================================================================

DROP TABLE IF EXISTS pq_prekeys;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'pq_prekeys'
    ) THEN
        RAISE EXCEPTION 'Migration 029 failed: pq_prekeys table still exists';
    END IF;

    RAISE NOTICE 'Migration 029 completed successfully!';
    RAISE NOTICE '  ✓ pq_prekeys table dropped (was unused dead code from migration 008)';
END $$;
