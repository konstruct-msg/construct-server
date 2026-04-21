-- ============================================================================
-- Migration 046: Repair spk_uploaded_at for devices that never rotated
-- ============================================================================
--
-- Migration 031 backfilled spk_uploaded_at = COALESCE(key_updated_at, registered_at)
-- for all existing devices. For devices that registered before migration 031 and
-- never performed an SPK rotation after it, spk_uploaded_at reflects the device
-- registration time — not when the SPK was actually last uploaded.
--
-- When such a device comes online after 14+ days and rotates their SPK, there is
-- a race window where peers fetching the bundle before the rotation completes see
-- the old (backfill) timestamp and reject the bundle as stale. The rotate_signed_prekey()
-- function correctly sets spk_uploaded_at = NOW() on rotation, so this only affects
-- pre-rotation bundle fetches.
--
-- This migration resets spk_uploaded_at to NULL for devices that have never
-- performed an explicit rotation (spk_rotation_epoch = 0). The Rust client checks
-- spk_uploaded_at == 0 → skip validation (see client_api.rs:89), so NULL/0 treated
-- as "legacy" device is safe and prevents false-positive staleness rejections.
-- ============================================================================

UPDATE devices
SET spk_uploaded_at = NULL
WHERE spk_rotation_epoch = 0
  AND spk_uploaded_at IS NOT NULL;

UPDATE devices
SET kyber_spk_uploaded_at = NULL
WHERE kyber_spk_rotation_epoch = 0
  AND kyber_spk_uploaded_at IS NOT NULL;

DO $$
DECLARE
  repaired_count INTEGER;
BEGIN
  GET DIAGNOSTICS repaired_count = ROW_COUNT;
  RAISE NOTICE '✅ Migration 046: Reset spk_uploaded_at for % device(s) with epoch=0', repaired_count;
END $$;
