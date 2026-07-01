-- add PQ ratchet support flag to device
ALTER TABLE devices ADD COLUMN IF NOT EXISTS supports_pq_ratchet boolean NOT NULL DEFAULT false;
