-- Fix timestamp types for delivery_pending table
-- Change from TIMESTAMP to TIMESTAMPTZ to match Rust DateTime<Utc> types

ALTER TABLE delivery_pending
    ALTER COLUMN expires_at TYPE TIMESTAMPTZ,
    ALTER COLUMN created_at TYPE TIMESTAMPTZ;
