-- Fix delivery_pending timestamps to use timezone-aware types
-- Migration 007 used TIMESTAMP, but we need TIMESTAMPTZ for proper UTC handling

ALTER TABLE delivery_pending
    ALTER COLUMN expires_at TYPE TIMESTAMPTZ,
    ALTER COLUMN created_at TYPE TIMESTAMPTZ;
