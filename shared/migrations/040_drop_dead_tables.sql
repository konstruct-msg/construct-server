-- Migration 040: Drop tables whose application code has been removed.
--
-- restriction_appeals: appeals workflow removed in cleanup (code was in sentinel-service).
-- disputes:            dispute/evidence system removed in cleanup (code was in sentinel-service).
--
-- Both tables were created but the Rust code that reads/writes them was deleted,
-- so the tables are orphaned schema objects. Dropping them keeps the schema
-- consistent with the code.

DROP TABLE IF EXISTS disputes;
DROP TABLE IF EXISTS restriction_appeals;
