-- Drop encrypted_data_registry: created in 009_key_management.sql but never
-- referenced by any application code (0 Rust refs). It belongs to the
-- Vault-dependent enterprise key-management feature, which is inactive in the
-- single-VPS deployment (no Vault → KeyManagementSystem fails open to None).
-- Safe, idempotent drop.
DROP TABLE IF EXISTS encrypted_data_registry CASCADE;
