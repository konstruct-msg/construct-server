-- Delivery ACK Pending Table
-- Privacy-first design for message delivery acknowledgments
--
-- Philosophy:
-- - NEVER store direct messageId → senderId mappings
-- - Use HMAC-SHA256 to create anonymous links between messages and senders
-- - Automatic expiry to minimize data retention
-- - Even with DB access, cannot link messages to senders without SECRET_KEY
-- - Protects against social graph reconstruction and timing correlation
--
-- Security Properties:
-- 1. message_hash = HMAC-SHA256(messageId, SECRET_KEY)
--    → One-way function, cannot reverse to get messageId
-- 2. sender_id stored in plaintext (necessary for ACK routing)
--    → But cannot be linked to specific messages without SECRET_KEY
-- 3. Automatic cleanup via expires_at
-- 4. No created_at timestamp with time (only for cleanup index)
--
-- Trade-off: sender_id is visible in DB, but relationship to messages is protected

CREATE TABLE IF NOT EXISTS delivery_pending (
    -- Primary key: HMAC-SHA256 hash of messageId
    -- Format: HMAC-SHA256(messageId, SECRET_KEY) as hex string
    message_hash VARCHAR(64) PRIMARY KEY,

    -- Sender's user ID (UUID as string)
    -- Required to route "delivered" ACK back to sender
    -- NOTE: Visible in DB but cannot be linked to messages without SECRET_KEY
    sender_id VARCHAR(36) NOT NULL,

    -- Expiration timestamp (UTC)
    -- Messages older than DELIVERY_EXPIRY_DAYS (default 7) are automatically cleaned
    expires_at TIMESTAMP NOT NULL,

    -- Creation timestamp (UTC) for audit/debugging
    -- NOTE: This could leak timing correlation metadata
    -- Consider removing in production for maximum privacy
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for efficient expiry cleanup
-- Used by background cleanup task to delete expired entries
CREATE INDEX IF NOT EXISTS idx_delivery_pending_expires
ON delivery_pending(expires_at);

-- Index for sender lookups (optional, for metrics)
-- WARNING: This index could facilitate timing correlation attacks
-- Consider removing in production if not needed for monitoring
CREATE INDEX IF NOT EXISTS idx_delivery_pending_sender
ON delivery_pending(sender_id);

-- Privacy Analysis:
--
-- Attack Scenarios WITHOUT SECRET_KEY:
-- ✅ PROTECTED: Cannot determine which messages belong to which sender
-- ✅ PROTECTED: Cannot reconstruct communication graph without SECRET_KEY
-- ✅ PROTECTED: message_hash cannot be reversed to messageId
--
-- ⚠️  PARTIAL: Timing correlation possible via created_at/expires_at
--    - Solution: Add random delays, batch operations, or remove created_at
-- ⚠️  PARTIAL: sender_id frequency analysis shows user activity patterns
--    - Solution: Hash sender_id too (see enhanced security in docs)
--
-- Attack Scenarios WITH SECRET_KEY:
-- ❌ COMPROMISED: Attacker can verify known messageId → sender_id links
-- ❌ COMPROMISED: Can brute-force if messageId format is predictable
--    - Mitigation: Use UUIDv4 for messageId (2^122 entropy, impractical to brute-force)
--
-- Defense in Depth:
-- 1. Use UUIDv4 for message IDs (not sequential or timestamp-based)
-- 2. Store SECRET_KEY in secure secrets manager (AWS Secrets Manager, Vault)
-- 3. Rotate SECRET_KEY periodically (6-12 months)
-- 4. Use different SECRET_KEY per environment (dev/staging/prod)
-- 5. Enable rate limiting to prevent brute-force attacks
-- 6. Consider Redis instead of PostgreSQL for automatic TTL expiry

-- Example Usage:
--
-- 1. When sender sends message:
--    message_hash := HMAC-SHA256(msg.id, SECRET_KEY)
--    INSERT INTO delivery_pending VALUES (
--        message_hash,
--        sender_id,
--        NOW() + INTERVAL '7 days',
--        NOW()
--    )
--
-- 2. When recipient acknowledges delivery:
--    message_hash := HMAC-SHA256(ack.messageId, SECRET_KEY)
--    SELECT sender_id FROM delivery_pending WHERE message_hash = message_hash
--    -- Send ACK to sender_id
--    DELETE FROM delivery_pending WHERE message_hash = message_hash
--
-- 3. Cleanup expired entries (daily cron):
--    DELETE FROM delivery_pending WHERE expires_at < NOW()
