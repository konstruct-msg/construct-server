// ============================================================================
// Replay Protection
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization

use construct_config::SECONDS_PER_DAY;
use anyhow::Result;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

pub(crate) struct ReplayProtection<'a> {
    client: &'a mut redis::aio::ConnectionManager,
    msg_hash_prefix: String,
}

impl<'a> ReplayProtection<'a> {
    pub(crate) fn new(
        client: &'a mut redis::aio::ConnectionManager,
        msg_hash_prefix: String,
    ) -> Self {
        Self {
            client,
            msg_hash_prefix,
        }
    }

    pub(crate) async fn check_message_replay(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
    ) -> Result<bool> {
        // Создаем уникальный хэш сообщения
        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(content.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let key = format!("{}{}", self.msg_hash_prefix, hash);

        // Проверяем существование
        let exists: bool = self.client.exists(&key).await?;

        if exists {
            tracing::warn!(
                message_id = %message_id,
                hash = %hash,
                "Potential replay attack detected"
            );
            return Ok(false); // Сообщение уже было
        }

        let _: () = self
            .client
            .set_ex(&key, "1", SECONDS_PER_DAY as u64)
            .await?;

        Ok(true) // Сообщение уникальное
    }

    /// Enhanced replay protection with timestamp validation
    ///
    /// Checks for replay attacks using:
    /// - message_id + content + nonce hash (for deduplication)
    /// - timestamp validation (rejects requests older than max_age_seconds)
    pub(crate) async fn check_replay_with_timestamp(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
        timestamp: i64,
        max_age_seconds: i64,
    ) -> Result<bool> {
        // 1. Validate timestamp (prevent replay of old requests)
        let now = chrono::Utc::now().timestamp();
        let age = now - timestamp;

        if age > max_age_seconds {
            tracing::warn!(
                message_id = %message_id,
                timestamp = timestamp,
                age_seconds = age,
                max_age = max_age_seconds,
                "Request timestamp too old - possible replay attack"
            );
            return Ok(false); // Timestamp validation failed
        }

        if age < -60 {
            // Allow 60 seconds clock skew for future timestamps
            tracing::warn!(
                message_id = %message_id,
                timestamp = timestamp,
                now = now,
                "Request timestamp too far in future - possible clock skew or attack"
            );
            return Ok(false); // Timestamp too far in future
        }

        // 2. Check replay using hash (same as check_message_replay)
        let mut hasher = Sha256::new();
        hasher.update(message_id.as_bytes());
        hasher.update(content.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let key = format!("{}{}", self.msg_hash_prefix, hash);

        // Use Lua script to atomically check and set (SETNX with TTL)
        // This reduces from 2 commands (EXISTS + SETEX) to 1 command
        let script = redis::Script::new(
            r"
            local exists = redis.call('EXISTS', KEYS[1])
            if exists == 1 then
                return 0  -- Already exists, replay detected
            end
            redis.call('SETEX', KEYS[1], ARGV[1], ARGV[2])
            return 1  -- New message, valid
            ",
        );

        let result: i64 = script
            .key(&key)
            .arg(max_age_seconds)
            .arg(timestamp.to_string())
            .invoke_async(self.client)
            .await?;

        if result == 0 {
            tracing::warn!(
                message_id = %message_id,
                hash = %hash,
                "Potential replay attack detected (duplicate hash)"
            );
            return Ok(false); // Message already seen
        }

        Ok(true) // Request is new and valid
    }
}
