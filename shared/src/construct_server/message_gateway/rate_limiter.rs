// ============================================================================
// Rate Limiter
// ============================================================================
//
// Implements rate limiting and user blocking using Redis:
// - Per-user message counters (hourly window)
// - Temporary user blocking
// - Replay attack detection
//
// All state is stored in Redis for multi-instance consistency
// ============================================================================

use anyhow::Result;
use redis::AsyncCommands;

pub struct RateLimiter {
    redis_conn: redis::aio::MultiplexedConnection,
}

impl RateLimiter {
    /// Create a new rate limiter with Redis connection
    pub fn new(redis_conn: redis::aio::MultiplexedConnection) -> Self {
        Self { redis_conn }
    }

    /// Check if user is blocked and return reason if so
    pub async fn check_user_blocked(&mut self, user_id: &str) -> Result<Option<String>> {
        let block_key = format!("user_block:{}", user_id);
        let reason: Option<String> = self.redis_conn.get(&block_key).await?;
        Ok(reason)
    }

    /// Increment message count and return current count
    ///
    /// Uses Redis INCR for atomic increment with 1-hour TTL
    pub async fn increment_message_count(&mut self, user_id: &str) -> Result<u64> {
        let count_key = format!("msg_count:{}:hour", user_id);

        let count: u64 = self.redis_conn.incr(&count_key, 1).await?;

        // Set expiry only on first increment (when count == 1)
        if count == 1 {
            let _: bool = self.redis_conn.expire(&count_key, 3600).await?; // 1 hour
        }

        Ok(count)
    }

    /// Block user temporarily with a reason
    pub async fn block_user(
        &mut self,
        user_id: &str,
        duration_seconds: i64,
        reason: &str,
    ) -> Result<()> {
        let block_key = format!("user_block:{}", user_id);
        let _: () = self
            .redis_conn
            .set_ex(&block_key, reason, duration_seconds as u64)
            .await?;
        Ok(())
    }

    /// Check if message is a replay (already seen)
    ///
    /// Returns true if message is new (not a replay)
    /// Returns false if message was already processed
    pub async fn check_message_replay(&mut self, dedup_key: &str) -> Result<bool> {
        let exists: bool = self.redis_conn.exists(dedup_key).await?;
        Ok(!exists) // Return true if NOT exists (i.e., is new)
    }

    /// Mark message as processed (for replay protection)
    ///
    /// Sets a key with TTL matching message retention policy
    pub async fn mark_message_processed(&mut self, dedup_key: &str, ttl_days: i64) -> Result<()> {
        let ttl_seconds = ttl_days * 24 * 60 * 60;
        let _: () = self
            .redis_conn
            .set_ex(dedup_key, "1", ttl_seconds as u64)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These are integration tests that require a Redis instance
    // Run with: cargo test --features integration-tests

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_increment_message_count() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let conn = client.get_multiplexed_async_connection().await.unwrap();
        let mut limiter = RateLimiter::new(conn);

        let user_id = "test_user_123";

        let count1 = limiter.increment_message_count(user_id).await.unwrap();
        assert_eq!(count1, 1);

        let count2 = limiter.increment_message_count(user_id).await.unwrap();
        assert_eq!(count2, 2);
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_block_user() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let conn = client.get_multiplexed_async_connection().await.unwrap();
        let mut limiter = RateLimiter::new(conn);

        let user_id = "test_blocked_user";

        // Block user
        limiter
            .block_user(user_id, 60, "Rate limit exceeded")
            .await
            .unwrap();

        // Check if blocked
        let reason = limiter.check_user_blocked(user_id).await.unwrap();
        assert_eq!(reason, Some("Rate limit exceeded".to_string()));
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_replay_detection() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let conn = client.get_multiplexed_async_connection().await.unwrap();
        let mut limiter = RateLimiter::new(conn);

        let dedup_key = "test_msg_dedup:abc123";

        // First check: should be new (not a replay)
        let is_new = limiter.check_message_replay(dedup_key).await.unwrap();
        assert!(is_new);

        // Mark as processed
        limiter.mark_message_processed(dedup_key, 7).await.unwrap();

        // Second check: should be replay
        let is_new = limiter.check_message_replay(dedup_key).await.unwrap();
        assert!(!is_new);
    }
}
