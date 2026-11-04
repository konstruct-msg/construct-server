// ============================================================================
// Rate Limiting
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_config::SECONDS_PER_HOUR;
use construct_redis::RedisClient;
use redis::AsyncCommands;

pub(crate) struct RateLimiter<'a> {
    client: &'a mut RedisClient,
}

impl<'a> RateLimiter<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    /// Generic rate limiter: increments counter for a given key with specified TTL
    /// Returns the current count
    /// OPTIMIZED: Uses Lua script to combine INCR + EXPIRE in single atomic operation
    pub(crate) async fn increment_rate_limit(
        &mut self,
        key: &str,
        ttl_seconds: i64,
    ) -> Result<i64> {
        let full_key = format!("rate:{}", key);

        // Use Lua script to atomically INCR and set TTL only on first increment
        // This reduces from 2 commands to 1 command
        let script = redis::Script::new(
            r"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
            ",
        );

        let count: i64 = script
            .key(&full_key)
            .arg(ttl_seconds)
            .invoke_async(self.client.connection_mut())
            .await?;

        Ok(count)
    }

    /// Increments failed login attempt counter for rate limiting
    /// Returns the total count of failed login attempts in the last 15 minutes
    pub(crate) async fn increment_failed_login_count(&mut self, username: &str) -> Result<u32> {
        let key = format!("rate:login:{}", username);

        let count: u32 = self.client.incr(&key).await? as u32;

        // 15 minutes = 900 seconds
        const FAILED_LOGIN_WINDOW_SECS: i64 = 900;
        if count == 1 {
            let _: bool = self
                .client
                .connection_mut()
                .expire(&key, FAILED_LOGIN_WINDOW_SECS)
                .await?;
        }

        Ok(count)
    }

    /// Resets failed login counter after successful login
    pub(crate) async fn reset_failed_login_count(&mut self, username: &str) -> Result<()> {
        let key = format!("rate:login:{}", username);
        let _: i64 = self.client.del(&key).await?;
        Ok(())
    }

    pub(crate) async fn block_user_temporarily(
        &mut self,
        user_id: &str,
        duration_seconds: i64,
        reason: &str,
    ) -> Result<()> {
        let key = format!("blocked:{}", user_id);
        let _: () = self
            .client
            .set_ex(&key, reason, duration_seconds as u64)
            .await?;

        tracing::warn!(
            user_id = %user_id,
            duration_seconds = duration_seconds,
            reason = %reason,
            "User temporarily blocked"
        );

        Ok(())
    }

    pub(crate) async fn is_user_blocked(&mut self, user_id: &str) -> Result<Option<String>> {
        let key = format!("blocked:{}", user_id);
        let reason: Option<String> = self.client.get(&key).await?;
        Ok(reason)
    }

    fn privacy_pass_hour_key(user_id: &str) -> String {
        let hour = chrono::Utc::now().timestamp() / 3600;
        format!("rate:pp_tokens:{user_id}:{hour}")
    }

    /// Tokens already issued to this user in the current UTC hour.
    pub(crate) async fn token_issuance_count(&mut self, user_id: &str) -> Result<u32> {
        let key = Self::privacy_pass_hour_key(user_id);
        let count: Option<u32> = self.client.get(&key).await?;
        Ok(count.unwrap_or(0))
    }

    /// Compare-and-swap a reservation the caller already sized.
    ///
    /// The size is decided in identity-service (`issuance_grant`) — this script
    /// does not size it again. It only commits `grant` when the key still has
    /// room under `cap`, and returns 0 otherwise, leaving the counter untouched.
    /// Returning the new total and letting the caller reject is what burned the
    /// remainder: the increment had already happened.
    pub(crate) async fn try_reserve_token_issuance(
        &mut self,
        user_id: &str,
        grant: u32,
        cap: u32,
    ) -> Result<u32> {
        let key = Self::privacy_pass_hour_key(user_id);
        let script = redis::Script::new(
            r"
            local count = tonumber(redis.call('GET', KEYS[1]) or '0')
            local grant = tonumber(ARGV[1])
            local cap = tonumber(ARGV[2])
            if grant <= 0 or count + grant > cap then
                return 0
            end
            local newcount = redis.call('INCRBY', KEYS[1], grant)
            if newcount == grant then
                redis.call('EXPIRE', KEYS[1], ARGV[3])
            end
            return grant
            ",
        );

        let reserved: u32 = script
            .key(&key)
            .arg(grant)
            .arg(cap)
            .arg(SECONDS_PER_HOUR)
            .invoke_async(self.client.connection_mut())
            .await?;

        Ok(reserved)
    }
}
