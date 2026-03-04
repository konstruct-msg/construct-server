// ============================================================================
// Rate Limiting
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_config::{SECONDS_PER_DAY, SECONDS_PER_HOUR};
use construct_redis::RedisClient;
use redis::AsyncCommands;

pub(crate) struct RateLimiter<'a> {
    client: &'a mut RedisClient,
}

impl<'a> RateLimiter<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    /// Increment message count with atomic TTL setting (optimized)
    /// Uses Lua script to combine INCR + EXPIRE in single atomic operation
    pub(crate) async fn increment_message_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:msg:{}", user_id);

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

        let count: u32 = script
            .key(&key)
            .arg(SECONDS_PER_HOUR)
            .invoke_async(self.client.connection_mut())
            .await?;

        Ok(count)
    }

    /// Increments message count per IP address for rate limiting
    /// Returns the total count of messages from this IP in the last hour
    /// This provides protection against distributed attacks (multiple users from same IP)
    pub(crate) async fn increment_ip_message_count(&mut self, ip: &str) -> Result<u32> {
        // Normalize IP (handle IPv6 brackets if present)
        let normalized_ip = ip.trim_start_matches('[').trim_end_matches(']');
        let key = format!("rate:ip:{}", normalized_ip);

        // Increment counter
        let count: u32 = self.client.incr(&key).await? as u32;

        // Set TTL only on first increment (1 hour window)
        if count == 1 {
            let _: bool = self
                .client
                .connection_mut()
                .expire(&key, SECONDS_PER_HOUR)
                .await?;
        }

        Ok(count)
    }

    /// Increments combined rate limit counter (user_id + IP) - OPTIMIZED
    /// Returns the total count of operations from this user+IP combination in the last hour
    /// This provides more precise rate limiting for authenticated operations:
    /// - Same user from different IPs: separate limits per IP
    /// - Different users from same IP: separate limits per user
    /// - Protects against both account takeover and distributed attacks
    ///
    /// OPTIMIZED: Uses Lua script to combine INCR + EXPIRE in single atomic operation
    pub(crate) async fn increment_combined_rate_limit(
        &mut self,
        user_id: &str,
        ip: &str,
        ttl_seconds: i64,
    ) -> Result<u32> {
        // Normalize IP (handle IPv6 brackets if present)
        let normalized_ip = ip.trim_start_matches('[').trim_end_matches(']');
        let key = format!("rate:combined:{}:{}", user_id, normalized_ip);

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

        let count: u32 = script
            .key(&key)
            .arg(ttl_seconds)
            .invoke_async(self.client.connection_mut())
            .await?;

        Ok(count)
    }

    pub(crate) async fn increment_key_update_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:key:{}", user_id);

        let count: u32 = self.client.incr(&key).await? as u32;

        if count == 1 {
            let _: bool = self
                .client
                .connection_mut()
                .expire(&key, SECONDS_PER_DAY)
                .await?;
        }

        Ok(count)
    }

    /// Increments password change attempt counter for rate limiting
    /// Returns the total count of password changes in the last 24 hours
    pub(crate) async fn increment_password_change_count(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:pwd:{}", user_id);

        let count: u32 = self.client.incr(&key).await? as u32;

        if count == 1 {
            let _: bool = self
                .client
                .connection_mut()
                .expire(&key, SECONDS_PER_DAY)
                .await?;
        }

        Ok(count)
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

    #[allow(dead_code)]
    pub(crate) async fn get_message_count_last_hour(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:msg:{}", user_id);
        let count: Option<u32> = self.client.get(&key).await?;
        Ok(count.unwrap_or(0))
    }

    #[allow(dead_code)]
    pub(crate) async fn get_key_update_count_last_day(&mut self, user_id: &str) -> Result<u32> {
        let key = format!("rate:key:{}", user_id);
        let count: Option<u32> = self.client.get(&key).await?;
        Ok(count.unwrap_or(0))
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

    /// Check and increment warmup-aware rate limit
    /// Returns Ok(()) if allowed, Err with rate limit exceeded message if blocked
    ///
    /// Uses atomic Lua script to check and increment in single operation
    pub(crate) async fn check_warmup_rate_limit(
        &mut self,
        user_id: &str,
        action: &str,
        max_count: u32,
        window_seconds: u64,
    ) -> Result<()> {
        let key = format!("ratelimit:{}:{}", user_id, action);

        // Use Lua script to atomically check limit, increment, and set TTL
        let script = redis::Script::new(
            r"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
            ",
        );

        let count: u32 = script
            .key(&key)
            .arg(window_seconds as i64)
            .invoke_async(self.client.connection_mut())
            .await?;

        if count > max_count {
            // Get TTL for error message
            let ttl: i64 = self.client.connection_mut().ttl(&key).await.unwrap_or(0);

            anyhow::bail!(
                "Rate limit exceeded. Limit: {} per {}. Try again in {} seconds.",
                max_count,
                if window_seconds >= 3600 {
                    format!("{} hours", window_seconds / 3600)
                } else if window_seconds >= 60 {
                    format!("{} minutes", window_seconds / 60)
                } else {
                    format!("{} seconds", window_seconds)
                },
                ttl
            );
        }

        Ok(())
    }
}
