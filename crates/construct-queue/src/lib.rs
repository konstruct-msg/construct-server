// ============================================================================
// Message Queue Module - Phase 2.8 Refactoring
// ============================================================================
//
// Phase 2.8: Split large queue.rs (1203 lines) into logical modules:
// - redis.rs: Redis connection and basic operations
// - sessions.rs: Session management
// - replay.rs: Replay protection
// - rate_limiting.rs: Rate limiting operations
// - cache.rs: Cache operations (key bundles, federation keys)
// - tokens.rs: Token management (refresh tokens, access tokens)
// - delivery.rs: Message delivery operations
//
// ============================================================================

mod cache;
mod connection;
mod delivery;
mod pow;
mod rate_limiting;
mod replay;
mod sessions;
mod tokens;

pub use pow::PowChallengeRecord;

#[cfg(test)]
mod tests;

use anyhow::Result;
use construct_config::{Config, SECONDS_PER_DAY};
use construct_redis::RedisClient;

/// Message Queue - Redis-only Storage (No Database Persistence)
///
/// IMPORTANT SECURITY POLICY:
///
/// Messages are NEVER persisted to the database to prevent:
/// 1. Social graph reconstruction (metadata leakage: who talks to whom)
/// 2. Long-term storage of encrypted data (reduces attack surface)
/// 3. Server-side message history (true end-to-end encryption)
///
/// Message Lifecycle:
/// 1. Online recipient  → Direct delivery via WebSocket (no storage)
/// 2. Offline recipient → Temporary storage in Redis with TTL
/// 3. User connects     → Messages delivered from Redis queue
/// 4. After delivery    → Messages DELETED from Redis immediately
/// 5. After TTL expires → Undelivered messages AUTO-DELETED by Redis
// MessageQueue clones share the same underlying Redis multiplexed connection.
// Each clone is safe to use concurrently from a separate Tokio task without
// additional locking, because redis::aio::ConnectionManager pipelines commands
// internally. This allows per-stream queue clones to call XREAD in parallel
// without serializing on a shared Mutex.
#[derive(Clone)]
pub struct MessageQueue {
    client: RedisClient,
    /// TTL for queued messages in seconds (configured via message_ttl_days)
    /// After this period, undelivered messages are automatically deleted by Redis
    #[allow(dead_code)]
    message_ttl_seconds: i64,
    offline_queue_prefix: String,
    delivery_queue_prefix: String,
    /// Reference to config for Redis key prefixes (needed for key generation)
    config: Config,
}

impl MessageQueue {
    pub async fn new(config: &Config) -> Result<Self> {
        tracing::debug!("Connecting to Redis via construct-redis...");

        // Parse Redis URL to check if TLS is required
        let is_tls = config.redis_url.starts_with("rediss://");
        if is_tls {
            tracing::info!("Redis TLS enabled (rediss://)");
        } else {
            tracing::info!("Redis TLS not enabled (redis://)");
        }

        // Use RedisClient from construct-redis
        let client = RedisClient::connect(&config.redis_url)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

        let message_ttl_seconds = config.message_ttl_days * SECONDS_PER_DAY;
        tracing::info!(
            "Message queue TTL: {} days ({} seconds)",
            config.message_ttl_days,
            message_ttl_seconds
        );
        Ok(Self {
            client,
            message_ttl_seconds,
            offline_queue_prefix: config.offline_queue_prefix.clone(),
            delivery_queue_prefix: config.delivery_queue_prefix.clone(),
            config: config.clone(),
        })
    }

    // ============================================================================
    // Legacy list-mailbox helpers (unused)
    // ============================================================================
    //
    // Kafka / delivery-worker is gone. Production delivery is Redis Streams
    // (`write_message_to_device_streams`). `has_messages` still looks at the
    // old list prefix and has no callers.

    #[allow(dead_code)]
    pub async fn has_messages(&mut self, user_id: &str) -> Result<bool> {
        let key = format!("{}{}", self.offline_queue_prefix, user_id);
        let count: i64 = self.client.llen(&key).await?;
        Ok(count > 0)
    }

    // ============================================================================
    // Session Management (delegated to sessions module)
    // ============================================================================

    pub async fn create_session(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .create_session(jti, user_id, ttl_seconds)
            .await
    }

    pub async fn validate_session(&mut self, jti: &str) -> Result<Option<String>> {
        sessions::SessionManager::new(&mut self.client)
            .validate_session(jti)
            .await
    }

    pub async fn revoke_session(&mut self, jti: &str, user_id: &str) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .revoke_session(jti, user_id)
            .await
    }

    #[allow(dead_code)]
    pub async fn revoke_all_sessions(&mut self, user_id: &str) -> Result<()> {
        sessions::SessionManager::new(&mut self.client)
            .revoke_all_sessions(user_id)
            .await
    }

    // ============================================================================
    // Replay Protection (delegated to replay module)
    // ============================================================================

    pub async fn check_message_replay(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
    ) -> Result<bool> {
        replay::ReplayProtection::new(
            &mut self.client,
            self.config.redis_key_prefixes.msg_hash.clone(),
        )
        .check_message_replay(message_id, content, nonce)
        .await
    }

    pub async fn check_replay_with_timestamp(
        &mut self,
        message_id: &str,
        content: &str,
        nonce: &str,
        timestamp: i64,
        max_age_seconds: i64,
    ) -> Result<bool> {
        replay::ReplayProtection::new(
            &mut self.client,
            self.config.redis_key_prefixes.msg_hash.clone(),
        )
        .check_replay_with_timestamp(message_id, content, nonce, timestamp, max_age_seconds)
        .await
    }

    // ============================================================================
    // Rate Limiting (delegated to rate_limiting module)
    // ============================================================================

    pub async fn increment_message_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_message_count(user_id)
            .await
    }

    pub async fn increment_ip_message_count(&mut self, ip: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_ip_message_count(ip)
            .await
    }

    pub async fn increment_combined_rate_limit(
        &mut self,
        user_id: &str,
        ip: &str,
        ttl_seconds: i64,
    ) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_combined_rate_limit(user_id, ip, ttl_seconds)
            .await
    }

    pub async fn increment_key_update_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_key_update_count(user_id)
            .await
    }

    /// Increment Privacy Pass token issuance count for hourly rate limiting.
    pub async fn increment_token_issuance_count(&mut self, user_id: &str, n: u64) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_token_issuance_count(user_id, n)
            .await
    }

    pub async fn increment_password_change_count(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_password_change_count(user_id)
            .await
    }

    pub async fn increment_rate_limit(&mut self, key: &str, ttl_seconds: i64) -> Result<i64> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_rate_limit(key, ttl_seconds)
            .await
    }

    pub async fn increment_failed_login_count(&mut self, username: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .increment_failed_login_count(username)
            .await
    }

    pub async fn reset_failed_login_count(&mut self, username: &str) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .reset_failed_login_count(username)
            .await
    }

    #[allow(dead_code)]
    pub async fn get_message_count_last_hour(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .get_message_count_last_hour(user_id)
            .await
    }

    #[allow(dead_code)]
    pub async fn get_key_update_count_last_day(&mut self, user_id: &str) -> Result<u32> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .get_key_update_count_last_day(user_id)
            .await
    }

    pub async fn block_user_temporarily(
        &mut self,
        user_id: &str,
        duration_seconds: i64,
        reason: &str,
    ) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .block_user_temporarily(user_id, duration_seconds, reason)
            .await
    }

    pub async fn is_user_blocked(&mut self, user_id: &str) -> Result<Option<String>> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .is_user_blocked(user_id)
            .await
    }

    /// Check warmup-aware rate limit for a user action
    ///
    /// This is the main entry point for warmup rate limiting.
    /// It checks the appropriate limits based on whether the user is in warmup period.
    ///
    /// Parameters:
    /// - user_id: User identifier (UUID string)
    /// - action: Rate limit action identifier (e.g., "msg_send", "chat_create")
    /// - max_count: Maximum allowed count in the window
    /// - window_seconds: Time window in seconds
    pub async fn check_warmup_rate_limit(
        &mut self,
        user_id: &str,
        action: &str,
        max_count: u32,
        window_seconds: u64,
    ) -> Result<()> {
        rate_limiting::RateLimiter::new(&mut self.client)
            .check_warmup_rate_limit(user_id, action, max_count, window_seconds)
            .await
    }

    // ============================================================================
    // Token Management (delegated to tokens module)
    // ============================================================================

    pub async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_refresh_token(jti, user_id, ttl_seconds)
            .await
    }

    pub async fn check_refresh_token(&mut self, jti: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .check_refresh_token(jti)
            .await
    }

    pub async fn revoke_refresh_token(&mut self, jti: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .revoke_refresh_token(jti)
            .await
    }

    /// Atomically consume refresh token: check and delete in one operation.
    /// Returns Some(user_id) if token was valid, None if not found.
    pub async fn consume_refresh_token(&mut self, jti: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .consume_refresh_token(jti)
            .await
    }

    /// Atomically rotate refresh token: consume old JTI and store new JTI in one
    /// Redis Lua script.  Eliminates the crash window between consume and store.
    /// Returns Some(user_id) on success, None if old token not found (already used).
    pub async fn rotate_refresh_token(
        &mut self,
        old_jti: &str,
        new_jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .rotate_refresh_token(old_jti, new_jti, user_id, ttl_seconds)
            .await
    }

    pub async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .revoke_all_user_tokens(user_id)
            .await
    }

    pub async fn invalidate_access_token(&mut self, jti: &str, ttl_seconds: i64) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .invalidate_access_token(jti, ttl_seconds)
            .await
    }

    pub async fn is_token_invalidated(&mut self, jti: &str) -> Result<bool> {
        tokens::TokenManager::new(&mut self.client)
            .is_token_invalidated(jti)
            .await
    }

    pub async fn mark_device_revoked(&mut self, device_id: &str, ttl_seconds: i64) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .mark_device_revoked(device_id, ttl_seconds)
            .await
    }

    pub async fn is_device_revoked(&mut self, device_id: &str) -> Result<bool> {
        tokens::TokenManager::new(&mut self.client)
            .is_device_revoked(device_id)
            .await
    }

    // =========================================================================
    // Device Link Tokens
    // =========================================================================

    pub async fn store_device_link_token(&mut self, token: &str, user_id: &str) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_device_link_token(token, user_id)
            .await
    }

    pub async fn consume_device_link_token(&mut self, token: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .consume_device_link_token(token)
            .await
    }

    // =========================================================================
    // Join Request Tokens (Flow B)
    // =========================================================================

    pub async fn store_join_request(
        &mut self,
        pending_device_id: &str,
        payload: &[u8],
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_join_request(pending_device_id, payload)
            .await
    }

    pub async fn get_join_request(&mut self, pending_device_id: &str) -> Result<Option<Vec<u8>>> {
        tokens::TokenManager::new(&mut self.client)
            .get_join_request(pending_device_id)
            .await
    }

    pub async fn consume_join_request(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        tokens::TokenManager::new(&mut self.client)
            .consume_join_request(pending_device_id)
            .await
    }

    pub async fn store_join_approved(
        &mut self,
        pending_device_id: &str,
        value: &str,
    ) -> Result<()> {
        tokens::TokenManager::new(&mut self.client)
            .store_join_approved(pending_device_id, value)
            .await
    }

    pub async fn get_join_approved(&mut self, pending_device_id: &str) -> Result<Option<String>> {
        tokens::TokenManager::new(&mut self.client)
            .get_join_approved(pending_device_id)
            .await
    }

    // ============================================================================
    // Cache Operations (delegated to cache module)
    // ============================================================================

    pub async fn cache_key_bundle(
        &mut self,
        user_id: &str,
        bundle: &construct_crypto::UploadableKeyBundle,
        ttl_hours: i64,
    ) -> Result<()> {
        cache::CacheManager::new(&mut self.client)
            .cache_key_bundle(user_id, bundle, ttl_hours)
            .await
    }

    pub async fn get_cached_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<construct_crypto::UploadableKeyBundle>> {
        cache::CacheManager::new(&mut self.client)
            .get_cached_key_bundle(user_id)
            .await
    }

    pub async fn invalidate_key_bundle_cache(&mut self, user_id: &str) -> Result<()> {
        cache::CacheManager::new(&mut self.client)
            .invalidate_key_bundle_cache(user_id)
            .await
    }

    pub async fn cache_federation_key_bundle(
        &mut self,
        user_id: &str,
        response_json: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        cache::CacheManager::new(&mut self.client)
            .cache_federation_key_bundle(user_id, response_json, ttl_seconds)
            .await
    }

    pub async fn get_cached_federation_key_bundle(
        &mut self,
        user_id: &str,
    ) -> Result<Option<String>> {
        cache::CacheManager::new(&mut self.client)
            .get_cached_federation_key_bundle(user_id)
            .await
    }

    // ============================================================================
    // Connection Tracking
    // ============================================================================

    #[allow(dead_code)]
    pub async fn track_connection(&mut self, user_id: &str, connection_id: &str) -> Result<u32> {
        use construct_config::SECONDS_PER_HOUR;
        use redis::AsyncCommands;

        let key = format!("connections:{}", user_id);
        let _: i64 = self
            .client
            .connection_mut()
            .sadd(&key, connection_id)
            .await?;
        let _: bool = self
            .client
            .connection_mut()
            .expire(&key, SECONDS_PER_HOUR)
            .await?;

        let count: u32 = self.client.connection_mut().scard(&key).await?;
        Ok(count)
    }

    #[allow(dead_code)]
    pub async fn untrack_connection(&mut self, user_id: &str, connection_id: &str) -> Result<()> {
        use redis::AsyncCommands;

        let key = format!("connections:{}", user_id);
        let _: i64 = self
            .client
            .connection_mut()
            .srem(&key, connection_id)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_active_connections(&mut self, user_id: &str) -> Result<u32> {
        use redis::AsyncCommands;

        let key = format!("connections:{}", user_id);
        let count: u32 = self.client.connection_mut().scard(&key).await?;
        Ok(count)
    }

    // ============================================================================
    // Basic Operations
    // ============================================================================

    pub async fn ping(&mut self) -> Result<()> {
        let _: () = redis::cmd("PING")
            .query_async(self.client.connection_mut())
            .await?;
        Ok(())
    }

    /// Set a key with expiration (generic string storage)
    pub async fn set_with_expiry(
        &mut self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> Result<()> {
        use redis::AsyncCommands;
        let _: () = self
            .client
            .connection_mut()
            .set_ex(key, value, ttl_seconds)
            .await?;
        Ok(())
    }

    /// Get a string value by key
    pub async fn get(&mut self, key: &str) -> Result<Option<String>> {
        use redis::AsyncCommands;
        let value: Option<String> = self.client.connection_mut().get(key).await?;
        Ok(value)
    }

    /// Delete a key
    pub async fn delete(&mut self, key: &str) -> Result<()> {
        use redis::AsyncCommands;
        let _: i64 = self.client.connection_mut().del(key).await?;
        Ok(())
    }

    // ============================================================================
    // Message Delivery (delegated to delivery module)
    // ============================================================================

    pub async fn read_user_messages_from_stream(
        &mut self,
        user_id: &str,
        server_instance_id: Option<&str>,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .read_user_messages_from_stream(user_id, server_instance_id, since_id, count)
        .await
    }

    // `trim_offline_stream` was removed with minimal-server-delivery step 2 — see the
    // note at its old site in delivery.rs. Nothing may delete a user's mail from a
    // cursor the user's client supplied.

    pub async fn wait_for_message_notification(
        &self,
        _user_id: &str,
        timeout_ms: u64,
    ) -> Result<bool> {
        // Note: This method doesn't need mutable access, but DeliveryManager requires it
        // We'll create a temporary mutable reference
        // Actually, wait_for_message_notification doesn't use client, so we can make it simpler
        use tokio::time::Duration;
        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
        Ok(false)
    }

    pub async fn track_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .track_user_online(user_id, server_instance_id)
        .await
    }

    pub async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .untrack_user_online(user_id)
        .await
    }

    pub async fn get_user_server_instance(&mut self, user_id: &str) -> Result<Option<String>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .get_user_server_instance(user_id)
        .await
    }

    pub async fn publish_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
        online_channel: &str,
    ) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .publish_user_online(user_id, server_instance_id, online_channel)
        .await
    }

    /// Leftover delivery-worker poll of `delivery_queue:{instance}`. Tests only.
    pub async fn poll_delivery_queue(&mut self, server_instance_id: &str) -> Result<Vec<Vec<u8>>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .poll_delivery_queue(server_instance_id)
        .await
    }

    /// Leftover delivery-worker instance registry. Tests only — production
    /// routing is `GET user:{user}:server_instance_id`.
    pub async fn register_server_instance(
        &mut self,
        queue_key: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .register_server_instance(queue_key, ttl_seconds)
        .await
    }

    /// Write a message to the legacy user mailbox stream.
    ///
    /// Prefer `write_message_to_device_streams`, which also fans out to device
    /// streams and publishes wakeup after the XADDs land.
    pub async fn write_message_to_user_stream(
        &mut self,
        user_id: &str,
        envelope: &construct_message::types::MessageEnvelope,
    ) -> Result<String> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .write_message_to_user_stream(user_id, envelope)
        .await
    }

    /// Fan-out a message to per-device Redis streams (multi-device support).
    ///
    /// Writes to `{prefix}:offline:{user_id}:{device_id}` for each `device_id` in the slice.
    /// Also keeps the legacy user-level stream (`{prefix}:offline:{user_id}`) so old clients
    /// that don't send `x-device-id` continue to receive messages unchanged.
    ///
    /// The single `inbox:wakeup:{user_id}` wakeup publish is sufficient — all connected
    /// devices for a user subscribe to the same channel and wake up together.
    ///
    /// **Errors when the message reached no stream at all.** After the step-4 cutover
    /// (`MSG_MAILBOX_USER_WRITE=0`) the device streams are the only mailbox, and
    /// `device_ids` is empty whenever the device lookup failed — `fetch_recipient_device_ids`
    /// returns `vec![]` on a DB error and on an unparseable user id alike. Returning `Ok`
    /// there would let `dispatch_envelope` report a delivered message that was never
    /// written: the same silent loss the cursor trim was removed to prevent, re-entered
    /// from the write side. A hard error surfaces it to the sender instead.
    pub async fn write_message_to_device_streams(
        &mut self,
        user_id: &str,
        device_ids: &[String],
        envelope: &construct_message::types::MessageEnvelope,
    ) -> Result<()> {
        let write_user = self.config.messaging.mailbox_user_write;

        // The "nowhere to land" check is at the bottom, after the writes, and there is
        // deliberately only one: an empty `device_ids` already produces zero successful
        // device writes, so an early guard on it would be a second spelling of the same
        // condition — and a mutation test proved it, surviving the removal of one guard
        // because the other still fired.
        if write_user {
            // Legacy user stream (cutover: MSG_MAILBOX_USER_WRITE=0 skips this).
            delivery::DeliveryManager::new(
                &mut self.client,
                &self.config,
                self.delivery_queue_prefix.clone(),
            )
            .write_message_to_user_stream(user_id, envelope)
            .await?;
        }

        // Per-device streams (always).
        let mut device_writes_ok = 0usize;
        for device_id in device_ids {
            match delivery::DeliveryManager::new(
                &mut self.client,
                &self.config,
                self.delivery_queue_prefix.clone(),
            )
            .write_message_to_device_stream(user_id, device_id, envelope)
            .await
            {
                Ok(()) => device_writes_ok += 1,
                Err(e) => {
                    // One failing device must not stop the others — but see the check below:
                    // "every device failed" is only tolerable while the user stream holds a copy.
                    tracing::warn!(
                        user_id = %user_id,
                        device_id = %device_id,
                        error = %e,
                        "Failed to write to per-device stream (non-fatal)"
                    );
                }
            }
        }

        // Nowhere to land. Covers both shapes at once: no devices known (a failed lookup
        // and a user with none are indistinguishable here) and every device write failed.
        if !write_user && device_writes_ok == 0 {
            anyhow::bail!(
                "No mailbox to write: user-stream writes are disabled (MSG_MAILBOX_USER_WRITE=0) \
                 and none of the {} device stream writes for recipient {user_id} landed",
                device_ids.len()
            );
        }

        // Wake only after at least one XADD has landed. Publishing first (the old
        // MSG_MAILBOX_USER_WRITE=0 branch) let a live MessageStream poll an empty
        // device stream and miss the message until the fallback tick.
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .publish_inbox_wakeup(user_id)
        .await;

        Ok(())
    }

    /// Whether legacy user-stream XADD is enabled (`MSG_MAILBOX_USER_WRITE`).
    pub fn mailbox_user_write_enabled(&self) -> bool {
        self.config.messaging.mailbox_user_write
    }

    /// Read messages from a per-device Redis stream.
    ///
    /// Used by multi-device-aware clients that pass `x-device-id` in stream metadata.
    /// Falls back gracefully: if the device stream is empty or doesn't exist, returns [].
    pub async fn read_device_messages_from_stream(
        &mut self,
        user_id: &str,
        device_id: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .read_device_messages_from_stream(user_id, device_id, since_id, count)
        .await
    }

    /// Read the recipient mailbox for delivery.
    ///
    /// - No `device_id`: legacy user stream only.
    /// - With `device_id` (step 3 transitional dual-read): merge device stream + user
    ///   stream, dedupe by `message_id` (prefer device copy), order by Redis stream id
    ///   as a time watermark, return at most `count` entries.
    ///
    /// Stream ids from the two keys are not the same sequence, but both are
    /// millisecond-based; a client cursor from either works as a shared watermark.
    /// See construct-docs `decisions/minimal-server-delivery.md` step 3.
    pub async fn read_mailbox_messages(
        &mut self,
        user_id: &str,
        device_id: Option<&str>,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<MailboxPage> {
        let Some(device_id) = device_id.filter(|d| !d.is_empty()) else {
            let entries = self
                .read_user_messages_from_stream(user_id, None, since_id, count)
                .await?;
            // Not a coverage signal: without a device_id there is no device stream to
            // compare against, so nothing here says anything about cutover readiness.
            return Ok(MailboxPage {
                entries,
                user_only: 0,
            });
        };

        // Oversample each source so the merge can still fill `count` after dedupe.
        let per_source = count.saturating_mul(2);
        let device_msgs = self
            .read_device_messages_from_stream(user_id, device_id, since_id, per_source)
            .await?;
        let user_msgs = self
            .read_user_messages_from_stream(user_id, None, since_id, per_source)
            .await?;

        Ok(merge_mailbox_pages(device_msgs, user_msgs, count))
    }

    /// Store the sender_id of a message for receipt routing.
    /// Called when dispatching a message so receipts can be relayed back to the sender.
    pub async fn store_message_sender(&mut self, message_id: &str, sender_id: &str) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .store_message_sender(message_id, sender_id)
        .await
    }

    /// Look up the original sender_id for a message_id (for receipt routing).
    pub async fn get_message_sender(&mut self, message_id: &str) -> Result<Option<String>> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .get_message_sender(message_id)
        .await
    }

    /// Returns true if this message_id was already dispatched (duplicate retry).
    pub async fn is_message_duplicate(&mut self, message_id: &str) -> Result<bool> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .is_message_duplicate(message_id)
        .await
    }

    /// Mark message_id as dispatched (idempotency key, TTL 24h).
    pub async fn mark_message_dispatched(&mut self, message_id: &str) -> Result<()> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .mark_message_dispatched(message_id)
        .await
    }

    /// Clone the internal Redis ConnectionManager for rate-limiting / caching operations.
    ///
    /// `ConnectionManager` is designed to be cloned — the clone shares the same underlying
    /// connection pool and reconnect logic. Callers get an independent handle without
    /// needing to hold the queue lock while performing Redis operations.
    pub fn clone_redis_connection(&self) -> redis::aio::ConnectionManager {
        self.client.connection().clone()
    }

    /// Trim all offline message streams to remove entries older than `max_age_seconds`.
    ///
    /// Delegates to `DeliveryManager::trim_streams_by_age`. Intended to be called from
    /// a periodic background task (e.g., every hour) to enforce the 30-day queue TTL.
    pub async fn trim_streams_by_age(&mut self, max_age_seconds: u64) -> Result<u64> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .trim_streams_by_age(max_age_seconds)
        .await
    }

    /// Purge all pending messages from `sender_id` out of `recipient_id`'s delivery
    /// streams (user-level and all per-device streams).
    ///
    /// Call immediately after a block operation to prevent the blocked contact's
    /// messages from being delivered on the next background fetch.
    /// Returns the number of stream entries deleted (informational only).
    pub async fn purge_stream_messages_from_sender(
        &mut self,
        recipient_id: &str,
        sender_id: &str,
    ) -> Result<u64> {
        delivery::DeliveryManager::new(
            &mut self.client,
            &self.config,
            self.delivery_queue_prefix.clone(),
        )
        .purge_messages_from_sender(recipient_id, sender_id)
        .await
    }
}

/// One mailbox read, plus the one number the step-4 cutover turns on.
pub struct MailboxPage {
    pub entries: Vec<(String, Option<construct_message::types::MessageEnvelope>)>,
    /// Entries in this page that the **device** stream did not have — they exist only
    /// because the legacy user stream is still written and still read.
    ///
    /// This is the cutover gate. Counting how many reads *used* dual-read says only that
    /// clients send a `device_id`; it cannot tell whether the device streams are complete,
    /// and completeness is the whole question before `MSG_MAILBOX_USER_WRITE=0` turns the
    /// user stream off. While this stays above zero, flipping the flag drops exactly these
    /// messages.
    pub user_only: usize,
}

/// Merge device + user mailbox pages for transitional dual-read.
///
/// Prefer the device copy when `message_id` collides. Order by Redis stream id
/// (millisecond watermark). Corrupt/`None` envelopes keep their stream ids for
/// cursor advance and never collide on message_id.
fn merge_mailbox_pages(
    device_msgs: Vec<(String, Option<construct_message::types::MessageEnvelope>)>,
    user_msgs: Vec<(String, Option<construct_message::types::MessageEnvelope>)>,
    count: usize,
) -> MailboxPage {
    use std::collections::{HashMap, HashSet};

    let device_ids: HashSet<String> = device_msgs
        .iter()
        .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.clone()))
        .collect();

    let mut by_message_id: HashMap<String, (String, construct_message::types::MessageEnvelope)> =
        HashMap::new();
    let mut orphans: Vec<(String, Option<construct_message::types::MessageEnvelope>)> = Vec::new();

    // User first, then device overwrites — device wins on collision.
    for (stream_id, envelope) in user_msgs.into_iter().chain(device_msgs) {
        match envelope {
            Some(env) => {
                by_message_id.insert(env.message_id.clone(), (stream_id, env));
            }
            None => orphans.push((stream_id, None)),
        }
    }

    let mut merged: Vec<(String, Option<construct_message::types::MessageEnvelope>)> =
        by_message_id
            .into_values()
            .map(|(stream_id, env)| (stream_id, Some(env)))
            .chain(orphans)
            .collect();

    merged.sort_by(|a, b| compare_stream_id_watermarks(&a.0, &b.0));
    merged.truncate(count);

    // Counted after truncation: only entries actually handed to the client are evidence.
    let user_only = merged
        .iter()
        .filter_map(|(_, e)| e.as_ref())
        .filter(|e| !device_ids.contains(&e.message_id))
        .count();

    MailboxPage {
        entries: merged,
        user_only,
    }
}

fn compare_stream_id_watermarks(a: &str, b: &str) -> std::cmp::Ordering {
    fn parse(id: &str) -> Option<(u64, u64)> {
        if let Some((ts, seq)) = id.split_once('-') {
            Some((ts.parse().ok()?, seq.parse().ok()?))
        } else {
            id.parse::<u64>().ok().map(|ts| (ts, 0))
        }
    }
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        _ => a.cmp(b),
    }
}

#[cfg(test)]
mod mailbox_merge_tests {
    use super::*;
    use construct_message::types::{MessageEnvelope, MessageType};

    fn env(id: &str) -> MessageEnvelope {
        MessageEnvelope {
            message_id: id.to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            timestamp: 1,
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: b"x".to_vec(),
            content_hash: "h".to_string(),
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner: None,
            max_queue_len: None,
            proto_content_type: None,
            recipient_device: None,
        }
    }

    #[test]
    fn merge_prefers_device_copy_and_orders_by_stream_id() {
        let user = vec![
            ("100-0".to_string(), Some(env("m1"))),
            ("300-0".to_string(), Some(env("m2"))),
        ];
        // Same m1 on device with a different stream id — device wins.
        let device = vec![
            ("150-0".to_string(), Some(env("m1"))),
            ("200-0".to_string(), Some(env("m3"))),
        ];
        let page = merge_mailbox_pages(device, user, 10);
        let ids: Vec<_> = page
            .entries
            .iter()
            .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.as_str()))
            .collect();
        assert_eq!(ids, vec!["m1", "m3", "m2"]);
        // m1 kept the device stream id
        assert_eq!(page.entries[0].0, "150-0");
        // m2 exists only in the user stream — the device fan-out missed it.
        assert_eq!(page.user_only, 1);
    }

    #[test]
    fn merge_respects_count_cap() {
        let user = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
            ("300-0".to_string(), Some(env("c"))),
        ];
        let page = merge_mailbox_pages(vec![], user, 2);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].1.as_ref().unwrap().message_id, "a");
        assert_eq!(page.entries[1].1.as_ref().unwrap().message_id, "b");
    }

    /// The gate the cutover reads. Zero means every delivered entry was on the device
    /// stream, so switching the user stream off would have changed nothing — which is
    /// the only evidence that makes `MSG_MAILBOX_USER_WRITE=0` safe.
    #[test]
    fn full_device_coverage_reports_no_user_only_entries() {
        let user = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
        ];
        let device = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
        ];
        assert_eq!(merge_mailbox_pages(device, user, 10).user_only, 0);
    }

    /// Entries dropped by the count cap are re-read on the next poll, so counting them
    /// as a coverage failure now would keep the gate permanently red on a deep backlog.
    ///
    /// Three delivered entries, one of them covered: the covered and uncovered counts
    /// differ, so the assertion distinguishes "missing from the device stream" from its
    /// inverse. With two entries they coincide and the test passes either way.
    #[test]
    fn user_only_counts_delivered_entries_not_the_truncated_tail() {
        let user = vec![
            ("100-0".to_string(), Some(env("a"))),
            ("200-0".to_string(), Some(env("b"))),
            ("300-0".to_string(), Some(env("c"))),
            ("400-0".to_string(), Some(env("d"))),
        ];
        let device = vec![("100-0".to_string(), Some(env("a")))];
        let page = merge_mailbox_pages(device, user, 3);
        assert_eq!(page.entries.len(), 3);
        assert_eq!(
            page.user_only, 2,
            "delivered `b` and `c` count, `d` does not"
        );
    }
}
