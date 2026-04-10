// ============================================================================
// Token Management
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_redis::RedisClient;

pub(crate) struct TokenManager<'a> {
    client: &'a mut RedisClient,
}

impl<'a> TokenManager<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    /// Store refresh token in Redis for validation and revocation.
    /// Also registers the JTI in the per-user reverse index (user_tokens:{user_id})
    /// so that revoke_all_user_tokens can work without a KEYS scan.
    pub(crate) async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("refresh_token:{}", jti);
        let index_key = format!("user_tokens:{}", user_id);
        self.client
            .set_ex(&key, user_id, ttl_seconds as u64)
            .await?;
        self.client.sadd(&index_key, jti).await?;
        self.client.expire(&index_key, ttl_seconds).await?;
        Ok(())
    }

    /// Check if refresh token is valid (exists and not revoked)
    pub(crate) async fn check_refresh_token(&mut self, jti: &str) -> Result<Option<String>> {
        let key = format!("refresh_token:{}", jti);
        let user_id: Option<String> = self.client.get(&key).await?;
        Ok(user_id)
    }

    /// Revoke refresh token (soft logout)
    pub(crate) async fn revoke_refresh_token(&mut self, jti: &str) -> Result<()> {
        let key = format!("refresh_token:{}", jti);
        let _: i64 = self.client.del(&key).await?;
        Ok(())
    }

    /// Consume refresh token atomically: check existence and delete in one operation.
    /// Returns Some(user_id) if token was valid and consumed.
    /// Returns None if token doesn't exist or was already consumed.
    /// This prevents race conditions where two parallel refresh requests could both succeed.
    pub(crate) async fn consume_refresh_token(&mut self, jti: &str) -> Result<Option<String>> {
        let key = format!("refresh_token:{}", jti);
        let script = redis::Script::new(
            r#"
            local val = redis.call('GET', KEYS[1])
            if val then
                redis.call('DEL', KEYS[1])
                return val
            else
                return false
            end
            "#,
        );
        let result: redis::Value = script
            .key(&key)
            .invoke_async(self.client.connection_mut())
            .await?;

        match result {
            redis::Value::BulkString(bytes) => {
                Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
            }
            _ => Ok(None),
        }
    }

    /// Atomically rotate a refresh token: consume the old JTI and store the new one
    /// in a single Lua script (one Redis round-trip, no crash window between the two).
    ///
    /// Returns `Some(user_id)` on success, `None` if the old token was not found
    /// (already consumed or revoked).  The reverse index (`user_tokens:{user_id}`) is
    /// updated within the same script so logout-all always sees the current token.
    pub(crate) async fn rotate_refresh_token(
        &mut self,
        old_jti: &str,
        new_jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<Option<String>> {
        let old_key = format!("refresh_token:{}", old_jti);
        let new_key = format!("refresh_token:{}", new_jti);
        let index_key = format!("user_tokens:{}", user_id);

        // Lua script:
        // 1. GET the old token — if absent, return nil (already consumed).
        // 2. DEL old token.
        // 3. SET new token with TTL.
        // 4. SADD + EXPIRE on the per-user reverse index.
        // All operations are serialised by Redis's single-threaded command executor.
        let script = redis::Script::new(
            r#"
            local val = redis.call('GET', KEYS[1])
            if not val then
                return false
            end
            redis.call('DEL', KEYS[1])
            redis.call('SETEX', KEYS[2], ARGV[1], ARGV[2])
            redis.call('SADD',  KEYS[3], ARGV[3])
            redis.call('EXPIRE', KEYS[3], ARGV[1])
            return val
            "#,
        );

        let result: redis::Value = script
            .key(&old_key)
            .key(&new_key)
            .key(&index_key)
            .arg(ttl_seconds)
            .arg(user_id)
            .arg(new_jti)
            .invoke_async(self.client.connection_mut())
            .await?;

        match result {
            redis::Value::BulkString(bytes) => {
                Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
            }
            _ => Ok(None),
        }
    }

    /// Revoke all refresh tokens for a user (logout from all devices).
    /// Uses the per-user reverse index user_tokens:{user_id} (populated by store_refresh_token)
    /// to avoid a KEYS scan which blocks the Redis event loop.
    pub(crate) async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        let index_key = format!("user_tokens:{}", user_id);

        let jtis: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&index_key)
            .query_async(self.client.connection_mut())
            .await
            .unwrap_or_default();

        let mut deleted_count = 0usize;
        for jti in &jtis {
            let token_key = format!("refresh_token:{}", jti);
            let n: i64 = self.client.del(&token_key).await.unwrap_or(0);
            deleted_count += n as usize;
        }
        self.client.del(&index_key).await.unwrap_or(0i64);

        tracing::info!(
            user_id = %user_id,
            deleted_count = deleted_count,
            "Revoked all refresh tokens for user"
        );

        Ok(())
    }

    /// Store invalidated access token (for soft logout)
    ///
    /// Stores token JTI with short TTL to prevent reuse after logout
    /// TTL should match access token lifetime
    pub(crate) async fn invalidate_access_token(
        &mut self,
        jti: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("invalidated_token:{}", jti);
        let _: () = self.client.set_ex(&key, "1", ttl_seconds as u64).await?;
        Ok(())
    }

    /// Check if access token is invalidated (was revoked)
    ///
    /// # Returns
    /// * `Ok(true)` - Token is invalidated (should be rejected)
    /// * `Ok(false)` - Token is valid (not invalidated)
    pub(crate) async fn is_token_invalidated(&mut self, jti: &str) -> Result<bool> {
        let key = format!("invalidated_token:{}", jti);
        let exists: bool = self.client.exists(&key).await?;
        Ok(exists)
    }

    // =========================================================================
    // Device Link Tokens (for multi-device QR linking)
    // =========================================================================

    /// Store a device link token with 15-minute TTL.
    /// Value: "{user_id}" — the user who initiated the link.
    pub(crate) async fn store_device_link_token(
        &mut self,
        token: &str,
        user_id: &str,
    ) -> Result<()> {
        let key = format!("device_link:{}", token);
        let _: () = self.client.set_ex(&key, user_id, 15 * 60).await?;
        Ok(())
    }

    /// Consume a device link token (one-time use): returns the user_id if valid.
    /// Deletes the token atomically so it cannot be reused.
    pub(crate) async fn consume_device_link_token(
        &mut self,
        token: &str,
    ) -> Result<Option<String>> {
        let key = format!("device_link:{}", token);
        // GET then DEL — fine for our scale (single Redis, no race condition risk)
        let user_id: Option<String> = self.client.get(&key).await?;
        if user_id.is_some() {
            let _: i64 = self.client.del(&key).await?;
        }
        Ok(user_id)
    }

    // =========================================================================
    // Join Request Tokens (Flow B: TUI → Phone linking)
    // =========================================================================

    /// Store a join request payload (JSON) with 10-minute TTL.
    pub(crate) async fn store_join_request(
        &mut self,
        pending_device_id: &str,
        json_payload: &str,
    ) -> Result<()> {
        let key = format!("join_req:{}", pending_device_id);
        let _: () = self.client.set_ex(&key, json_payload, 10 * 60).await?;
        Ok(())
    }

    /// Get a join request payload by pending_device_id (non-destructive read).
    pub(crate) async fn get_join_request(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<String>> {
        let key = format!("join_req:{}", pending_device_id);
        let payload: Option<String> = self.client.get(&key).await?;
        Ok(payload)
    }

    /// Atomically consume a join request (GET + DEL).
    /// Returns the JSON payload if it existed.
    pub(crate) async fn consume_join_request(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<String>> {
        let key = format!("join_req:{}", pending_device_id);
        let payload: Option<String> = self.client.get(&key).await?;
        if payload.is_some() {
            let _: i64 = self.client.del(&key).await?;
        }
        Ok(payload)
    }

    /// Store approved join result with tokens, 2-minute TTL.
    /// Value format: "{access_token}:{refresh_token}:{user_id}:{exp_timestamp}"
    pub(crate) async fn store_join_approved(
        &mut self,
        pending_device_id: &str,
        value: &str,
    ) -> Result<()> {
        let key = format!("join_approved:{}", pending_device_id);
        let _: () = self.client.set_ex(&key, value, 2 * 60).await?;
        Ok(())
    }

    /// Get approved join result by pending_device_id.
    /// Returns: "{access_token}:{refresh_token}:{user_id}:{exp_timestamp}" or None.
    pub(crate) async fn get_join_approved(
        &mut self,
        pending_device_id: &str,
    ) -> Result<Option<String>> {
        let key = format!("join_approved:{}", pending_device_id);
        let value: Option<String> = self.client.get(&key).await?;
        Ok(value)
    }
}
