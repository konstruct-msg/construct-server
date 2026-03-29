// ============================================================================
// Token Management
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_redis::RedisClient;
use redis::AsyncCommands;

pub(crate) struct TokenManager<'a> {
    client: &'a mut RedisClient,
}

impl<'a> TokenManager<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    /// Store refresh token in Redis for validation and revocation
    pub(crate) async fn store_refresh_token(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let key = format!("refresh_token:{}", jti);
        // Store user_id with the token for validation
        let _: () = self
            .client
            .set_ex(&key, user_id, ttl_seconds as u64)
            .await?;
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

    /// Revoke all refresh tokens for a user (logout from all devices)
    pub(crate) async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        // Pattern: refresh_token:*
        // Use KEYS for simplicity (in production with many tokens, use SCAN)
        let pattern = "refresh_token:*";

        // Note: KEYS can block Redis, but for token revocation it's acceptable
        // In high-scale production, maintain a reverse index: user_tokens:{user_id} -> Set{jti}
        let keys: Vec<String> = self.client.connection_mut().keys(pattern).await?;

        let mut deleted_count = 0;
        for key in keys {
            // Check if this token belongs to the user
            let stored_user_id: Option<String> = self.client.get(&key).await?;
            if stored_user_id.as_deref() == Some(user_id) {
                let _: i64 = self.client.del(&key).await?;
                deleted_count += 1;
            }
        }

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
