// ============================================================================
// Token Management
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization

use anyhow::Result;
use redis::AsyncCommands;

pub(crate) struct TokenManager<'a> {
    client: &'a mut redis::aio::ConnectionManager,
}

impl<'a> TokenManager<'a> {
    pub(crate) fn new(client: &'a mut redis::aio::ConnectionManager) -> Self {
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
        let _: () = self
            .client
            .set_ex(&key, user_id, ttl_seconds as u64)
            .await?;
        // Register in reverse index so revoke_all_user_tokens avoids KEYS scan
        let _: () = redis::cmd("SADD")
            .arg(&index_key)
            .arg(jti)
            .query_async(&mut *self.client)
            .await?;
        let _: () = redis::cmd("EXPIRE")
            .arg(&index_key)
            .arg(ttl_seconds)
            .query_async(&mut *self.client)
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
        let _: () = self.client.del(&key).await?;
        Ok(())
    }

    /// Revoke all refresh tokens for a user (logout from all devices).
    /// Uses the per-user reverse index user_tokens:{user_id} (populated by store_refresh_token)
    /// to avoid a KEYS scan which blocks the Redis event loop.
    pub(crate) async fn revoke_all_user_tokens(&mut self, user_id: &str) -> Result<()> {
        let index_key = format!("user_tokens:{}", user_id);

        let jtis: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&index_key)
            .query_async(&mut *self.client)
            .await
            .unwrap_or_default();

        let mut deleted_count = 0usize;
        for jti in &jtis {
            let token_key = format!("refresh_token:{}", jti);
            let n: i64 = redis::cmd("DEL")
                .arg(&token_key)
                .query_async(&mut *self.client)
                .await
                .unwrap_or(0);
            deleted_count += n as usize;
        }

        let _: () = redis::cmd("DEL")
            .arg(&index_key)
            .query_async(&mut *self.client)
            .await
            .unwrap_or(());

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
}
