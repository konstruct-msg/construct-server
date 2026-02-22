// ============================================================================
// Session Management
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis

use anyhow::Result;
use construct_redis::RedisClient;
use redis::AsyncCommands;

pub(crate) struct SessionManager<'a> {
    client: &'a mut RedisClient,
}

impl<'a> SessionManager<'a> {
    pub(crate) fn new(client: &'a mut RedisClient) -> Self {
        Self { client }
    }

    pub(crate) async fn create_session(
        &mut self,
        jti: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        let session_key = format!("session:{}", jti);
        self.client
            .set_ex(&session_key, user_id, ttl_seconds as u64)
            .await?;
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let _: () = self
            .client
            .connection_mut()
            .sadd(&user_sessions_key, jti)
            .await?;
        let _: () = self
            .client
            .connection_mut()
            .expire(&user_sessions_key, ttl_seconds)
            .await?;
        tracing::info!(user_id = %user_id, session_jti = %jti, "Created session");
        Ok(())
    }

    pub(crate) async fn validate_session(&mut self, jti: &str) -> Result<Option<String>> {
        let session_key = format!("session:{}", jti);
        let user_id: Option<String> = self.client.get(&session_key).await?;
        Ok(user_id)
    }

    pub(crate) async fn revoke_session(&mut self, jti: &str, user_id: &str) -> Result<()> {
        let session_key = format!("session:{}", jti);
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let _: i64 = self.client.del(&session_key).await?;
        let _: () = self
            .client
            .connection_mut()
            .srem(&user_sessions_key, jti)
            .await?;
        tracing::info!(user_id = %user_id, session_jti = %jti, "Revoked session");
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) async fn revoke_all_sessions(&mut self, user_id: &str) -> Result<()> {
        let user_sessions_key = format!("user_sessions:{}", user_id);
        let jtis: Vec<String> = self
            .client
            .connection_mut()
            .smembers(&user_sessions_key)
            .await?;
        for jti in &jtis {
            let session_key = format!("session:{}", jti);
            let _: i64 = self.client.del(&session_key).await?;
        }
        if !jtis.is_empty() {
            let _: i64 = self.client.del(&user_sessions_key).await?;
        }
        tracing::info!(user_id = %user_id, count = jtis.len(), "Revoked all sessions");
        Ok(())
    }
}
