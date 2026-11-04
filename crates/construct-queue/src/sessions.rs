//! Cleanup of residual legacy session keys on device deactivation. Live auth
//! uses PASETO/refresh tokens; there is no session creation or validation path here.

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
