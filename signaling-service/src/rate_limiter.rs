use base64::Engine;

#[derive(Clone)]
pub(crate) struct RateLimiter {
    redis: redis::Client,
    peer_salt: String,
}

impl RateLimiter {
    pub(crate) fn new(redis: redis::Client, peer_salt: String) -> Self {
        Self { redis, peer_salt }
    }

    pub(crate) async fn check_call_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("ratelimit:calls:{}", user_id);
        let count: i64 = redis::pipe()
            .incr(&key, 1i64)
            .expire(&key, 60)
            .query_async(&mut conn)
            .await?;
        Ok(count <= 10)
    }

    pub(crate) async fn check_peer_rate(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<bool, anyhow::Error> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let mut mac = Hmac::<Sha1>::new_from_slice(self.peer_salt.as_bytes())?;
        mac.update(peer_id.as_bytes());
        let peer_bucket =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        let key = format!("ratelimit:calls:{}:{}", user_id, peer_bucket);
        let count: i64 = redis::pipe()
            .incr(&key, 1i64)
            .expire(&key, 60)
            .query_async(&mut conn)
            .await?;
        Ok(count <= 3)
    }

    pub(crate) async fn check_turn_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("ratelimit:turn:{}", user_id);
        let count: i64 = redis::pipe()
            .incr(&key, 1i64)
            .expire(&key, 30)
            .query_async(&mut conn)
            .await?;
        Ok(count <= 1)
    }
}
