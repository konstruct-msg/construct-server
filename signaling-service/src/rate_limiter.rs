use base64::Engine;
use redis::aio::ConnectionManager;

#[derive(Clone)]
pub(crate) struct RateLimiter {
    redis: ConnectionManager,
    peer_salt: String,
}

impl RateLimiter {
    pub(crate) fn new(redis: ConnectionManager, peer_salt: String) -> Self {
        Self { redis, peer_salt }
    }

    pub(crate) async fn check_call_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.clone();
        let key = format!("ratelimit:calls:{}", user_id);
        let count: i64 = redis::cmd("INCR").arg(&key).query_async(&mut conn).await?;
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(60i64)
                .query_async(&mut conn)
                .await?;
        }
        Ok(count <= 10)
    }

    pub(crate) async fn check_peer_rate(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<bool, anyhow::Error> {
        let peer_bucket = self.peer_bucket(peer_id)?;
        let mut conn = self.redis.clone();
        let key = format!("ratelimit:calls:{}:{}", user_id, peer_bucket);
        let count: i64 = redis::cmd("INCR").arg(&key).query_async(&mut conn).await?;
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(60i64)
                .query_async(&mut conn)
                .await?;
        }
        Ok(count <= 3)
    }

    pub(crate) async fn check_decline_cooldown(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<bool, anyhow::Error> {
        let peer_bucket = self.peer_bucket(peer_id)?;
        let key = format!("ratelimit:decline_cooldown:{}:{}", user_id, peer_bucket);
        let mut conn = self.redis.clone();
        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut conn)
            .await?;
        Ok(!exists)
    }

    pub(crate) async fn set_decline_cooldown(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<(), anyhow::Error> {
        let peer_bucket = self.peer_bucket(peer_id)?;
        let key = format!("ratelimit:decline_cooldown:{}:{}", user_id, peer_bucket);
        let mut conn = self.redis.clone();
        let _: () = redis::cmd("SETEX")
            .arg(key)
            .arg(60i64)
            .arg("1")
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    pub(crate) async fn check_turn_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.clone();
        let key = format!("ratelimit:turn:{}", user_id);
        let count: i64 = redis::cmd("INCR").arg(&key).query_async(&mut conn).await?;
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(30i64)
                .query_async(&mut conn)
                .await?;
        }
        Ok(count <= 1)
    }

    fn peer_bucket(&self, peer_id: &str) -> Result<String, anyhow::Error> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let mut mac = Hmac::<Sha1>::new_from_slice(self.peer_salt.as_bytes())?;
        mac.update(peer_id.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
    }
}
