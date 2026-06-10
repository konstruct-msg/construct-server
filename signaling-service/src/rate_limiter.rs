use base64::Engine;
use redis::aio::ConnectionManager;

/// Atomic INCR + EXPIRE Lua script — prevents the race where a crash between the two
/// commands leaves the counter key without a TTL (permanent rate block).
const INCR_EXPIRE_LUA: &str = r#"
    local n = redis.call('INCR', KEYS[1])
    if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    return n
"#;

/// Tunable rate-limit thresholds. Defaults match the historical hardcoded values;
/// each can be overridden via an environment variable (see `from_env`).
#[derive(Clone, Debug)]
pub(crate) struct RateLimitConfig {
    /// Max calls a user may initiate per `call_window_secs`.
    pub call_max: i64,
    pub call_window_secs: i64,
    /// Max calls a user may initiate to the same peer per `peer_window_secs`.
    pub peer_max: i64,
    pub peer_window_secs: i64,
    /// Cooldown after a decline before the same pair can call again.
    pub decline_cooldown_secs: i64,
    /// Max TURN-credential fetches per user per `turn_window_secs`.
    pub turn_max: i64,
    pub turn_window_secs: i64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            call_max: 10,
            call_window_secs: 60,
            peer_max: 3,
            peer_window_secs: 60,
            decline_cooldown_secs: 60,
            turn_max: 10,
            turn_window_secs: 60,
        }
    }
}

impl RateLimitConfig {
    /// Load thresholds from env vars, falling back to the defaults above when unset/invalid.
    pub(crate) fn from_env() -> Self {
        fn env_i64(key: &str, default: i64) -> i64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(default)
        }
        let d = Self::default();
        Self {
            call_max: env_i64("RATE_LIMIT_CALL_MAX", d.call_max),
            call_window_secs: env_i64("RATE_LIMIT_CALL_WINDOW_SECS", d.call_window_secs),
            peer_max: env_i64("RATE_LIMIT_PEER_MAX", d.peer_max),
            peer_window_secs: env_i64("RATE_LIMIT_PEER_WINDOW_SECS", d.peer_window_secs),
            decline_cooldown_secs: env_i64(
                "RATE_LIMIT_DECLINE_COOLDOWN_SECS",
                d.decline_cooldown_secs,
            ),
            turn_max: env_i64("RATE_LIMIT_TURN_MAX", d.turn_max),
            turn_window_secs: env_i64("RATE_LIMIT_TURN_WINDOW_SECS", d.turn_window_secs),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RateLimiter {
    redis: ConnectionManager,
    peer_salt: String,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub(crate) fn new(
        redis: ConnectionManager,
        peer_salt: String,
        config: RateLimitConfig,
    ) -> Self {
        Self {
            redis,
            peer_salt,
            config,
        }
    }

    pub(crate) async fn check_call_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.clone();
        let key = format!("ratelimit:calls:{}", user_id);
        let count: i64 = redis::Script::new(INCR_EXPIRE_LUA)
            .key(&key)
            .arg(self.config.call_window_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(count <= self.config.call_max)
    }

    pub(crate) async fn check_peer_rate(
        &self,
        user_id: &str,
        peer_id: &str,
    ) -> Result<bool, anyhow::Error> {
        let peer_bucket = self.peer_bucket(peer_id)?;
        let mut conn = self.redis.clone();
        let key = format!("ratelimit:calls:{}:{}", user_id, peer_bucket);
        let count: i64 = redis::Script::new(INCR_EXPIRE_LUA)
            .key(&key)
            .arg(self.config.peer_window_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(count <= self.config.peer_max)
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
            .arg(self.config.decline_cooldown_secs)
            .arg("1")
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    pub(crate) async fn check_turn_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        // Defaults to 10/60s (see RateLimitConfig): at most one TURN fetch happens per call,
        // and clients cache user-scoped credentials across calls, so this comfortably covers a
        // legitimate hang-up-and-redial pattern while still bounding credential scraping. The
        // previous 1/30s reaped every back-to-back call into a STUN-only (failed) call.
        // Override via RATE_LIMIT_TURN_MAX / RATE_LIMIT_TURN_WINDOW_SECS.
        let mut conn = self.redis.clone();
        let key = format!("ratelimit:turn:{}", user_id);
        let count: i64 = redis::Script::new(INCR_EXPIRE_LUA)
            .key(&key)
            .arg(self.config.turn_window_secs)
            .invoke_async(&mut conn)
            .await?;
        Ok(count <= self.config.turn_max)
    }

    fn peer_bucket(&self, peer_id: &str) -> Result<String, anyhow::Error> {
        use hmac::{digest::KeyInit, Hmac, Mac};
        use sha1::Sha1;

        let mut mac = Hmac::<Sha1>::new_from_slice(self.peer_salt.as_bytes())?;
        mac.update(peer_id.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
    }
}
