// ============================================================================
// TrustLevel — anti-spam account-age gate for messaging
// ============================================================================
//
// New accounts (<7 days) are given tight per-hour and per-day fanout limits.
// Warming accounts (7–30 days) have relaxed limits.
// Trusted accounts (30+ days) are rate-limited only lightly.
//
// Limits that are exceeded do NOT hard-block the send; instead they issue a
// Proof-of-Work challenge that the client must solve before retrying.  This
// keeps the UX smooth for legitimate users who happen to burst while making
// spam expensive.
//
// Redis keys:
//   trust:{user_id}          — cached account-age in hours (SETEX 3600)
//   rate:msg:{user_id}:hour  — hourly send counter (INCR + EXPIRE 3600); uses Redis hash tag for cluster routing
//   fanout:{user_id}:{day}   — daily unique-recipient HLL (PFADD, EXPIRE 172800)
// ============================================================================

use std::fmt::Write as FmtWrite;
use std::time::{SystemTime, UNIX_EPOCH};

use construct_config::MessagingConfig;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// TrustLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Account age 0–7 days
    New,
    /// Account age 7–30 days
    Warming,
    /// Account age 30+ days
    Trusted,
}

impl TrustLevel {
    pub fn from_age_hours(hours: f64, config: &MessagingConfig) -> Self {
        if hours < config.trust_new_max_age_hours {
            Self::New
        } else if hours < config.trust_warming_max_age_hours {
            Self::Warming
        } else {
            Self::Trusted
        }
    }

    /// Maximum messages per hour for this trust level.
    pub fn hourly_limit(self, config: &MessagingConfig) -> u32 {
        match self {
            Self::New => config.hourly_limit_new,
            Self::Warming => config.hourly_limit_warming,
            Self::Trusted => config.hourly_limit_trusted,
        }
    }

    /// Maximum unique recipients per day. `None` = unlimited.
    pub fn fanout_limit(self, config: &MessagingConfig) -> Option<u32> {
        match self {
            Self::New => Some(config.fanout_limit_new),
            Self::Warming => Some(config.fanout_limit_warming),
            Self::Trusted => None,
        }
    }

    /// MAXLEN applied to the recipient's offline queue when this sender writes.
    /// New senders get a smaller queue cap to prevent queue-flooding attacks.
    pub fn queue_maxlen(self, config: &MessagingConfig) -> i64 {
        match self {
            Self::New => config.queue_maxlen_new,
            Self::Warming | Self::Trusted => config.queue_maxlen_standard,
        }
    }
}

// ---------------------------------------------------------------------------
// TrustLevel resolution (Redis-cached)
// ---------------------------------------------------------------------------

/// Resolve a user's TrustLevel with a 1-hour Redis cache.
///
/// Falls back to `TrustLevel::New` on any error (fail-safe: tighter limits
/// rather than no limits when Redis or DB is unavailable).
pub async fn get_trust_level(
    redis: &mut ConnectionManager,
    pool: &PgPool,
    user_id: Uuid,
    config: &MessagingConfig,
) -> TrustLevel {
    let cache_key = format!("trust:{}", user_id);

    // Try the cache first.
    if let Ok(Some(hours)) = redis::cmd("GET")
        .arg(&cache_key)
        .query_async::<Option<f64>>(redis)
        .await
    {
        return TrustLevel::from_age_hours(hours, config);
    }

    // Cache miss — query the DB.
    let age_hours = construct_server_shared::rate_limit::get_user_account_age_hours(pool, user_id)
        .await
        .unwrap_or(0.0);

    // Populate cache (1h TTL). Failure is non-fatal — next request will re-query.
    let _: Result<(), _> = redis::cmd("SETEX")
        .arg(&cache_key)
        .arg(3600u64)
        .arg(age_hours)
        .query_async::<()>(redis)
        .await;

    TrustLevel::from_age_hours(age_hours, config)
}

// ---------------------------------------------------------------------------
// Hourly rate check
// ---------------------------------------------------------------------------

/// Atomically increment the hourly send counter for `user_id`.
///
/// Returns `Ok(current_count)` when under the limit, or `Err(pow_difficulty)`
/// when the limit is exceeded (difficulty scales with overage).
///
/// Critically, the counter is **not** incremented when the limit is already
/// exceeded — this prevents rate-limited retries from inflating the counter
/// further (which would unfairly escalate the PoW difficulty on each attempt).
pub async fn check_hourly_rate(
    redis: &mut ConnectionManager,
    user_id: &str,
    limit: u32,
    config: &MessagingConfig,
) -> Result<i64, u32> {
    let key = format!("rate:msg:{{{0}}}:hour", user_id);

    // Atomic check-then-increment: only INCR when still under the limit so that
    // rate-limited retries do not inflate the counter (and therefore the PoW ratio).
    // If already at or above the limit, return the current count without touching it.
    let count: i64 = redis::Script::new(
        r#"
        local limit = tonumber(ARGV[1])
        local current = redis.call('GET', KEYS[1])
        if current ~= false and tonumber(current) >= limit then
            return tonumber(current)
        end
        local new_count = redis.call('INCR', KEYS[1])
        if new_count == 1 then
            redis.call('EXPIRE', KEYS[1], 3600)
        end
        return new_count
        "#,
    )
    .key(&key)
    .arg(limit)
    .invoke_async(redis)
    .await
    .unwrap_or(0);

    if count <= limit as i64 {
        Ok(count)
    } else {
        let ratio = count as f64 / limit as f64;
        let pow_level = if ratio >= config.pow_ratio_high {
            config.pow_level_high
        } else if ratio >= config.pow_ratio_mid {
            config.pow_level_mid
        } else {
            config.pow_level_low
        };
        Err(pow_level)
    }
}

// ---------------------------------------------------------------------------
// Daily fanout check (HyperLogLog)
// ---------------------------------------------------------------------------

/// Track daily unique recipients via Redis HyperLogLog.
///
/// Returns `Ok(approx_count)` when under the fanout limit, or `Err(pow_level_low)` when
/// the daily unique-recipient cap is exceeded.
pub async fn check_fanout_rate(
    redis: &mut ConnectionManager,
    user_id: &str,
    recipient_id: &str,
    limit: u32,
    config: &MessagingConfig,
) -> Result<u64, u32> {
    // Key includes calendar day (days since epoch) so it naturally rolls over.
    let day = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400;
    let key = format!("fanout:{}:{}", user_id, day);

    let _added: i64 = redis::cmd("PFADD")
        .arg(&key)
        .arg(recipient_id)
        .query_async::<i64>(redis)
        .await
        .unwrap_or(0);

    // 2-day TTL so the key cleans itself up without a cron job.
    let _: Result<(), _> = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(172_800u64)
        .query_async::<()>(redis)
        .await;

    let count: u64 = redis::cmd("PFCOUNT")
        .arg(&key)
        .query_async::<u64>(redis)
        .await
        .unwrap_or(0);

    if count <= limit as u64 {
        Ok(count)
    } else {
        Err(config.pow_level_low)
    }
}

// ---------------------------------------------------------------------------
// PoW challenge helper
// ---------------------------------------------------------------------------

/// Build a random PoW challenge string and expiry timestamp.
///
/// Returns `(challenge_hex, expires_at_unix_millis)`.
pub fn make_challenge(difficulty: u32, config: &MessagingConfig) -> (String, i64) {
    let bytes: [u8; 16] = rand::random();
    let mut challenge = String::with_capacity(32);
    for b in bytes {
        let _ = write!(challenge, "{:02x}", b);
    }
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
        + (config.challenge_expiry_secs as i64 * 1_000);
    let _ = difficulty; // used by caller in the proto field, not here
    (challenge, expires_at)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MessagingConfig {
        MessagingConfig::default()
    }

    // ── Pure unit tests ───────────────────────────────────────────────────────

    #[test]
    fn test_trust_level_new_under_7_days() {
        assert_eq!(TrustLevel::from_age_hours(100.0, &cfg()), TrustLevel::New);
    }

    #[test]
    fn test_trust_level_warming_7_to_30_days() {
        assert_eq!(
            TrustLevel::from_age_hours(200.0, &cfg()),
            TrustLevel::Warming
        );
    }

    #[test]
    fn test_trust_level_trusted_over_30_days() {
        assert_eq!(
            TrustLevel::from_age_hours(800.0, &cfg()),
            TrustLevel::Trusted
        );
    }

    #[test]
    fn test_trust_level_boundaries() {
        let c = cfg();
        // Just below 168h (7 days) → New
        assert_eq!(TrustLevel::from_age_hours(167.0, &c), TrustLevel::New);
        // At exactly 168h → Warming
        assert_eq!(TrustLevel::from_age_hours(168.0, &c), TrustLevel::Warming);
        // Just below 720h (30 days) → Warming
        assert_eq!(TrustLevel::from_age_hours(719.0, &c), TrustLevel::Warming);
        // At exactly 720h → Trusted
        assert_eq!(TrustLevel::from_age_hours(720.0, &c), TrustLevel::Trusted);
    }

    #[test]
    fn test_hourly_limit_values() {
        let c = cfg();
        assert_eq!(TrustLevel::New.hourly_limit(&c), 20);
        assert_eq!(TrustLevel::Warming.hourly_limit(&c), 100);
        assert_eq!(TrustLevel::Trusted.hourly_limit(&c), 500);
    }

    #[test]
    fn test_fanout_limit_values() {
        let c = cfg();
        assert_eq!(TrustLevel::New.fanout_limit(&c), Some(10));
        assert_eq!(TrustLevel::Warming.fanout_limit(&c), Some(50));
        assert_eq!(TrustLevel::Trusted.fanout_limit(&c), None);
    }

    #[test]
    fn test_queue_maxlen_values() {
        let c = cfg();
        assert_eq!(TrustLevel::New.queue_maxlen(&c), 100);
        assert_eq!(TrustLevel::Warming.queue_maxlen(&c), 10_000);
        assert_eq!(TrustLevel::Trusted.queue_maxlen(&c), 10_000);
    }

    #[test]
    fn test_make_challenge_format() {
        let (challenge, expires_at) = make_challenge(4, &cfg());
        assert_eq!(challenge.len(), 32, "challenge must be 32 hex chars");
        assert!(
            challenge.chars().all(|c| c.is_ascii_hexdigit()),
            "challenge must be lowercase hex"
        );
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let diff_ms = expires_at - now_ms;
        assert!(
            diff_ms > 0 && diff_ms <= 60_000,
            "expiry should be ~60s in the future"
        );
    }

    #[test]
    fn test_make_challenge_unique() {
        let c = cfg();
        let (c1, _) = make_challenge(4, &c);
        let (c2, _) = make_challenge(4, &c);
        assert_ne!(c1, c2, "consecutive challenges must differ");
    }

    #[cfg(feature = "integration_tests")]
    mod integration {
        use super::*;
        use serial_test::serial;
        use uuid::Uuid;

        fn cfg() -> MessagingConfig {
            MessagingConfig::default()
        }

        async fn redis_conn() -> ConnectionManager {
            redis::Client::open("redis://127.0.0.1:6379")
                .unwrap()
                .get_connection_manager()
                .await
                .unwrap()
        }

        async fn del_key(redis: &mut ConnectionManager, key: &str) {
            let _: Result<(), _> = redis::cmd("DEL").arg(key).query_async::<()>(redis).await;
        }

        #[tokio::test]
        #[serial]
        async fn test_check_hourly_rate_allows_under_limit() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:hourly", Uuid::new_v4());
            let key = format!("rate:msg:{{{0}}}:hour", user_id);

            let result = check_hourly_rate(&mut redis, &user_id, 10, &cfg()).await;
            del_key(&mut redis, &key).await;

            assert!(result.is_ok(), "first message should be allowed");
            assert_eq!(result.unwrap(), 1);
        }

        #[tokio::test]
        #[serial]
        async fn test_check_hourly_rate_blocks_at_limit() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:limit", Uuid::new_v4());
            let key = format!("rate:msg:{{{0}}}:hour", user_id);

            // Pre-seed the counter past the limit.
            let _: Result<i64, _> = redis::cmd("SET")
                .arg(&key)
                .arg(10i64)
                .query_async::<i64>(&mut redis)
                .await;

            let result = check_hourly_rate(&mut redis, &user_id, 10, &cfg()).await;
            del_key(&mut redis, &key).await;

            assert!(result.is_err(), "counter at limit+1 should return Err");
            assert_eq!(
                result.unwrap_err(),
                6u32,
                "ratio just over 1× → difficulty 6"
            );
        }

        #[tokio::test]
        #[serial]
        async fn test_check_hourly_rate_pow_scales_with_ratio() {
            let mut redis = redis_conn().await;
            let limit = 10u32;
            let c = cfg();

            // 5× ratio → difficulty 10
            let user_id_5x = format!("test:trust:{}:pow5x", Uuid::new_v4());
            let key_5x = format!("rate:msg:{{{0}}}:hour", user_id_5x);
            let _: Result<i64, _> = redis::cmd("SET")
                .arg(&key_5x)
                .arg((limit as i64 * 5) - 1)
                .query_async::<i64>(&mut redis)
                .await;
            let result_5x = check_hourly_rate(&mut redis, &user_id_5x, limit, &c).await;
            del_key(&mut redis, &key_5x).await;
            assert_eq!(result_5x.unwrap_err(), 10u32, "5× ratio → difficulty 10");

            // 3× ratio → difficulty 8
            let user_id_3x = format!("test:trust:{}:pow3x", Uuid::new_v4());
            let key_3x = format!("rate:msg:{{{0}}}:hour", user_id_3x);
            let _: Result<i64, _> = redis::cmd("SET")
                .arg(&key_3x)
                .arg((limit as i64 * 3) - 1)
                .query_async::<i64>(&mut redis)
                .await;
            let result_3x = check_hourly_rate(&mut redis, &user_id_3x, limit, &c).await;
            del_key(&mut redis, &key_3x).await;
            assert_eq!(result_3x.unwrap_err(), 8u32, "3× ratio → difficulty 8");
        }

        #[tokio::test]
        #[serial]
        async fn test_check_fanout_rate_new_recipients_counted() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:fanout", Uuid::new_v4());
            let day = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 86400;
            let key = format!("fanout:{}:{}", user_id, day);

            let r1 = check_fanout_rate(&mut redis, &user_id, "recipient_a", 50, &cfg()).await;
            let r2 = check_fanout_rate(&mut redis, &user_id, "recipient_b", 50, &cfg()).await;
            del_key(&mut redis, &key).await;

            assert!(r1.is_ok());
            assert_eq!(r1.unwrap(), 1);
            assert!(r2.is_ok());
            assert_eq!(r2.unwrap(), 2);
        }

        #[tokio::test]
        #[serial]
        async fn test_check_fanout_rate_blocks_at_limit() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:fanoutlimit", Uuid::new_v4());
            let day = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 86400;
            let key = format!("fanout:{}:{}", user_id, day);
            let c = cfg();

            // Add 2 unique recipients with limit=2 to fill it.
            let _ = check_fanout_rate(&mut redis, &user_id, "rcpt_1", 2, &c).await;
            let _ = check_fanout_rate(&mut redis, &user_id, "rcpt_2", 2, &c).await;
            // Third unique recipient should exceed limit.
            let result = check_fanout_rate(&mut redis, &user_id, "rcpt_3", 2, &c).await;
            del_key(&mut redis, &key).await;

            assert!(result.is_err(), "exceeding fanout limit should return Err");
            assert_eq!(result.unwrap_err(), 6u32);
        }

        #[tokio::test]
        #[serial]
        async fn test_check_fanout_rate_same_recipient_not_double_counted() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:fanoutdedup", Uuid::new_v4());
            let day = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 86400;
            let key = format!("fanout:{}:{}", user_id, day);

            let r1 = check_fanout_rate(&mut redis, &user_id, "same_recipient", 50, &cfg()).await;
            let r2 = check_fanout_rate(&mut redis, &user_id, "same_recipient", 50, &cfg()).await;
            let r3 = check_fanout_rate(&mut redis, &user_id, "same_recipient", 50, &cfg()).await;
            del_key(&mut redis, &key).await;

            // HLL is approximate, but for a single element it must stay at 1.
            assert!(r1.is_ok());
            assert!(r2.is_ok());
            assert!(r3.is_ok());
            assert_eq!(r1.unwrap(), 1);
            assert_eq!(r2.unwrap(), 1);
            assert_eq!(r3.unwrap(), 1, "same recipient must not be double-counted");
        }
    }
}
