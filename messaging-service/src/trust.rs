// ============================================================================
// TrustLevel — anti-spam account-age gate for messaging
// ============================================================================
//
// New accounts (<7 days) are given tight per-hour and per-day fanout limits.
// Warming accounts (7–30 days) have relaxed limits.
// Trusted accounts (30+ days) are rate-limited only lightly.
//
// An exceeded limit refuses the send with `RATE_LIMIT` and `retry_after_ms`: when the hourly
// window ends, or the UTC day for fanout. (Until todo 249 it answered with a Proof-of-Work
// challenge that no client could solve: SendMessageRequest has no field for a solution.)
//
// Redis keys:
//   trust:{user_id}          — cached account-age in hours (SETEX 3600)
//   rate:msg:{user_id}:hour  — hourly send counter (INCR + EXPIRE 3600); uses Redis hash tag for cluster routing
//   fanout:{user_id}:{day}   — daily unique-recipient HLL (PFADD, EXPIRE 172800); `…:probe` is a
//                             transient copy that asks whether a recipient is new
// ============================================================================

use std::time::{SystemTime, UNIX_EPOCH};

use construct_config::MessagingConfig;
use construct_server_shared::shared::proto::services::v1 as proto;
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

/// A send a limit refused: the client may retry after this many seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(pub u64);

/// Atomically count one send against the hourly limit for `user_id`.
///
/// `Ok(count)` while `count <= limit`; past it, `Err(RetryAfter)` until the window ends. A
/// refused send is not counted, so retries do not stretch the window. Redis errors fail open.
pub async fn check_hourly_rate(
    redis: &mut ConnectionManager,
    user_id: &str,
    limit: u32,
) -> Result<i64, RetryAfter> {
    let key = format!("rate:msg:{{{0}}}:hour", user_id);

    // {1, count} when counted, {0, ttl} when refused. A key left without a TTL would refuse
    // forever, so a refusal also gives it one.
    let (allowed, value): (i64, i64) = redis::Script::new(
        r#"
        local limit = tonumber(ARGV[1])
        local current = tonumber(redis.call('GET', KEYS[1]) or '0')
        if current >= limit then
            local ttl = redis.call('TTL', KEYS[1])
            if ttl < 0 then
                redis.call('EXPIRE', KEYS[1], 3600)
                ttl = 3600
            end
            return {0, ttl}
        end
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
            redis.call('EXPIRE', KEYS[1], 3600)
        end
        return {1, count}
        "#,
    )
    .key(&key)
    .arg(limit)
    .invoke_async(redis)
    .await
    .unwrap_or((1, 0));

    if allowed == 1 {
        Ok(value)
    } else {
        Err(RetryAfter(value.max(1) as u64))
    }
}

// ---------------------------------------------------------------------------
// Daily fanout check (HyperLogLog)
// ---------------------------------------------------------------------------

/// Count `recipient_id` among the sender's unique recipients of the UTC day.
///
/// A recipient already counted today is always allowed, so reaching the cap never cuts the
/// sender off from people it already wrote to. A new recipient past the cap is refused and
/// not counted, so retrying it stays refused. `Ok(count)` or `Err(RetryAfter)` until the
/// next UTC day. Redis errors fail open.
pub async fn check_fanout_rate(
    redis: &mut ConnectionManager,
    user_id: &str,
    recipient_id: &str,
    limit: u32,
) -> Result<u64, RetryAfter> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let key = format!("fanout:{}:{}", user_id, now / 86400);

    // Whether the recipient is new is asked of a copy (PFADD on the real key would count it).
    // {1, count} when allowed, {0, 0} when refused. 2-day TTL so the key cleans itself up.
    let (allowed, count): (i64, i64) = redis::Script::new(
        r#"
        local key, probe = KEYS[1], KEYS[2]
        redis.call('PFMERGE', probe, key)
        local is_new = redis.call('PFADD', probe, ARGV[1])
        redis.call('DEL', probe)
        if is_new == 1 then
            if redis.call('PFCOUNT', key) >= tonumber(ARGV[2]) then
                return {0, 0}
            end
            redis.call('PFADD', key, ARGV[1])
            redis.call('EXPIRE', key, 172800)
        end
        return {1, redis.call('PFCOUNT', key)}
        "#,
    )
    .key(&key)
    .key(format!("{key}:probe"))
    .arg(recipient_id)
    .arg(limit)
    .invoke_async(redis)
    .await
    .unwrap_or((1, 0));

    if allowed == 1 {
        Ok(count as u64)
    } else {
        Err(RetryAfter(secs_until_next_utc_day(now)))
    }
}

/// Seconds from `now` (unix seconds) to the next UTC midnight, when the fanout key rolls over.
fn secs_until_next_utc_day(now: u64) -> u64 {
    86400 - now % 86400
}

// ---------------------------------------------------------------------------
// Both limits, as SendMessage and MessageStream apply them
// ---------------------------------------------------------------------------

/// The hourly limit, then the daily fanout. `Some((limit, retry))` names the limit that
/// refused the send; a send the hourly limit refuses is not counted toward fanout.
pub async fn check_send_limits(
    redis: &mut ConnectionManager,
    trust: TrustLevel,
    config: &MessagingConfig,
    sender_id: &str,
    recipient_id: &str,
) -> Option<(&'static str, RetryAfter)> {
    if let Err(retry) = check_hourly_rate(redis, sender_id, trust.hourly_limit(config)).await {
        return Some(("hourly", retry));
    }
    let fanout_limit = trust.fanout_limit(config)?;
    check_fanout_rate(redis, sender_id, recipient_id, fanout_limit)
        .await
        .err()
        .map(|retry| ("fanout", retry))
}

/// The `RATE_LIMIT` error for a refused send; counts and logs the refusal.
pub fn rate_limited_error(
    message_id: &str,
    sender_id: &str,
    limit: &'static str,
    RetryAfter(secs): RetryAfter,
) -> proto::MessageError {
    construct_metrics::MSG_SEND_RATE_LIMITED_TOTAL
        .with_label_values(&[limit])
        .inc();
    tracing::info!(sender = %sender_id, limit, retry_after_secs = secs, "Send refused by rate limit");
    proto::MessageError {
        message_id: message_id.to_string(),
        error_code: proto::ErrorCode::RateLimit.into(),
        error_message: format!("Rate limit exceeded ({limit}); retry in {secs} s"),
        retryable: true,
        retry_after_ms: Some((secs * 1000) as i64),
    }
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
    fn fanout_retry_after_runs_to_the_next_utc_midnight() {
        assert_eq!(secs_until_next_utc_day(0), 86400);
        assert_eq!(secs_until_next_utc_day(86400 * 20_000 + 1), 86399);
        assert_eq!(secs_until_next_utc_day(86400 * 20_000 + 86399), 1);
    }

    // Redis round trips. They sat behind an `integration_tests` feature that only clippy's
    // --all-features turned on, so they compiled in CI and never ran.
    mod integration {
        use super::*;
        use serial_test::serial;
        use uuid::Uuid;

        async fn redis_conn() -> ConnectionManager {
            let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
            construct_redis::manager_for(client).await.unwrap()
        }

        async fn del_key(redis: &mut ConnectionManager, key: &str) {
            let _: Result<(), _> = redis::cmd("DEL").arg(key).query_async::<()>(redis).await;
        }

        async fn ttl(redis: &mut ConnectionManager, key: &str) -> i64 {
            redis::cmd("TTL").arg(key).query_async(redis).await.unwrap()
        }

        fn fanout_key(user_id: &str) -> String {
            let day = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 86400;
            format!("fanout:{}:{}", user_id, day)
        }

        #[tokio::test]
        #[ignore = "requires Redis"]
        #[serial]
        async fn the_hourly_limit_counts_up_to_the_limit_then_refuses_until_the_window_ends() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:hourly", Uuid::new_v4());
            let key = format!("rate:msg:{{{0}}}:hour", user_id);

            let mut counted = Vec::new();
            for _ in 0..3 {
                counted.push(check_hourly_rate(&mut redis, &user_id, 3).await);
            }
            let refused = check_hourly_rate(&mut redis, &user_id, 3).await;
            let refused_again = check_hourly_rate(&mut redis, &user_id, 3).await;
            let count: i64 = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut redis)
                .await
                .unwrap();
            del_key(&mut redis, &key).await;

            assert_eq!(counted, [Ok(1), Ok(2), Ok(3)]);
            let RetryAfter(secs) = refused.expect_err("the 4th send of 3 is refused");
            assert!(
                (3590..=3600).contains(&secs),
                "retry when the hour ends, got {secs}"
            );
            assert!(refused_again.is_err());
            assert_eq!(count, 3, "a refused send is not counted");
        }

        #[tokio::test]
        #[ignore = "requires Redis"]
        #[serial]
        async fn an_hourly_counter_without_a_ttl_gets_one_instead_of_refusing_forever() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:nottl", Uuid::new_v4());
            let key = format!("rate:msg:{{{0}}}:hour", user_id);
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(10)
                .query_async(&mut redis)
                .await
                .unwrap();

            let result = check_hourly_rate(&mut redis, &user_id, 10).await;
            let left = ttl(&mut redis, &key).await;
            del_key(&mut redis, &key).await;

            assert_eq!(result, Err(RetryAfter(3600)));
            assert!((3590..=3600).contains(&left), "TTL set, got {left}");
        }

        #[tokio::test]
        #[ignore = "requires Redis"]
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

            let r1 = check_fanout_rate(&mut redis, &user_id, "recipient_a", 50).await;
            let r2 = check_fanout_rate(&mut redis, &user_id, "recipient_b", 50).await;
            del_key(&mut redis, &key).await;

            assert!(r1.is_ok());
            assert_eq!(r1.unwrap(), 1);
            assert!(r2.is_ok());
            assert_eq!(r2.unwrap(), 2);
        }

        #[tokio::test]
        #[ignore = "requires Redis"]
        #[serial]
        async fn past_the_fanout_cap_a_new_recipient_is_refused_and_known_ones_stay_reachable() {
            let mut redis = redis_conn().await;
            let user_id = format!("test:trust:{}:fanoutlimit", Uuid::new_v4());
            let key = fanout_key(&user_id);

            let first = check_fanout_rate(&mut redis, &user_id, "rcpt_1", 2).await;
            let second = check_fanout_rate(&mut redis, &user_id, "rcpt_2", 2).await;
            let third = check_fanout_rate(&mut redis, &user_id, "rcpt_3", 2).await;
            let third_again = check_fanout_rate(&mut redis, &user_id, "rcpt_3", 2).await;
            let known = check_fanout_rate(&mut redis, &user_id, "rcpt_1", 2).await;
            del_key(&mut redis, &key).await;

            assert_eq!((first, second), (Ok(1), Ok(2)));
            let RetryAfter(secs) = third.expect_err("a third recipient of 2 is refused");
            assert!((1..=86400).contains(&secs));
            assert!(
                third_again.is_err(),
                "a refused recipient is not counted by being tried"
            );
            assert_eq!(known, Ok(2), "a recipient counted today stays reachable");
        }

        #[tokio::test]
        #[ignore = "requires Redis"]
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

            let r1 = check_fanout_rate(&mut redis, &user_id, "same_recipient", 50).await;
            let r2 = check_fanout_rate(&mut redis, &user_id, "same_recipient", 50).await;
            let r3 = check_fanout_rate(&mut redis, &user_id, "same_recipient", 50).await;
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
