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
//   rate:msg:{user_id}:hour  — hourly send counter (INCR + EXPIRE 3600)
//   fanout:{user_id}:{day}   — daily unique-recipient HLL (PFADD, EXPIRE 172800)
// ============================================================================

use std::fmt::Write as FmtWrite;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub fn from_age_hours(hours: f64) -> Self {
        if hours < 168.0 {
            // < 7 days
            Self::New
        } else if hours < 720.0 {
            // < 30 days
            Self::Warming
        } else {
            Self::Trusted
        }
    }

    /// Maximum messages per hour for this trust level.
    pub fn hourly_limit(self) -> u32 {
        match self {
            Self::New => 20,
            Self::Warming => 100,
            Self::Trusted => 500,
        }
    }

    /// Maximum unique recipients per day. `None` = unlimited.
    pub fn fanout_limit(self) -> Option<u32> {
        match self {
            Self::New => Some(10),
            Self::Warming => Some(50),
            Self::Trusted => None,
        }
    }

    /// MAXLEN applied to the recipient's offline queue when this sender writes.
    /// New senders get a smaller queue cap to prevent queue-flooding attacks.
    pub fn queue_maxlen(self) -> i64 {
        match self {
            Self::New => 100,
            Self::Warming | Self::Trusted => 10_000,
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
) -> TrustLevel {
    let cache_key = format!("trust:{}", user_id);

    // Try the cache first.
    if let Ok(Some(hours)) = redis::cmd("GET")
        .arg(&cache_key)
        .query_async::<Option<f64>>(redis)
        .await
    {
        return TrustLevel::from_age_hours(hours);
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

    TrustLevel::from_age_hours(age_hours)
}

// ---------------------------------------------------------------------------
// Hourly rate check
// ---------------------------------------------------------------------------

/// Atomically increment the hourly send counter for `user_id`.
///
/// Returns `Ok(current_count)` when under the limit, or `Err(pow_difficulty)`
/// when the limit is exceeded (difficulty scales with overage).
pub async fn check_hourly_rate(
    redis: &mut ConnectionManager,
    user_id: &str,
    limit: u32,
) -> Result<i64, u32> {
    let key = format!("rate:msg:{}:hour", user_id);

    // Atomic INCR + set TTL on first write.
    let count: i64 = redis::Script::new(
        r#"
        local current = redis.call('INCR', KEYS[1])
        if current == 1 then
            redis.call('EXPIRE', KEYS[1], 3600)
        end
        return current
        "#,
    )
    .key(&key)
    .invoke_async(redis)
    .await
    .unwrap_or(0);

    if count <= limit as i64 {
        Ok(count)
    } else {
        let ratio = count as f64 / limit as f64;
        let pow_level = if ratio >= 5.0 {
            8
        } else if ratio >= 3.0 {
            6
        } else {
            4
        };
        Err(pow_level)
    }
}

// ---------------------------------------------------------------------------
// Daily fanout check (HyperLogLog)
// ---------------------------------------------------------------------------

/// Track daily unique recipients via Redis HyperLogLog.
///
/// Returns `Ok(approx_count)` when under the fanout limit, or `Err(4)` when
/// the daily unique-recipient cap is exceeded.
pub async fn check_fanout_rate(
    redis: &mut ConnectionManager,
    user_id: &str,
    recipient_id: &str,
    limit: u32,
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
        Err(4u32)
    }
}

// ---------------------------------------------------------------------------
// PoW challenge helper
// ---------------------------------------------------------------------------

/// Build a random PoW challenge string and expiry timestamp.
///
/// Returns `(challenge_hex, expires_at_unix_millis)`.
pub fn make_challenge(difficulty: u32) -> (String, i64) {
    let bytes: [u8; 16] = rand::random();
    let mut challenge = String::with_capacity(32);
    for b in bytes {
        let _ = write!(challenge, "{:02x}", b);
    }
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
        + 60_000; // 60 seconds from now
    let _ = difficulty; // used by caller in the proto field, not here
    (challenge, expires_at)
}
