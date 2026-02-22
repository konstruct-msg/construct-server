/// Rate Limiting Module
///
/// Implements warmup (sandbox) rate limits for new accounts (<48h)
/// and general rate limiting for all users.
///
/// Key features:
/// - Redis-based counters with TTL (fast, ephemeral)
/// - PostgreSQL fallback if Redis unavailable
/// - Account age-based limits (warmup vs established)
/// - No metadata stored in users table (privacy first)
use anyhow::{Context, Result};
use redis::AsyncCommands;
use sqlx::PgPool;
use uuid::Uuid;

use construct_error::AppError;

/// Rate limit action types
#[derive(Debug, Clone, Copy)]
pub enum RateLimitAction {
    /// Create new chat (warmup: 10/day, established: unlimited)
    CreateChat,
    /// Send message to new chat (warmup: 20/hour, established: 1000/hour)
    SendMessageNew,
    /// Send message to existing chat (warmup: 100/hour, established: 1000/hour)
    SendMessageExisting,
    /// Create invite token (warmup: 3/day, established: 100/day)
    CreateInvite,
    /// Add device via QR (warmup: 1/day, established: 10/day)
    AddDeviceQr,
    /// Username search (warmup: 10/hour, established: 1000/hour)
    UsernameSearch,
    /// Upload media (warmup: 20/day, established: unlimited)
    UploadMedia,
}

impl RateLimitAction {
    /// Get action identifier for Redis/DB keys
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateChat => "chat_create",
            Self::SendMessageNew => "msg_new",
            Self::SendMessageExisting => "msg_exist",
            Self::CreateInvite => "invite",
            Self::AddDeviceQr => "add_dev",
            Self::UsernameSearch => "search",
            Self::UploadMedia => "media",
        }
    }

    /// Get warmup limits (max count, window in seconds)
    pub fn warmup_limits(&self) -> (u32, u64) {
        match self {
            Self::CreateChat => (10, 86400),          // 10 per day
            Self::SendMessageNew => (20, 3600),       // 20 per hour
            Self::SendMessageExisting => (100, 3600), // 100 per hour
            Self::CreateInvite => (3, 86400),         // 3 per day
            Self::AddDeviceQr => (1, 86400),          // 1 per day
            Self::UsernameSearch => (10, 3600),       // 10 per hour
            Self::UploadMedia => (20, 86400),         // 20 per day
        }
    }

    /// Get established user limits (max count, window in seconds)
    /// Returns None if unlimited
    pub fn established_limits(&self) -> Option<(u32, u64)> {
        match self {
            Self::CreateChat => None,                        // Unlimited
            Self::SendMessageNew => Some((1000, 3600)),      // 1000 per hour
            Self::SendMessageExisting => Some((1000, 3600)), // 1000 per hour
            Self::CreateInvite => Some((100, 86400)),        // 100 per day
            Self::AddDeviceQr => Some((10, 86400)),          // 10 per day
            Self::UsernameSearch => Some((1000, 3600)),      // 1000 per hour
            Self::UploadMedia => None,                       // Unlimited
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::CreateChat => "create new chat",
            Self::SendMessageNew => "send message to new chat",
            Self::SendMessageExisting => "send message to existing chat",
            Self::CreateInvite => "create invite token",
            Self::AddDeviceQr => "add device via QR",
            Self::UsernameSearch => "search usernames",
            Self::UploadMedia => "upload media",
        }
    }
}

/// Check if user is in warmup period (<48 hours old)
pub async fn is_user_in_warmup(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query_scalar::<_, bool>("SELECT is_user_in_warmup($1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to check warmup status")?;

    Ok(result)
}

/// Get user account age in hours
pub async fn get_user_account_age_hours(pool: &PgPool, user_id: Uuid) -> Result<f64> {
    let age = sqlx::query_scalar::<_, Option<f64>>("SELECT get_user_account_age_hours($1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to get account age")?;

    Ok(age.unwrap_or(0.0))
}

/// Check rate limit using Redis (primary) or PostgreSQL (fallback)
pub async fn check_rate_limit(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    pool: &PgPool,
    user_id: Uuid,
    action: RateLimitAction,
    max_count: u32,
    window_seconds: u64,
) -> Result<(), AppError> {
    // Try Redis first
    match check_rate_limit_redis(redis_conn, user_id, action, max_count, window_seconds).await {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Redis rate limit check failed, falling back to PostgreSQL"
            );
            // Fallback to PostgreSQL
            check_rate_limit_postgres(pool, user_id, action, max_count, window_seconds).await
        }
    }
}

/// Check rate limit using Redis (fast, ephemeral)
async fn check_rate_limit_redis(
    conn: &mut redis::aio::MultiplexedConnection,
    user_id: Uuid,
    action: RateLimitAction,
    max_count: u32,
    window_seconds: u64,
) -> Result<(), AppError> {
    let key = format!("ratelimit:{}:{}", user_id, action.as_str());

    // Increment counter
    let count: u32 = conn
        .incr(&key, 1)
        .await
        .map_err(|e| AppError::Internal(format!("Redis incr failed: {}", e)))?;

    // Set expiry on first increment
    if count == 1 {
        let _: bool = conn
            .expire(&key, window_seconds as i64)
            .await
            .map_err(|e| AppError::Internal(format!("Redis expire failed: {}", e)))?;
    }

    // Check limit
    if count > max_count {
        let ttl: i64 = conn
            .ttl(&key)
            .await
            .map_err(|e| AppError::Internal(format!("Redis TTL failed: {}", e)))?;

        return Err(AppError::TooManyRequests(format!(
            "Rate limit exceeded for '{}'. Limit: {} per {}. Try again in {} seconds.",
            action.description(),
            max_count,
            if window_seconds >= 3600 {
                format!("{} hours", window_seconds / 3600)
            } else {
                format!("{} seconds", window_seconds)
            },
            ttl
        )));
    }

    Ok(())
}

/// Check rate limit using PostgreSQL (fallback, slower)
async fn check_rate_limit_postgres(
    pool: &PgPool,
    user_id: Uuid,
    action: RateLimitAction,
    max_count: u32,
    window_seconds: u64,
) -> Result<(), AppError> {
    // Create rate_limits table if not exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rate_limits (
            user_id UUID NOT NULL,
            action VARCHAR(50) NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            window_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (user_id, action)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create rate_limits table: {}", e)))?;

    // Increment or insert
    let result = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO rate_limits (user_id, action, count, window_start)
        VALUES ($1, $2, 1, NOW())
        ON CONFLICT (user_id, action) DO UPDATE
        SET count = CASE
            WHEN rate_limits.window_start < NOW() - INTERVAL '1 second' * $3 THEN 1
            ELSE rate_limits.count + 1
        END,
        window_start = CASE
            WHEN rate_limits.window_start < NOW() - INTERVAL '1 second' * $3 THEN NOW()
            ELSE rate_limits.window_start
        END
        RETURNING count
        "#,
    )
    .bind(user_id)
    .bind(action.as_str())
    .bind(window_seconds as i32)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to check rate limit: {}", e)))?;

    if result > max_count as i32 {
        return Err(AppError::TooManyRequests(format!(
            "Rate limit exceeded for '{}'. Limit: {} per {}. Try again later.",
            action.description(),
            max_count,
            if window_seconds >= 3600 {
                format!("{} hours", window_seconds / 3600)
            } else {
                format!("{} seconds", window_seconds)
            }
        )));
    }

    Ok(())
}

/// Check warmup limits for a user action
pub async fn check_warmup_limits(
    redis_conn: &mut redis::aio::MultiplexedConnection,
    pool: &PgPool,
    user_id: Uuid,
    action: RateLimitAction,
) -> Result<(), AppError> {
    // Check if user is in warmup period
    let in_warmup = is_user_in_warmup(pool, user_id)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to check warmup: {}", e)))?;

    if in_warmup {
        // Apply warmup limits
        let (max_count, window_seconds) = action.warmup_limits();

        tracing::debug!(
            user_id = %user_id,
            action = ?action,
            max_count = max_count,
            window_seconds = window_seconds,
            "Applying warmup rate limit"
        );

        check_rate_limit(redis_conn, pool, user_id, action, max_count, window_seconds).await?;
    } else {
        // Apply established user limits (if any)
        if let Some((max_count, window_seconds)) = action.established_limits() {
            tracing::debug!(
                user_id = %user_id,
                action = ?action,
                max_count = max_count,
                window_seconds = window_seconds,
                "Applying established user rate limit"
            );

            check_rate_limit(redis_conn, pool, user_id, action, max_count, window_seconds).await?;
        }
        // else: Unlimited for established users
    }

    Ok(())
}

/// Cleanup old PostgreSQL rate limit entries (call periodically)
pub async fn cleanup_rate_limits(pool: &PgPool) -> Result<u64> {
    let result =
        sqlx::query("DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL '1 day'")
            .execute(pool)
            .await
            .context("Failed to cleanup rate limits")?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_action_strings() {
        assert_eq!(RateLimitAction::CreateChat.as_str(), "chat_create");
        assert_eq!(RateLimitAction::SendMessageNew.as_str(), "msg_new");
    }

    #[test]
    fn test_warmup_limits() {
        let (max, window) = RateLimitAction::CreateChat.warmup_limits();
        assert_eq!(max, 10);
        assert_eq!(window, 86400); // 1 day
    }

    #[test]
    fn test_established_limits() {
        assert!(RateLimitAction::CreateChat.established_limits().is_none()); // Unlimited

        let limits = RateLimitAction::SendMessageNew.established_limits();
        assert!(limits.is_some());
        let (max, _) = limits.unwrap();
        assert_eq!(max, 1000);
    }
}
