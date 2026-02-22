//! # Construct Redis
//!
//! Redis utilities and operations for Construct secure messaging server.
//!
//! ## Note
//!
//! This is a foundational crate. Full queue functionality remains in `shared`
//! until Phase 4.2 when we'll properly extract and refactor Redis operations.
//!
//! Current scope:
//! - Connection management
//! - Basic Redis operations
//! - Configuration types
//!
//! Future (Phase 4.2):
//! - Full queue operations (delivery, sessions, rate limiting)
//! - Replay protection
//! - Cache operations

use anyhow::Result;
use redis::aio::ConnectionManager;

/// Redis configuration
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub message_ttl_days: i64,
    pub key_prefix: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            message_ttl_days: 7,
            key_prefix: "construct:".to_string(),
        }
    }
}

/// Create a Redis connection manager
///
/// Uses ConnectionManager for automatic reconnection and connection pooling
pub async fn create_connection(redis_url: &str) -> Result<ConnectionManager> {
    let client = redis::Client::open(redis_url)?;
    let manager = ConnectionManager::new(client).await?;
    Ok(manager)
}

/// Calculate TTL in seconds from days
pub fn ttl_from_days(days: i64) -> i64 {
    const SECONDS_PER_DAY: i64 = 86400;
    days * SECONDS_PER_DAY
}

/// Calculate TTL in seconds from hours
pub fn ttl_from_hours(hours: i64) -> i64 {
    const SECONDS_PER_HOUR: i64 = 3600;
    hours * SECONDS_PER_HOUR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_calculations() {
        assert_eq!(ttl_from_days(7), 604800); // 7 days
        assert_eq!(ttl_from_hours(24), 86400); // 24 hours = 1 day
    }

    #[test]
    fn test_default_config() {
        let config = RedisConfig::default();
        assert_eq!(config.message_ttl_days, 7);
        assert_eq!(config.key_prefix, "construct:");
    }
}

