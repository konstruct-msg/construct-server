// ============================================================================
// Redis Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Redis key prefixes configuration
#[derive(Clone, Debug)]
pub struct RedisKeyPrefixes {
    /// Prefix for user-related keys: "user:{user_id}:..."
    pub user: String,
}

impl RedisKeyPrefixes {
    pub(crate) fn from_env() -> Self {
        Self {
            user: std::env::var("REDIS_KEY_PREFIX_USER").unwrap_or_else(|_| "user:".to_string()),
        }
    }
}
