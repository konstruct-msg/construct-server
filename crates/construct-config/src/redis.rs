// ============================================================================
// Redis Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Redis key prefixes configuration
#[derive(Clone, Debug)]
pub struct RedisKeyPrefixes {
    /// Prefix for processed message deduplication keys: "processed_msg:{message_id}"
    pub processed_msg: String,
    /// Prefix for user-related keys: "user:{user_id}:..."
    pub user: String,
    /// Prefix for session keys: "session:{jti}"
    pub session: String,
    /// Prefix for user sessions set: "user_sessions:{user_id}"
    pub user_sessions: String,
    /// Prefix for message hash replay protection: "msg_hash:{hash}"
    pub msg_hash: String,
    /// Prefix for rate limiting keys: "rate:{type}:{id}"
    pub rate: String,
    /// Prefix for blocked users: "blocked:{user_id}"
    pub blocked: String,
    /// Prefix for key bundle cache: "key_bundle:{user_id}"
    pub key_bundle: String,
    /// Prefix for connection tracking: "connections:{user_id}"
    pub connections: String,
    /// Prefix for direct delivery deduplication: "delivered_direct:{message_id}"
    /// Used to skip delivery-worker for messages already delivered via tx.send()
    pub delivered_direct: String,
}

impl RedisKeyPrefixes {
    pub(crate) fn from_env() -> Self {
        Self {
            processed_msg: std::env::var("REDIS_KEY_PREFIX_PROCESSED_MSG")
                .unwrap_or_else(|_| "processed_msg:".to_string()),
            user: std::env::var("REDIS_KEY_PREFIX_USER").unwrap_or_else(|_| "user:".to_string()),
            session: std::env::var("REDIS_KEY_PREFIX_SESSION")
                .unwrap_or_else(|_| "session:".to_string()),
            user_sessions: std::env::var("REDIS_KEY_PREFIX_USER_SESSIONS")
                .unwrap_or_else(|_| "user_sessions:".to_string()),
            msg_hash: std::env::var("REDIS_KEY_PREFIX_MSG_HASH")
                .unwrap_or_else(|_| "msg_hash:".to_string()),
            rate: std::env::var("REDIS_KEY_PREFIX_RATE").unwrap_or_else(|_| "rate:".to_string()),
            blocked: std::env::var("REDIS_KEY_PREFIX_BLOCKED")
                .unwrap_or_else(|_| "blocked:".to_string()),
            key_bundle: std::env::var("REDIS_KEY_PREFIX_KEY_BUNDLE")
                .unwrap_or_else(|_| "key_bundle:".to_string()),
            connections: std::env::var("REDIS_KEY_PREFIX_CONNECTIONS")
                .unwrap_or_else(|_| "connections:".to_string()),
            delivered_direct: std::env::var("REDIS_KEY_PREFIX_DELIVERED_DIRECT")
                .unwrap_or_else(|_| "delivered_direct:".to_string()),
        }
    }
}

/// Redis channel names configuration
#[derive(Clone, Debug)]
pub struct RedisChannels {
    /// Dead letter queue channel name
    pub dead_letter_queue: String,
    /// Delivery message channel template: "delivery_message:{server_instance_id}"
    pub delivery_message: String,
    /// Delivery notification channel template: "delivery_notification:{server_instance_id}"
    pub delivery_notification: String,
}

impl RedisChannels {
    pub(crate) fn from_env() -> Self {
        Self {
            dead_letter_queue: std::env::var("REDIS_CHANNEL_DEAD_LETTER_QUEUE")
                .unwrap_or_else(|_| "dead_letter_queue".to_string()),
            delivery_message: std::env::var("REDIS_CHANNEL_DELIVERY_MESSAGE")
                .unwrap_or_else(|_| "delivery_message:".to_string()),
            delivery_notification: std::env::var("REDIS_CHANNEL_DELIVERY_NOTIFICATION")
                .unwrap_or_else(|_| "delivery_notification:".to_string()),
        }
    }
}
