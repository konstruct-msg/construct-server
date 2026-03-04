// ============================================================================
// Delivery Worker State
// ============================================================================
//
// Shared state for delivery worker operations.
// Extracted from bin/delivery_worker.rs for better modularity.
//
// ============================================================================

use construct_config::Config;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared state for Kafka-based delivery worker
///
/// This state is shared across all delivery worker operations:
/// - Redis connections
/// - Configuration
/// - Metrics and tracking
pub struct WorkerState {
    pub config: Arc<Config>,
    pub redis_conn: Arc<RwLock<redis::aio::MultiplexedConnection>>,
    pub redis_client: Arc<redis::Client>,
    /// Counter for consecutive "no delivery queues" errors (for periodic summary logging)
    #[allow(dead_code)]
    pub no_queues_count: Arc<RwLock<u64>>,
    /// Phase 4: Shadow-read mode enabled
    /// When true, compares Kafka messages with Redis offline queues for validation
    #[allow(dead_code)]
    pub shadow_read_enabled: bool,
    /// Track message IDs processed from Kafka (for reverse-check in Phase 4.3)
    #[allow(dead_code)]
    pub processed_message_ids: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Users who came online (for logging and monitoring)
    #[allow(dead_code)]
    pub users_online_notifications: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl WorkerState {
    /// Create new WorkerState with Redis connection
    pub fn new(
        config: Arc<Config>,
        redis_client: redis::Client,
        redis_conn: redis::aio::MultiplexedConnection,
    ) -> Self {
        Self {
            config,
            redis_conn: Arc::new(RwLock::new(redis_conn)),
            redis_client: Arc::new(redis_client),
            no_queues_count: Arc::new(RwLock::new(0)),
            shadow_read_enabled: false,
            processed_message_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            users_online_notifications: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Create WorkerState with shadow-read mode enabled
    pub fn with_shadow_read(
        config: Arc<Config>,
        redis_client: redis::Client,
        redis_conn: redis::aio::MultiplexedConnection,
        shadow_read_enabled: bool,
    ) -> Self {
        Self {
            config,
            redis_conn: Arc::new(RwLock::new(redis_conn)),
            redis_client: Arc::new(redis_client),
            no_queues_count: Arc::new(RwLock::new(0)),
            shadow_read_enabled,
            processed_message_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            users_online_notifications: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }
}
