// lint: some pub fns used only in integration tests
#![allow(dead_code)]
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

/// Shared state for Kafka-based delivery worker
///
/// This state is shared across all delivery worker operations:
/// - Redis connections
/// - Configuration
pub struct WorkerState {
    pub config: Arc<Config>,
    /// ConnectionManager handles reconnects automatically and supports concurrent access.
    pub redis_conn: redis::aio::ConnectionManager,
}

impl WorkerState {
    /// Create new WorkerState with a ConnectionManager
    pub fn new(config: Arc<Config>, redis_conn: redis::aio::ConnectionManager) -> Self {
        Self { config, redis_conn }
    }
}
