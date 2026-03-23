// ============================================================================
// Database Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Database connection pool configuration
#[derive(Clone, Debug)]
pub struct DbConfig {
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of idle connections kept open (warm-up: avoids cold-start latency)
    pub min_connections: u32,
    /// Timeout for acquiring a connection from the pool (seconds)
    pub acquire_timeout_secs: u64,
    /// Timeout for idle connections before they are closed (seconds)
    pub idle_timeout_secs: u64,
}

impl DbConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            max_connections: std::env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            // Keep 2 connections warm so the first requests after cold start don't
            // pay the TCP + auth handshake overhead to Postgres (~10 ms on Docker).
            min_connections: std::env::var("DB_MIN_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            acquire_timeout_secs: std::env::var("DB_ACQUIRE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            idle_timeout_secs: std::env::var("DB_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
        }
    }
}
