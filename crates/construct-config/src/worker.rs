// ============================================================================
// Worker Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Delivery worker specific configuration
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Enable shadow-read mode (compare Kafka vs Redis for validation)
    pub shadow_read_enabled: bool,
}

impl WorkerConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            shadow_read_enabled: std::env::var("SHADOW_READ_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        }
    }
}
