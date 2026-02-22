// ============================================================================
// Service Discovery - Phase 2.6.1
// ============================================================================
//
// Service discovery for microservices architecture.
// Supports multiple discovery modes:
// - Static: Fixed URLs from config
// - DNS: DNS-based service discovery
// - Consul: Consul-based service discovery (future)
//
// ============================================================================

use anyhow::Result;
use construct_config::MicroservicesConfig;
use std::sync::Arc;

/// Service discovery abstraction
pub trait ServiceDiscovery: Send + Sync {
    /// Get service URL for a given service name
    fn get_service_url(&self, service_name: &str) -> Result<String>;
}

/// Static service discovery (from config)
pub struct StaticServiceDiscovery {
    config: Arc<MicroservicesConfig>,
}

impl StaticServiceDiscovery {
    pub fn new(config: Arc<MicroservicesConfig>) -> Self {
        Self { config }
    }
}

impl ServiceDiscovery for StaticServiceDiscovery {
    fn get_service_url(&self, service_name: &str) -> Result<String> {
        match service_name {
            "auth" => Ok(self.config.auth_service_url.clone()),
            "messaging" => Ok(self.config.messaging_service_url.clone()),
            "user" => Ok(self.config.user_service_url.clone()),
            "notification" => Ok(self.config.notification_service_url.clone()),
            _ => anyhow::bail!("Unknown service: {}", service_name),
        }
    }
}

/// Create service discovery based on config
pub fn create_service_discovery(config: Arc<MicroservicesConfig>) -> Box<dyn ServiceDiscovery> {
    match config.discovery_mode.as_str() {
        "static" => Box::new(StaticServiceDiscovery::new(config)),
        "dns" => {
            // TODO: Implement DNS-based discovery
            tracing::warn!("DNS-based discovery not yet implemented, falling back to static");
            Box::new(StaticServiceDiscovery::new(config))
        }
        "consul" => {
            // TODO: Implement Consul-based discovery
            tracing::warn!("Consul-based discovery not yet implemented, falling back to static");
            Box::new(StaticServiceDiscovery::new(config))
        }
        _ => {
            tracing::warn!(
                "Unknown discovery mode: {}, falling back to static",
                config.discovery_mode
            );
            Box::new(StaticServiceDiscovery::new(config))
        }
    }
}
