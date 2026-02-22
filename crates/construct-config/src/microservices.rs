// ============================================================================
// Microservices Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Circuit breaker configuration for service resilience
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Failure threshold before opening circuit (default: 5)
    pub failure_threshold: u32,
    /// Success threshold to close circuit (default: 2)
    pub success_threshold: u32,
    /// Timeout in seconds before attempting to close circuit (default: 60)
    pub timeout_secs: u64,
}

impl CircuitBreakerConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            failure_threshold: std::env::var("CIRCUIT_BREAKER_FAILURE_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            success_threshold: std::env::var("CIRCUIT_BREAKER_SUCCESS_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            timeout_secs: std::env::var("CIRCUIT_BREAKER_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),
        }
    }
}

/// Microservices configuration (Phase 2.6)
#[derive(Clone, Debug)]
pub struct MicroservicesConfig {
    /// Whether microservices mode is enabled (default: false)
    /// When false: monolithic mode (all endpoints in one server)
    /// When true: microservices mode (API Gateway routes to separate services)
    pub enabled: bool,
    /// Auth Service URL (e.g., "http://auth-service:8001" or "http://localhost:8001")
    pub auth_service_url: String,
    /// Messaging Service URL (e.g., "http://messaging-service:8002")
    pub messaging_service_url: String,
    /// User Service URL (e.g., "http://user-service:8003")
    pub user_service_url: String,
    /// Notification Service URL (e.g., "http://notification-service:8004")
    pub notification_service_url: String,
    /// Service discovery mode: "dns" | "static" | "consul" (default: "static")
    pub discovery_mode: String,
    /// Timeout for service requests in seconds (default: 30)
    pub service_timeout_secs: u64,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
}

impl MicroservicesConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            enabled: std::env::var("MICROSERVICES_ENABLED")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
            auth_service_url: std::env::var("AUTH_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8001".to_string()),
            messaging_service_url: std::env::var("MESSAGING_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8002".to_string()),
            user_service_url: std::env::var("USER_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8003".to_string()),
            notification_service_url: std::env::var("NOTIFICATION_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8004".to_string()),
            discovery_mode: std::env::var("SERVICE_DISCOVERY_MODE")
                .unwrap_or_else(|_| "static".to_string()),
            service_timeout_secs: std::env::var("SERVICE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(70), // Must be > long polling max (60s)
            circuit_breaker: CircuitBreakerConfig::from_env(),
        }
    }
}
