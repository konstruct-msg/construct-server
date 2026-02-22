// ============================================================================
// API Gateway - Phase 2.6.1
// ============================================================================
//
// API Gateway acts as a single entry point for all client requests.
// It handles:
// - JWT authentication verification
// - Rate limiting (IP-based, user-based)
// - CSRF protection
// - Request routing to appropriate microservices
// - Load balancing between service instances
//
// Architecture:
// - Stateless (can scale horizontally)
// - Routes requests to microservices based on path
// - Falls back to monolithic mode if microservices are disabled
//
// ============================================================================

pub mod circuit_breaker;
pub mod discovery;
pub mod middleware;
pub mod router;
pub mod service_client;

pub use discovery::ServiceDiscovery;
pub use middleware::GatewayMiddlewareState;
pub use router::{GatewayRouter, GatewayState};
pub use service_client::ServiceClient;
