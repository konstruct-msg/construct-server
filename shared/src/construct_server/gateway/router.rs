// ============================================================================
// Gateway Router - Phase 2.6.1
// ============================================================================
//
// Routes requests to appropriate microservices based on path.
// When microservices are disabled, routes to local handlers (monolithic mode).
//
// Routing rules:
// - /api/v1/auth/* → auth-service
// - /api/v1/messages → messaging-service
// - /api/v1/media/* → messaging-service
// - /api/v1/users/* → user-service
// - /api/v1/account → user-service
// - /api/v1/keys/* → user-service
// - /api/v1/notifications/* → notification-service
// - /* → local handlers (monolithic mode or not yet migrated)
//
// ============================================================================

use crate::auth::AuthManager;
use crate::gateway::discovery::ServiceDiscovery;
use crate::gateway::service_client::ServiceClient;
use crate::queue::MessageQueue;
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::Response,
};
use construct_config::Config;
use std::sync::Arc;

/// Gateway router state
pub struct GatewayState {
    pub config: Arc<Config>,
    pub service_discovery: Box<dyn ServiceDiscovery>,
    pub service_client: ServiceClient,
    pub auth_manager: Arc<AuthManager>,
    pub queue: Arc<tokio::sync::Mutex<MessageQueue>>,
}

/// Route request to appropriate service
pub async fn route_request(
    State(state): State<Arc<GatewayState>>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let path = request.uri().path();

    // If microservices are disabled, return error (should use monolithic server)
    if !state.config.microservices.enabled {
        // In monolithic mode, this gateway should not be used
        // Return 503 to indicate service unavailable
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Determine target service based on path
    let service_name = match path {
        path if path.starts_with("/api/v1/auth") => "auth",
        path if path.starts_with("/api/v1/messages") => "messaging",
        path if path.starts_with("/api/v1/media") => "messaging",
        path if path.starts_with("/api/v1/users") => "user",
        path if path.starts_with("/api/v1/account") => "user",
        path if path.starts_with("/api/v1/keys") => "user",
        path if path.starts_with("/api/v1/notifications") => "notification",
        _ => {
            // Unknown path - return 404
            return Err(StatusCode::NOT_FOUND);
        }
    };

    // Get service URL
    let service_url = match state.service_discovery.get_service_url(service_name) {
        Ok(url) => url,
        Err(e) => {
            tracing::error!(error = %e, service = service_name, "Failed to get service URL");
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    // Forward request to service
    match state
        .service_client
        .forward_request(&service_url, service_name, request)
        .await
    {
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::error!(
                error = %e,
                service = service_name,
                service_url = %service_url,
                "Failed to forward request to service"
            );
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

/// Gateway router builder
pub struct GatewayRouter;

impl GatewayRouter {
    /// Create gateway state
    pub fn create_state(
        config: Arc<Config>,
        auth_manager: Arc<AuthManager>,
        queue: Arc<tokio::sync::Mutex<MessageQueue>>,
    ) -> Arc<GatewayState> {
        use crate::gateway::discovery::create_service_discovery;

        let service_discovery = create_service_discovery(Arc::new(config.microservices.clone()));
        let service_client = ServiceClient::new_with_circuit_breaker(
            config.microservices.service_timeout_secs,
            Arc::new(config.microservices.circuit_breaker.clone()),
        );

        Arc::new(GatewayState {
            config,
            service_discovery,
            service_client,
            auth_manager,
            queue,
        })
    }
}
