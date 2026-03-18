// ============================================================================
// Axum Routes Module
// ============================================================================
//
// Only infrastructure endpoints remain here. All core functionality
// (auth, keys, messages, users, invites) is handled exclusively via gRPC.
//
// Endpoints:
// - /health*      — health checks
// - /metrics      — Prometheus metrics
// - /federation/* — server-to-server federation (REST by design)
// - /.well-known/ — server discovery
//
// ============================================================================

pub use construct_extractors as extractors; // re-exported for microservices
pub mod federation;
pub mod health;
mod middleware;

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use construct_server_shared::context::AppContext;

/// Create the main application router.
/// Only infrastructure/monitoring and federation endpoints are served here.
/// All core functionality (auth, keys, messages, users) is gRPC only.
pub fn create_router(app_context: Arc<AppContext>) -> Router {
    Router::new()
        // Health and monitoring
        .route("/health", get(health::health_check))
        .route("/health/ready", get(health::readiness_check))
        .route("/health/live", get(health::liveness_check))
        .route("/metrics", get(health::metrics))
        // Server discovery (federation)
        .route(
            "/.well-known/construct-server",
            get(federation::well_known_construct_server),
        )
        .route(
            "/.well-known/konstruct",
            get(federation::well_known_konstruct),
        )
        .route("/federation/health", get(federation::federation_health))
        .route(
            "/federation/v1/messages",
            post(federation::receive_federated_message),
        )
        .route(
            "/federation/v1/sealed",
            post(federation::receive_federated_sealed),
        )
        .route(
            "/federation/v1/keys/:user_id",
            get(federation::get_federation_keys),
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum::middleware::from_fn(
                    crate::routes::middleware::request_logging,
                ))
                .layer(axum::middleware::from_fn(
                    crate::routes::middleware::add_security_headers,
                ))
                .into_inner(),
        )
        .layer(axum::middleware::from_fn_with_state(
            app_context.clone(),
            crate::routes::middleware::metrics_auth,
        ))
        .with_state(app_context)
}
