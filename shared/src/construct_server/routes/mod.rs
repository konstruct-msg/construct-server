// ============================================================================
// Axum Routes Module
// ============================================================================
//
// This module contains all HTTP routes migrated from the manual HTTP handler
// to Axum framework for better type safety, middleware support, and maintainability.
//
// Structure:
// - mod.rs: Main router assembly and middleware
// - health.rs: Health check and metrics endpoints
// - keys.rs: Key management endpoints
// - messages.rs: Message sending endpoints
// - federation.rs: Federation endpoints
// - csrf.rs: CSRF token generation and validation
// - extractors.rs: Custom Axum extractors (JWT, AppContext, etc.)
// - middleware.rs: Request logging, CSRF protection, security headers
//
// ============================================================================

pub mod account; // Made public for user-service
pub mod account_deletion; // Device-signed account deletion (Phase 5.0.1)
mod capabilities; // Phase 5: Crypto-agility capabilities endpoint
pub mod csrf; // Made public for gateway middleware
pub mod devices; // Device-based passwordless authentication
pub mod extractors; // Made public for auth-service, user-service, messaging-service, and notification-service
pub mod federation; // Made public for service discovery
pub mod health; // Made public for tests
pub mod invites; // Phase 5: Dynamic invite tokens (one-time QR codes) - Made public for user-service
pub mod keys; // Made public for user-service
pub mod media; // Made public for messaging-service
pub mod messages; // Made public for messaging-service
mod middleware;
pub mod notifications; // Made public for notification-service
pub mod request_signing; // Made public for user-service (account deletion uses request signing)

use axum::{
    Router,
    routing::{get, patch, post, put},
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::context::AppContext;

/// Create the main application router with all routes
pub fn create_router(app_context: Arc<AppContext>) -> Router {
    Router::new()
        // Health and monitoring (no CSRF needed)
        .route("/health", get(health::health_check))
        .route("/health/ready", get(health::readiness_check))
        .route("/health/live", get(health::liveness_check))
        .route("/metrics", get(health::metrics))
        // CSRF token endpoint (GET - no CSRF needed)
        .route("/api/csrf-token", get(csrf::get_csrf_token))
        // NOTE: Device-based auth and token management live in auth-service
        // Account management (CSRF protected, authenticated)
        .route("/api/v1/account", get(account::get_account))
        .route("/api/v1/account", put(account::update_account))
        // Device-signed account deletion (Phase 5.0.1) - replaces legacy DELETE /api/v1/account
        .route(
            "/api/v1/users/me/delete-challenge",
            get(account_deletion::get_delete_challenge),
        )
        .route(
            "/api/v1/users/me/delete-confirm",
            post(account_deletion::confirm_delete),
        )
        // Keys management (CSRF protected)
        .route("/api/v1/keys/upload", post(keys::upload_keys))
        .route(
            "/api/v1/users/:id/public-key",
            get(keys::get_public_key_bundle),
        )
        // PATCH endpoint for updating verifying key (per INVITE_LINKS_QR_API_SPEC.md)
        .route(
            "/api/v1/users/me/public-key",
            patch(keys::update_verifying_key),
        )
        // Username availability check (public, rate-limited)
        .route(
            "/api/v1/users/username/availability",
            get(account::check_username_availability),
        )
        // Phase 5: Crypto-agility capabilities
        .route(
            "/api/v1/users/:id/capabilities",
            get(capabilities::get_user_capabilities),
        )
        // Phase 5: Dynamic invites (one-time contact sharing)
        .route("/api/v1/invites/generate", post(invites::generate_invite))
        .route("/api/v1/invites/accept", post(invites::accept_invite))
        // Messages (CSRF protected)
        .route("/api/v1/messages/confirm", post(messages::confirm_message)) // Week R2: 2-phase commit
        .route("/api/v1/control", post(messages::send_control_message)) // Phase 4.5: END_SESSION
        // Federation (no CSRF - uses server signatures)
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
            "/federation/v1/keys/:user_id",
            get(federation::get_federation_keys),
        )
        // Apply middleware (order matters - last added runs first)
        .layer(
            ServiceBuilder::new()
                // Tracing layer (outermost - runs first)
                .layer(TraceLayer::new_for_http())
                // Request logging
                .layer(axum::middleware::from_fn(
                    crate::routes::middleware::request_logging,
                ))
                // Security headers
                .layer(axum::middleware::from_fn(
                    crate::routes::middleware::add_security_headers,
                ))
                .into_inner(),
        )
        // Metrics authentication (needs state, applied before CSRF)
        .layer(axum::middleware::from_fn_with_state(
            app_context.clone(),
            crate::routes::middleware::metrics_auth,
        ))
        // CSRF protection middleware (needs state, applied separately)
        .layer(axum::middleware::from_fn_with_state(
            app_context.clone(),
            crate::routes::middleware::csrf_protection,
        ))
        .with_state(app_context)
}
