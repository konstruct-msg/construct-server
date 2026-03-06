// ============================================================================
// API Gateway Service - Phase 2.6.1
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

mod circuit_breaker;
mod discovery;
mod handlers;
mod middleware;
mod router;
pub mod routes;
mod service_client;

use crate::middleware::{GatewayMiddlewareState, csrf_protection, jwt_verification, rate_limiting};
use crate::router::{GatewayRouter, route_request};
use anyhow::{Context, Result};
use axum::{
    Router, http::StatusCode, middleware as axum_middleware, response::Response, routing::any,
};
use construct_config::Config;
use construct_server_shared::auth::AuthManager;
use construct_server_shared::metrics;
use construct_server_shared::queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== API Gateway Service Starting ===");
    info!("Port: {}", config.port);
    info!("Microservices Enabled: {}", config.microservices.enabled);

    if !config.microservices.enabled {
        warn!("Microservices mode is DISABLED. Gateway will return 503 for all requests.");
        warn!("Set MICROSERVICES_ENABLED=true to enable microservices mode.");
    }

    // Initialize dependencies
    let auth_manager = Arc::new(AuthManager::new(&config)?);
    let queue = Arc::new(Mutex::new(MessageQueue::new(&config).await?));

    // Create gateway state
    let gateway_state =
        GatewayRouter::create_state(config.clone(), auth_manager.clone(), queue.clone());

    // Create middleware state (for middleware layers)
    let middleware_state = Arc::new(GatewayMiddlewareState {
        config: config.clone(),
        auth_manager: auth_manager.clone(),
        queue: queue.clone(),
    });

    // Create router
    let app = Router::new()
        // Health check endpoints (bypass gateway and middleware)
        .route("/health", axum::routing::get(health_check))
        .route("/health/ready", axum::routing::get(health_check))
        .route("/health/live", axum::routing::get(health_check))
        // Metrics endpoint (bypass gateway and middleware)
        .route("/metrics", axum::routing::get(metrics_endpoint))
        // Route all /api/v1/* requests through gateway with middleware
        // Note: wildcard must be named in Axum (/*path instead of /*)
        .route("/api/v1/*path", any(route_request))
        // Apply middleware (order matters - last added runs first)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(axum_middleware::from_fn_with_state(
                    middleware_state.clone(),
                    csrf_protection,
                ))
                .layer(axum_middleware::from_fn_with_state(
                    middleware_state.clone(),
                    rate_limiting,
                ))
                .layer(axum_middleware::from_fn_with_state(
                    middleware_state,
                    jwt_verification,
                ))
                .into_inner(),
        )
        .with_state(gateway_state);

    // Start server
    info!("API Gateway listening on {}", config.bind_address);

    // TODO(construct-ice): Dual-mode transport — accept obfuscated and plain traffic simultaneously.
    //
    // When ready, spawn a second listener on ICE_PORT (default 9443) that wraps each accepted
    // TCP stream with `construct_ice::Obfs4Listener::accept()` before passing it to hyper/Axum.
    // Both listeners share the same `app` (clone it — Router is Arc internally).
    //
    // Rough plan (Variant A — two ports, one router):
    //
    //   1. Add to construct-config:
    //        ice_enabled: bool   (ICE_ENABLED=true)
    //        ice_port: u16       (ICE_PORT=9443, default)
    //        ice_server_key: Option<String>  (ICE_SERVER_KEY=<base64 private key>, generated once)
    //        ice_iat_mode: u8    (ICE_IAT_MODE=0, 0=none/1=enabled/2=paranoid)
    //
    //   2. Deserialize key with `construct_ice::ServerConfig::from_keypair(...)` or generate once
    //      on first launch and persist in secrets (same pattern as APNs key).
    //
    //   3. Spawn task:
    //        let ice_listener = construct_ice::Obfs4Listener::bind(ice_addr, ice_cfg).await?;
    //        let ice_app = app.clone();
    //        tokio::spawn(async move {
    //            loop {
    //                let (stream, _addr) = ice_listener.accept().await?;
    //                let svc = ice_app.clone();
    //                tokio::spawn(async move {
    //                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
    //                        .serve_connection(TokioIo::new(stream), svc)
    //                        .await
    //                });
    //            }
    //        });
    //
    //   4. Log bridge line so ops can distribute it to censored clients:
    //        info!("construct-ice bridge line: {}", ice_cfg.bridge_line());
    //
    // construct-ice library: /Users/maximeliseyev/Code/construct-ice (local crate, not published)
    // Add to gateway/Cargo.toml:
    //   construct-ice = { path = "../../construct-ice", features = ["tonic-transport"] }
    //
    // DPI resistance analysis → session file: CONSTRUCT_ICE_DPI_ANALYSIS.md
    // obfs4 audit findings   → session file: OBFS4_AUDIT_FINDINGS.md

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "ok"
}

/// Metrics endpoint (Prometheus format)
async fn metrics_endpoint() -> Result<Response<String>, StatusCode> {
    match metrics::gather_metrics() {
        Ok(metrics_data) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(metrics_data)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?),
        Err(e) => {
            tracing::error!("Failed to gather metrics: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
