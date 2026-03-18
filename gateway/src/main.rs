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

    // Start plain listener
    info!("API Gateway listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    // Start ICE (obfs4) listener if enabled — accepts obfuscated traffic on a
    // separate port and routes it through the same Axum router.
    if config.ice_enabled {
        let ice_server_cfg = ice_load_or_generate(&config)?;
        let ice_addr = format!("0.0.0.0:{}", config.ice_port);
        let ice_listener = construct_ice::Obfs4Listener::bind(&ice_addr, ice_server_cfg)
            .await
            .context("Failed to bind ICE listener")?;
        info!(
            port = config.ice_port,
            "ICE listener started — obfuscated traffic accepted"
        );
        let ice_app = app.clone();
        tokio::spawn(async move {
            loop {
                match ice_listener.accept().await {
                    Ok((stream, peer)) => {
                        tracing::debug!(peer = %peer, "ICE connection accepted");
                        let svc = ice_app.clone();
                        tokio::spawn(async move {
                            use hyper_util::rt::{TokioExecutor, TokioIo};
                            let io = TokioIo::new(stream);
                            // Bridge Request<Incoming> → Request<axum::body::Body>
                            let svc = hyper::service::service_fn(
                                move |req: hyper::Request<hyper::body::Incoming>| {
                                    let mut router = svc.clone();
                                    async move {
                                        use tower::Service;
                                        let req = req.map(axum::body::Body::new);
                                        router.call(req).await
                                    }
                                },
                            );
                            if let Err(e) =
                                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                    .serve_connection(io, svc)
                                    .await
                            {
                                tracing::debug!(error = %e, "ICE connection closed");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "ICE accept error"),
                }
            }
        });
    } else {
        info!("ICE transport disabled (set ICE_ENABLED=true to activate)");
    }

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}

/// Load `ServerConfig` from `ICE_SERVER_KEY` env var, or generate an ephemeral one.
///
/// If the key is ephemeral (not persisted), clients need a new bridge cert after
/// every gateway restart.  For production: generate once and set `ICE_SERVER_KEY`.
fn ice_load_or_generate(
    config: &construct_config::Config,
) -> anyhow::Result<construct_ice::ServerConfig> {
    use base64::Engine;

    let server_cfg = if let Some(key_b64) = &config.ice_server_key {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .context("ICE_SERVER_KEY: invalid base64")?;
        let cfg = construct_ice::ServerConfig::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("ICE_SERVER_KEY: {}", e))?;
        let iat = construct_ice::IatMode::from_u8(config.ice_iat_mode).unwrap_or_default();
        cfg.with_iat(iat)
    } else {
        let cfg = construct_ice::ServerConfig::generate();
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(cfg.to_bytes());
        tracing::warn!(
            key = %key_b64,
            "ICE_SERVER_KEY not set — using ephemeral key. \
             Set ICE_SERVER_KEY={} to persist across restarts.",
            key_b64
        );
        let iat = construct_ice::IatMode::from_u8(config.ice_iat_mode).unwrap_or_default();
        cfg.with_iat(iat)
    };

    info!(bridge_line = %server_cfg.bridge_line(), "ICE server identity loaded");
    Ok(server_cfg)
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
