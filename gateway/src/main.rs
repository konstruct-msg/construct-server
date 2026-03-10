// ============================================================================
// API Gateway Service
// ============================================================================
//
// This service is the entry point for obfuscated (ICE/obfs4) traffic and
// provides health + metrics endpoints used by the monitoring stack.
//
// All gRPC traffic is routed through Envoy → tonic services directly.
// This gateway no longer performs REST proxying.
//
// ============================================================================

mod handlers;
pub mod routes;

use anyhow::{Context, Result};
use axum::{Router, http::StatusCode, response::Response};
use construct_config::Config;
use construct_server_shared::metrics;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;
    let config = Arc::new(config);

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== API Gateway Service Starting ===");
    info!("Port: {}", config.port);

    // Create router — health + metrics only (all API routes are gRPC via Envoy)
    let app = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/health/ready", axum::routing::get(health_check))
        .route("/health/live", axum::routing::get(health_check))
        .route("/metrics", axum::routing::get(metrics_endpoint))
        .layer(TraceLayer::new_for_http());

    // Start plain listener
    info!("API Gateway listening on {}", config.bind_address);
    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    // Start ICE (obfs4) listener if enabled — accepts obfuscated traffic on a
    // separate port, strips obfuscation, and TCP-proxies to the gRPC upstream
    // (Envoy by default). This makes ICE a transparent tunnel: the client's
    // H2/gRPC frames reach the upstream unchanged.
    if config.ice_enabled {
        let ice_server_cfg = ice_load_or_generate(&config)?;
        let ice_addr = format!("0.0.0.0:{}", config.ice_port);
        let ice_listener = construct_ice::Obfs4Listener::bind(&ice_addr, ice_server_cfg)
            .await
            .context("Failed to bind ICE listener")?;
        info!(
            port = config.ice_port,
            upstream = %config.ice_upstream,
            "ICE listener started — obfuscated traffic accepted"
        );
        let upstream = config.ice_upstream.clone();
        tokio::spawn(async move {
            loop {
                match ice_listener.accept().await {
                    Ok((ice_stream, peer)) => {
                        let upstream = upstream.clone();
                        tokio::spawn(async move {
                            match tokio::net::TcpStream::connect(&upstream).await {
                                Ok(mut envoy_stream) => {
                                    tracing::info!(peer = %peer, upstream = %upstream, "ICE connection proxying");
                                    // Pin the obfs4 stream so copy_bidirectional can use it
                                    let mut ice_pinned = Box::pin(ice_stream);
                                    if let Err(e) = tokio::io::copy_bidirectional(
                                        &mut ice_pinned,
                                        &mut envoy_stream,
                                    )
                                    .await
                                    {
                                        tracing::debug!(peer = %peer, error = %e, "ICE tunnel closed");
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    peer = %peer,
                                    upstream = %upstream,
                                    error = %e,
                                    "ICE: failed to connect to upstream"
                                ),
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
        cfg
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
