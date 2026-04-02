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
// IMPORTANT: The /.well-known/construct-server endpoint MUST return 200 for
// the client DPI detector to work correctly. If it returns 404 (not found),
// clients falsely detect DPI interference and switch to ICE unnecessarily,
// adding 5-8 seconds to every connection attempt.
//
// ============================================================================

mod handlers;
pub mod routes;

use anyhow::{Context, Result};
use axum::{Json, Router, extract::State, http::StatusCode, response::Response};
use construct_config::Config;
use construct_server_shared::metrics;
use serde_json::json;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
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

    // Create router — health + metrics + .well-known (all API routes are gRPC via Envoy)
    // NOTE: .well-known MUST return 200 — clients use it to detect DPI interference.
    // A 404 here causes false-positive DPI detection → unnecessary ICE auto-start → 5-8s delay.
    let app = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/health/ready", axum::routing::get(health_check))
        .route("/health/live", axum::routing::get(health_check))
        .route("/metrics", axum::routing::get(metrics_endpoint))
        .route(
            "/.well-known/construct-server",
            axum::routing::get(well_known_construct_server),
        )
        .route(
            "/.well-known/konstruct",
            axum::routing::get(well_known_construct_server),
        )
        .with_state(config.clone())
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
    //
    // If ICE_TLS_CERT_PATH + ICE_TLS_KEY_PATH are set, obfs4 runs inside TLS
    // (ICE-over-TLS mode): DPI sees standard HTTPS on port 443, inside is obfs4.
    if config.ice_enabled {
        let ice_server_cfg = ice_load_or_generate(&config)?;
        let ice_addr = format!("0.0.0.0:{}", config.ice_port);

        // Try to load TLS config — enables ICE-over-TLS mode
        let tls_acceptor = match (&config.ice_tls_cert_path, &config.ice_tls_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let acceptor = ice_tls_acceptor(cert_path, key_path)
                    .context("Failed to load ICE TLS certificate")?;
                info!(cert = %cert_path, "ICE-over-TLS enabled — obfs4 wrapped in TLS");
                Some(Arc::new(acceptor))
            }
            _ => {
                debug!(
                    "ICE TLS not configured — Traefik handles TLS termination (set ICE_TLS_CERT_PATH + ICE_TLS_KEY_PATH for standalone mode)"
                );
                None
            }
        };

        // Cover proxy config — only active when no gateway-managed TLS (i.e. Traefik terminates
        // TLS before us).  When set, connections that look like TLS ClientHello or HTTP are
        // transparently forwarded to the upstream site; real obfs4 clients are unaffected.
        let cover_cfg: Option<construct_ice::transport::cover::CoverProxyConfig> = if tls_acceptor
            .is_none()
        {
            config.ice_cover_upstream.as_deref().map(|addr| {
                    info!(upstream = %addr, "ICE cover proxy enabled — active probers forwarded to cover site");
                    construct_ice::transport::cover::CoverProxyConfig::new(addr)
                })
        } else {
            if config.ice_cover_upstream.is_some() {
                tracing::warn!(
                    "ICE_COVER_UPSTREAM is set but ICE-over-TLS is also active — \
                        cover proxy disabled (peek happens before gateway TLS, not after)"
                );
            }
            None
        };

        let tcp_listener = tokio::net::TcpListener::bind(&ice_addr)
            .await
            .context("Failed to bind ICE listener")?;
        let ice_listener = Arc::new(construct_ice::Obfs4Listener::from_listener(
            tcp_listener,
            ice_server_cfg,
        ));

        info!(
            port = config.ice_port,
            upstream = %config.ice_upstream,
            tls = tls_acceptor.is_some(),
            cover = config.ice_cover_upstream.as_deref().unwrap_or("disabled"),
            "ICE listener started — obfuscated traffic accepted"
        );
        let upstream = config.ice_upstream.clone();
        tokio::spawn(async move {
            loop {
                // ── Cover proxy path (no gateway TLS) ────────────────────────────────
                // peek() classifies the first bytes as TLS/HTTP → forward to cover site,
                // or as obfs4 noise → proceed with normal handshake below.
                if let Some(ref ccfg) = cover_cfg {
                    match ice_listener.accept_obfs4_or_proxy(ccfg.clone()).await {
                        Ok((
                            construct_ice::transport::cover::MixedAccept::Proxied(handle),
                            peer,
                        )) => {
                            tracing::debug!(peer = %peer, "ICE cover: TLS/HTTP probe forwarded to cover upstream");
                            tokio::spawn(async move {
                                if let Err(e) = handle.await {
                                    tracing::debug!(peer = %peer, error = %e, "ICE cover proxy task error");
                                }
                            });
                            continue;
                        }
                        Ok((
                            construct_ice::transport::cover::MixedAccept::Obfs4(ice_stream),
                            peer,
                        )) => {
                            let upstream = upstream.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    proxy_to_upstream(*ice_stream, &upstream, peer).await
                                {
                                    tracing::debug!(peer = %peer, error = %e, "ICE tunnel closed");
                                }
                            });
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "ICE accept error (cover path)");
                            continue;
                        }
                    }
                }

                // ── Standard path (no cover proxy) ───────────────────────────────────
                match ice_listener.accept_tcp().await {
                    Ok((tcp, peer)) => {
                        let upstream = upstream.clone();
                        let ice_listener = Arc::clone(&ice_listener);
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            // If TLS configured: wrap TCP in TLS first, then obfs4
                            // If no TLS: plain obfs4 over TCP (Traefik terminates TLS upstream)
                            let proxy_result = if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(tcp).await {
                                    Ok(tls_stream) => {
                                        match ice_listener.accept_stream(tls_stream).await {
                                            Ok(ice_stream) => {
                                                proxy_to_upstream(ice_stream, &upstream, peer).await
                                            }
                                            Err(e) => {
                                                tracing::warn!(peer = %peer, error = %e, "ICE-over-TLS: obfs4 handshake failed");
                                                Ok(())
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(peer = %peer, error = %e, "ICE-over-TLS: TLS handshake failed");
                                        Ok(())
                                    }
                                }
                            } else {
                                match ice_listener.accept_stream(tcp).await {
                                    Ok(ice_stream) => {
                                        proxy_to_upstream(ice_stream, &upstream, peer).await
                                    }
                                    Err(e) => {
                                        tracing::warn!(peer = %peer, error = %e, "ICE: obfs4 handshake failed");
                                        Ok(())
                                    }
                                }
                            };
                            if let Err(e) = proxy_result {
                                tracing::debug!(peer = %peer, error = %e, "ICE tunnel closed");
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

/// Build a `TlsAcceptor` from PEM cert + key files.
fn ice_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::ServerConfig as TlsServerConfig;
    use rustls_pemfile::{certs, private_key};
    use std::{fs::File, io::BufReader};

    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open ICE TLS cert: {cert_path}"))?;
    let key_file =
        File::open(key_path).with_context(|| format!("Failed to open ICE TLS key: {key_path}"))?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .context("Failed to parse ICE TLS certificate")?;

    let key = private_key(&mut BufReader::new(key_file))
        .context("Failed to read ICE TLS private key")?
        .context("No private key found in ICE TLS key file")?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS server config")?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}

/// Proxy an obfs4 stream bidirectionally to the upstream (Envoy/gRPC).
async fn proxy_to_upstream<S>(
    ice_stream: construct_ice::Obfs4Stream<S>,
    upstream: &str,
    peer: std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match tokio::net::TcpStream::connect(upstream).await {
        Ok(mut envoy_stream) => {
            tracing::info!(peer = %peer, upstream = %upstream, "ICE connection proxying");
            let mut ice_pinned = Box::pin(ice_stream);
            tokio::io::copy_bidirectional(&mut ice_pinned, &mut envoy_stream).await?;
        }
        Err(e) => tracing::warn!(
            peer = %peer,
            upstream = %upstream,
            error = %e,
            "ICE: failed to connect to upstream"
        ),
    }
    Ok(())
}

/// GET /.well-known/construct-server
/// GET /.well-known/konstruct
///
/// Server discovery endpoint for DPI detection and ICE endpoint configuration.
/// MUST return 200 — the client DPI detector calls this; a 404 causes a false-positive
/// DPI detection, triggering ICE auto-start and adding 5-8 seconds to every connection.
async fn well_known_construct_server(
    State(config): State<Arc<Config>>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 1],
    Json<serde_json::Value>,
) {
    let domain = &config.instance_domain;
    let body = json!({
        "version": "1.0",
        "protocol": "grpc",
        "server": {
            "domain": domain,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "grpc_endpoint": format!("{}:443", domain),
        "signaling_endpoint": format!("{}:443", domain),
        "services": [
            "auth.AuthService",
            "user.UserService",
            "messaging.MessagingService",
            "notification.NotificationService",
            "invite.InviteService",
            "media.MediaService",
            "signaling.SignalingService"
        ],
        "ice": {
            "primary": format!("ice.{}:443", domain),
            "relays": config.ice_relay_addresses,
        },
        "capabilities": {
            "max_message_size_bytes": 100_000,
            "max_file_size_bytes": 100_000_000,
            "supports_streaming": true,
            "supports_grpc_web": true,
        },
    });
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=3600")],
        Json(body),
    )
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
