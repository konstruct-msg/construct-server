// ============================================================================
// API Gateway Service
// ============================================================================
//
// This service is the entry point for obfuscated (VEIL/obfs4) traffic and
// provides health + metrics endpoints used by the monitoring stack.
//
// All gRPC traffic is routed through Envoy → tonic services directly.
// This gateway no longer performs REST proxying.
//
// IMPORTANT: The /.well-known/construct-server endpoint MUST return 200 for
// the client DPI detector to work correctly. If it returns 404 (not found),
// clients falsely detect DPI interference and switch to VEIL unnecessarily,
// adding 5-8 seconds to every connection attempt.
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{Json, Router, extract::State, http::StatusCode, response::Response};
use construct_config::Config;
use construct_server_shared::metrics;
use serde_json::json;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Gateway application state: config + optional bundle verification key + token encryption key (for sealed sender)
#[derive(Clone)]
struct GatewayState {
    config: Arc<Config>,
    /// Base64-encoded Ed25519 public key for verifying PreKeyBundle server signatures.
    /// Populated from `BUNDLE_SIGNING_PUBLIC_KEY` env var. Optional — absent in dev.
    bundle_verification_key: Option<String>,
    /// Base64-encoded X25519 public key used by clients to encrypt Privacy Pass tokens
    /// inside SealedInner (so VEIL relays can't read them).
    /// Populated from `TOKEN_ENCRYPTION_PUBLIC_KEY` env var.
    /// Should match the value derived on auth-service from SERVER_SIGNING_KEY via HKDF.
    token_encryption_key: Option<String>,
}

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

    let bundle_verification_key = std::env::var("BUNDLE_SIGNING_PUBLIC_KEY").ok();
    if bundle_verification_key.is_some() {
        info!("Bundle verification key loaded — .well-known will advertise it");
    }

    let token_encryption_key = std::env::var("TOKEN_ENCRYPTION_PUBLIC_KEY").ok();
    if token_encryption_key.is_some() {
        info!(
            "Token encryption public key loaded — .well-known will advertise token_encryption_key for sealed sender / Privacy Pass"
        );
    }

    let state = GatewayState {
        config: config.clone(),
        bundle_verification_key,
        token_encryption_key,
    };

    // Create router — health + metrics + .well-known (all API routes are gRPC via Envoy)
    // NOTE: .well-known MUST return 200 — clients use it to detect DPI interference.
    // A 404 here causes false-positive DPI detection → unnecessary VEIL auto-start → 5-8s delay.
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
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    // Start plain listener
    info!("API Gateway listening on {}", config.bind_address);
    let listener = construct_server_shared::mptcp_or_tcp_listener(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    // Start VEIL (obfs4) listener if enabled — accepts obfuscated traffic on a
    // separate port, strips obfuscation, and TCP-proxies to the gRPC upstream
    // (Envoy by default). This makes VEIL a transparent tunnel: the client's
    // H2/gRPC frames reach the upstream unchanged.
    //
    // If VEIL_TLS_CERT_PATH + VEIL_TLS_KEY_PATH are set, obfs4 runs inside TLS
    // (VEIL-over-TLS mode): DPI sees standard HTTPS on port 443, inside is obfs4.
    if config.veil_enabled {
        let ice_server_cfg = veil_load_or_generate(&config)?;
        let ice_addr = format!("0.0.0.0:{}", config.veil_port);

        // Try to load TLS config — enables VEIL-over-TLS mode
        let tls_acceptor = match (&config.veil_tls_cert_path, &config.veil_tls_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let acceptor = ice_tls_acceptor(cert_path, key_path)
                    .context("Failed to load VEIL TLS certificate")?;
                info!(cert = %cert_path, "VEIL-over-TLS enabled — obfs4 wrapped in TLS");
                Some(Arc::new(acceptor))
            }
            _ => {
                debug!(
                    "VEIL TLS not configured — Traefik handles TLS termination (set ICE_TLS_CERT_PATH + ICE_TLS_KEY_PATH for standalone mode)"
                );
                None
            }
        };

        // Cover proxy config — only active when no gateway-managed TLS (i.e. Traefik terminates
        // TLS before us).  When set, connections that look like TLS ClientHello or HTTP are
        // transparently forwarded to the upstream site; real obfs4 clients are unaffected.
        let cover_cfg: Option<construct_veil::transport::cover::CoverProxyConfig> = if tls_acceptor
            .is_none()
        {
            config.veil_cover_upstream.as_deref().map(|addr| {
                    info!(upstream = %addr, "VEIL cover proxy enabled — active probers forwarded to cover site");
                    construct_veil::transport::cover::CoverProxyConfig::new(addr)
                })
        } else {
            if config.veil_cover_upstream.is_some() {
                tracing::warn!(
                    "ICE_COVER_UPSTREAM is set but VEIL-over-TLS is also active — \
                        cover proxy disabled (peek happens before gateway TLS, not after)"
                );
            }
            None
        };

        let tcp_listener = tokio::net::TcpListener::bind(&ice_addr)
            .await
            .context("Failed to bind VEIL listener")?;
        let ice_listener = Arc::new(construct_veil::Obfs4Listener::from_listener(
            tcp_listener,
            ice_server_cfg,
        ));

        info!(
            port = config.veil_port,
            upstream = %config.veil_upstream,
            tls = tls_acceptor.is_some(),
            cover = config.veil_cover_upstream.as_deref().unwrap_or("disabled"),
            "VEIL listener started — obfuscated traffic accepted"
        );
        let upstream = config.veil_upstream.clone();
        tokio::spawn(async move {
            loop {
                // ── Cover proxy path (no gateway TLS) ────────────────────────────────
                // peek() classifies the first bytes as TLS/HTTP → forward to cover site,
                // or as obfs4 noise → proceed with normal handshake below.
                if let Some(ref ccfg) = cover_cfg {
                    match ice_listener.accept_obfs4_or_proxy(ccfg.clone()).await {
                        Ok((
                            construct_veil::transport::cover::MixedAccept::Proxied(handle),
                            peer,
                        )) => {
                            tracing::debug!(peer = %peer, "VEIL cover: TLS/HTTP probe forwarded to cover upstream");
                            tokio::spawn(async move {
                                if let Err(e) = handle.await {
                                    tracing::debug!(peer = %peer, error = %e, "VEIL cover proxy task error");
                                }
                            });
                            continue;
                        }
                        Ok((
                            construct_veil::transport::cover::MixedAccept::Obfs4(ice_stream),
                            peer,
                        )) => {
                            let upstream = upstream.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    proxy_to_upstream(*ice_stream, &upstream, peer).await
                                {
                                    tracing::debug!(peer = %peer, error = %e, "VEIL tunnel closed");
                                }
                            });
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "VEIL accept error (cover path)");
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
                                                tracing::warn!(peer = %peer, error = %e, "VEIL-over-TLS: obfs4 handshake failed");
                                                Ok(())
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(peer = %peer, error = %e, "VEIL-over-TLS: TLS handshake failed");
                                        Ok(())
                                    }
                                }
                            } else {
                                match ice_listener.accept_stream(tcp).await {
                                    Ok(ice_stream) => {
                                        proxy_to_upstream(ice_stream, &upstream, peer).await
                                    }
                                    Err(e) => {
                                        tracing::warn!(peer = %peer, error = %e, "VEIL: obfs4 handshake failed");
                                        Ok(())
                                    }
                                }
                            };
                            if let Err(e) = proxy_result {
                                tracing::debug!(peer = %peer, error = %e, "ICE tunnel closed");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "VEIL accept error"),
                }
            }
        });
    } else {
        info!("VEIL transport disabled (set ICE_ENABLED=true to activate)");
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
fn veil_load_or_generate(
    config: &construct_config::Config,
) -> anyhow::Result<construct_veil::ServerConfig> {
    use base64::Engine;

    let server_cfg = if let Some(key_b64) = &config.veil_server_key {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .context("VEIL_SERVER_KEY: invalid base64")?;
        let cfg = construct_veil::ServerConfig::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("ICE_SERVER_KEY: {}", e))?;
        let iat = construct_veil::IatMode::from_u8(config.veil_iat_mode).unwrap_or_default();
        cfg.with_iat(iat)
    } else {
        let cfg = construct_veil::ServerConfig::generate();
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(cfg.to_bytes());
        tracing::warn!(
            key = %key_b64,
            "ICE_SERVER_KEY not set — using ephemeral key. \
             Set ICE_SERVER_KEY={} to persist across restarts.",
            key_b64
        );
        let iat = construct_veil::IatMode::from_u8(config.veil_iat_mode).unwrap_or_default();
        cfg.with_iat(iat)
    };

    info!(bridge_line = %server_cfg.bridge_line(), "VEIL server identity loaded");
    Ok(server_cfg)
}

/// Build a `TlsAcceptor` from PEM cert + key files.
fn ice_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::ServerConfig as TlsServerConfig;
    use rustls_pemfile::{certs, private_key};
    use std::{fs::File, io::BufReader};

    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open VEIL TLS cert: {cert_path}"))?;
    let key_file =
        File::open(key_path).with_context(|| format!("Failed to open VEIL TLS key: {key_path}"))?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .context("Failed to parse VEIL TLS certificate")?;

    let key = private_key(&mut BufReader::new(key_file))
        .context("Failed to read VEIL TLS private key")?
        .context("No private key found in VEIL TLS key file")?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS server config")?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}

/// Proxy an obfs4 stream bidirectionally to the upstream (Envoy/gRPC).
async fn proxy_to_upstream<S>(
    ice_stream: construct_veil::Obfs4Stream<S>,
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
            "VEIL: failed to connect to upstream"
        ),
    }
    Ok(())
}

/// GET /.well-known/construct-server
/// GET /.well-known/konstruct
///
/// Server discovery endpoint for DPI detection and VEIL endpoint configuration.
/// MUST return 200 — the client DPI detector calls this; a 404 causes a false-positive
/// DPI detection, triggering VEIL auto-start and adding 5-8 seconds to every connection.
async fn well_known_construct_server(
    State(state): State<GatewayState>,
) -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 1],
    Json<serde_json::Value>,
) {
    let config = &state.config;
    let domain = &config.instance_domain;
    let mut body = json!({
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
        "veil": {
            "primary": format!("ice.{}:443", domain),
            "relays": config.veil_relay_addresses,
        },
        "capabilities": {
            "max_message_size_bytes": 100_000,
            "max_file_size_bytes": 100_000_000,
            "supports_streaming": true,
            "supports_grpc_web": true,
        },
    });
    // Expose bundle verification key when configured so clients can verify server-signed bundles.
    if let Some(vk) = &state.bundle_verification_key {
        body["bundle_verification_key"] = json!(vk);
    }

    // Expose token encryption key (X25519) for clients to seal Privacy Pass tokens in SealedInner.
    // This prevents VEIL relay operators from seeing the tokens.
    if let Some(tk) = &state.token_encryption_key {
        body["token_encryption_key"] = json!(tk);
        // Also publish under server section for compatibility with some client parsers.
        if let Some(server_obj) = body.get_mut("server").and_then(|s| s.as_object_mut()) {
            server_obj.insert("token_encryption_key".to_string(), json!(tk));
        }
    }
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
