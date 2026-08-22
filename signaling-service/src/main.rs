mod forwarded;
mod rate_limiter;
mod registry;
mod service;
mod time;
mod turn;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_auth::AuthManager;
use construct_config::Config;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::shared::proto::signaling::v1::signaling_service_server::SignalingServiceServer;
use sqlx::postgres::PgPoolOptions;

use crate::rate_limiter::{RateLimitConfig, RateLimiter};
use crate::registry::CallRegistry;
use crate::service::{make_default_peer_salt, make_instance_id, SignalingServiceImpl};

fn load_turn_secret() -> anyhow::Result<String> {
    use construct_config::{
        allow_insecure_secrets, is_production_environment, INSECURE_TURN_SECRET,
    };
    match env::var("TURN_SECRET") {
        Ok(s) if !s.is_empty() && s != INSECURE_TURN_SECRET => Ok(s),
        Ok(s) => {
            if is_production_environment() && !allow_insecure_secrets() {
                anyhow::bail!(
                    "TURN_SECRET must not be empty or '{INSECURE_TURN_SECRET}' in production. \
                     Generate with: openssl rand -hex 32"
                );
            }
            tracing::warn!(
                "TURN_SECRET is empty or '{INSECURE_TURN_SECRET}' — insecure (dev only)"
            );
            Ok(if s.is_empty() {
                INSECURE_TURN_SECRET.to_string()
            } else {
                s
            })
        }
        Err(_) => {
            if is_production_environment() && !allow_insecure_secrets() {
                anyhow::bail!(
                    "TURN_SECRET is REQUIRED in production. Generate with: openssl rand -hex 32"
                );
            }
            tracing::warn!(
                "TURN_SECRET not set — using insecure default '{INSECURE_TURN_SECRET}' (dev only)"
            );
            Ok(INSECURE_TURN_SECRET.to_string())
        }
    }
}

fn load_contact_hmac_secret() -> anyhow::Result<Vec<u8>> {
    use construct_config::{
        allow_insecure_secrets, is_production_environment, INSECURE_CONTACT_HMAC,
    };
    match env::var("CONTACT_HMAC_SECRET") {
        Ok(hex) if !hex.trim().is_empty() => {
            let bytes = hex::decode(hex.trim())
                .map_err(|e| anyhow::anyhow!("CONTACT_HMAC_SECRET is not valid hex: {e}"))?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "CONTACT_HMAC_SECRET must be exactly 32 bytes (got {})",
                    bytes.len()
                );
            }
            if bytes.as_slice() == INSECURE_CONTACT_HMAC && !allow_insecure_secrets() {
                anyhow::bail!(
                    "CONTACT_HMAC_SECRET must not use the known insecure default material"
                );
            }
            Ok(bytes)
        }
        _ => {
            if is_production_environment() && !allow_insecure_secrets() {
                anyhow::bail!(
                    "CONTACT_HMAC_SECRET is REQUIRED in production. \
                     Generate with: openssl rand -hex 32"
                );
            }
            tracing::warn!("CONTACT_HMAC_SECRET not set — using insecure default (dev only)");
            Ok(INSECURE_CONTACT_HMAC.to_vec())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "signaling_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "50060".into())
        .parse()?;
    let grpc_bind_addr = format!("0.0.0.0:{}", port);
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_addr).await?;

    let turn_secret = load_turn_secret()?;
    let turn_ttl: u64 = env::var("TURN_CREDENTIALS_TTL_SECONDS")
        .unwrap_or_else(|_| "86400".into())
        .parse()?;

    let peer_salt =
        env::var("RATE_LIMIT_PEER_SALT").unwrap_or_else(|_| make_default_peer_salt(&turn_secret));

    let instance_id = env::var("INSTANCE_ID").unwrap_or_else(|_| make_instance_id());
    let registry = Arc::new(CallRegistry::new(&redis_url, instance_id).await?);

    tokio::spawn(Arc::clone(&registry).instance_pubsub_loop());
    tokio::spawn(Arc::clone(&registry).cleanup_loop());

    let notification_client = match env::var("NOTIFICATION_GRPC_ENDPOINT") {
        Ok(endpoint) if !endpoint.trim().is_empty() => match NotificationClient::new(&endpoint) {
            Ok(client) => {
                info!(
                    endpoint = %endpoint,
                    "NotificationService client configured (lazy connect)"
                );
                Some(client)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    endpoint = %endpoint,
                    "Invalid NOTIFICATION_GRPC_ENDPOINT — VoIP wake disabled"
                );
                None
            }
        },
        _ => {
            tracing::debug!("NOTIFICATION_GRPC_ENDPOINT not set — VoIP wake disabled");
            None
        }
    };

    let contact_hmac_secret = load_contact_hmac_secret()?;

    info!("SignalingService listening on {}", grpc_bind_addr);

    // Load JWT auth manager for device_id cross-verification.
    // Auth is required for user/device identity (Bearer); Config keys must be present
    // in production. Degraded None only when Config fails in non-prod.
    let auth: Option<Arc<AuthManager>> = match Config::from_env() {
        Ok(config) => match AuthManager::new(&config) {
            Ok(manager) => {
                info!("JWT/PASETO device verification enabled");
                Some(Arc::new(manager))
            }
            Err(e) => {
                if construct_config::is_production_environment() {
                    return Err(e.context(
                        "AuthManager init failed in production (set PASETO/JWT public keys)",
                    ));
                }
                tracing::warn!(
                    error = %e,
                    "AuthManager init failed — auth disabled (dev only; set PASETO/JWT keys)"
                );
                None
            }
        },
        Err(e) => {
            if construct_config::is_production_environment() {
                return Err(e.context("Config load failed in production"));
            }
            tracing::warn!(
                error = %e,
                "Config load failed — auth disabled (dev only)"
            );
            None
        }
    };

    let http_port: u16 = env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8091".into())
        .parse()?;
    let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port).parse()?;
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route(
                "/metrics",
                axum::routing::get(construct_server_shared::metrics::metrics_handler),
            );
        let listener = construct_server_shared::mptcp_or_tcp_listener(&http_addr.to_string())
            .await
            .unwrap();
        info!("SignalingService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    let service = SignalingServiceImpl {
        registry: Arc::clone(&registry),
        rate_limiter: RateLimiter::new(
            registry.redis_client(),
            peer_salt,
            RateLimitConfig::from_env(),
        ),
        turn_secret,
        turn_ttl,
        notification_client,
        contact_hmac_secret: Arc::new(contact_hmac_secret),
        auth,
        db_pool: match env::var("DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => {
                match PgPoolOptions::new()
                    .max_connections(
                        env::var("DB_MAX_CONNECTIONS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(20),
                    )
                    .min_connections(0)
                    .connect(&url)
                    .await
                {
                    Ok(pool) => {
                        info!("DB pool enabled for signaling-service (user_blocks checks)");
                        Some(Arc::new(pool))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to connect DB - calls_allowed checks limited to Redis-only"
                        );
                        None
                    }
                }
            }
            _ => {
                tracing::error!(
                    "DATABASE_URL not set or empty — signaling-service cannot check mutual \
                     contacts. ALL calls will be denied with permissionDenied. \
                     Ensure DATABASE_URL is present in app.env and not overridden to empty."
                );
                None
            }
        },
    };

    Server::builder()
        .add_service(SignalingServiceServer::new(service))
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
