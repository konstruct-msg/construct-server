mod forwarded;
mod rate_limiter;
mod registry;
mod routing;
mod service;
mod time;
mod turn;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::shared::proto::signaling::v1::signaling_service_server::SignalingServiceServer;
use sqlx::postgres::PgPoolOptions;

use crate::rate_limiter::RateLimiter;
use crate::registry::CallRegistry;
use crate::service::{make_default_peer_salt, make_instance_id, SignalingServiceImpl};

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
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    let turn_secret = env::var("TURN_SECRET").unwrap_or_else(|_| "changeme".into());
    let turn_ttl: u64 = env::var("TURN_CREDENTIALS_TTL_SECONDS")
        .unwrap_or_else(|_| "86400".into())
        .parse()?;

    let peer_salt =
        env::var("RATE_LIMIT_PEER_SALT").unwrap_or_else(|_| make_default_peer_salt(&turn_secret));

    let db_pool: Option<Arc<construct_db::DbPool>> = match env::var("DATABASE_URL") {
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
                    info!("DB pool enabled for signaling-service");
                    Some(Arc::new(pool))
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to connect DB — call records and block checks disabled"
                    );
                    None
                }
            }
        }
        _ => None,
    };

    let instance_id = env::var("INSTANCE_ID").unwrap_or_else(|_| make_instance_id());
    let registry = Arc::new(CallRegistry::new(&redis_url, instance_id, db_pool.clone())?);

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

    let contact_hmac_secret = match env::var("CONTACT_HMAC_SECRET") {
        Ok(hex) => match hex::decode(&hex) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            _ => {
                tracing::warn!(
                    "CONTACT_HMAC_SECRET is not valid hex — using insecure default (dev only)"
                );
                b"construct-insecure-contact-hmac".to_vec()
            }
        },
        Err(_) => {
            tracing::warn!(
                "CONTACT_HMAC_SECRET not set — using insecure default (dev only). \
                 Set it in production: openssl rand -hex 32"
            );
            b"construct-insecure-contact-hmac".to_vec()
        }
    };

    info!("SignalingService listening on {}", addr);

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
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        info!("SignalingService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    let service = SignalingServiceImpl {
        registry: Arc::clone(&registry),
        rate_limiter: RateLimiter::new(registry.redis_client(), peer_salt),
        turn_secret,
        turn_ttl,
        notification_client,
        contact_hmac_secret: Arc::new(contact_hmac_secret),
        db_pool,
    };

    Server::builder()
        .add_service(SignalingServiceServer::new(service))
        .serve_with_shutdown(addr, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
