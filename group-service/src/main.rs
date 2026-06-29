mod cleanup;
mod handlers;
mod helpers;
mod metrics;
mod service;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::shared::proto::services::v1::channel_service_server::ChannelServiceServer;
use construct_server_shared::shared::proto::services::v1::mls_service_server::MlsServiceServer;
use service::GroupServiceImpl;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "group_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = sqlx::PgPool::connect(&database_url).await?;

    sqlx::migrate!("../shared/migrations").run(&db).await?;

    let db = Arc::new(db);

    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let redis_client = redis::Client::open(redis_url)?;
    let redis = redis_client.get_connection_manager().await?;

    // MLS cleanup worker
    let cleanup_interval_hours: u64 = std::env::var("MLS_CLEANUP_INTERVAL_HOURS")
        .unwrap_or_else(|_| "24".to_string())
        .parse()
        .unwrap_or(24);

    let _cleanup_handle = cleanup::start_cleanup_worker((*db).clone(), cleanup_interval_hours);
    info!(
        interval_hours = cleanup_interval_hours,
        "MLS cleanup worker started"
    );

    // Notification client for MLS push
    let notification_client =
        std::env::var("NOTIFICATION_SERVICE_URL")
            .ok()
            .and_then(|url| {
                match NotificationClient::new(&url) {
                    Ok(c) => {
                        info!(%url, "Notification client connected for MLS push notifications");
                        Some(c)
                    }
                    Err(e) => {
                        tracing::warn!(%url, error = %e, "Failed to create notification client; push notifications disabled");
                        None
                    }
                }
            });

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "50058".to_string())
        .parse()?;
    let grpc_bind_addr = format!("0.0.0.0:{}", port);
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_addr).await?;

    info!("GroupService listening on {}", grpc_bind_addr);

    // HTTP server for /health and /metrics
    let http_port: u16 = std::env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8097".into())
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
        info!("GroupService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    let svc = GroupServiceImpl {
        db,
        hub: service::GroupHub::new(),
        notification_client,
        redis,
    };

    Server::builder()
        .add_service(MlsServiceServer::new(svc.clone()))
        .add_service(ChannelServiceServer::new(svc))
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
