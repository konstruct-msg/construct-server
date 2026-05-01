// ============================================================================
// Channel Service - Public/Private Broadcast Channels
// ============================================================================
//
// Port: 50061
// ============================================================================

mod handlers;
mod helpers;
mod metrics;
mod service;

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::shared::proto::services::v1::channel_service_server::ChannelServiceServer;
use service::ChannelServiceImpl;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "channel_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = sqlx::PgPool::connect(&database_url).await?;

    // Run pending migrations on startup
    sqlx::migrate!("../shared/migrations").run(&db).await?;

    let db = Arc::new(db);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "50061".to_string())
        .parse()?;
    let grpc_bind_addr = format!("0.0.0.0:{}", port);
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_addr).await?;

    info!("ChannelService listening on {}", grpc_bind_addr);

    // Small HTTP server for /health and /metrics
    let http_port: u16 = std::env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8098".into())
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
        info!("ChannelService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    Server::builder()
        .add_service(ChannelServiceServer::new(ChannelServiceImpl { db }))
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
