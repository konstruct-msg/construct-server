mod handler;

use std::env;
use std::net::SocketAddr;

use axum::{Router, routing::get};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::handler::{Config, masque_ws_handler};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "masque_service=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listen_addr: SocketAddr = env::var("MASQUE_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9200".into())
        .parse()?;

    let target_host = env::var("MASQUE_TARGET_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let target_port: u16 = env::var("MASQUE_TARGET_PORT")
        .unwrap_or_else(|_| "443".into())
        .parse()?;

    let auth_token = env::var("MASQUE_AUTH_TOKEN").unwrap_or_default();
    if auth_token.is_empty() {
        tracing::warn!(
            "MASQUE_AUTH_TOKEN not set — relay open to any client. \
             Set in production: MASQUE_AUTH_TOKEN=$(openssl rand -hex 32)"
        );
    }

    let config = Config {
        target: format!("{target_host}:{target_port}"),
        auth_token,
    };

    let app = Router::new()
        .route("/masque", get(masque_ws_handler))
        .route("/health", get(|| async { "ok" }))
        .with_state(config);

    info!(%listen_addr, target = %format!("{target_host}:{target_port}"), "masque-service starting");

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
