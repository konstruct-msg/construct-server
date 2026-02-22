// ============================================================================
// Construct Media Service - Privacy-Focused Media Storage
// ============================================================================
//
// SECURITY DESIGN:
// ================
// 1. NO IP LOGGING - We don't log IP addresses
// 2. NO USER TRACKING - Upload tokens are one-time, no user_id stored
// 3. ENCRYPTED BLOBS ONLY - We store only E2E encrypted data
// 4. AUTO-DELETE - Files are deleted after TTL (default 7 days)
// 5. MINIMAL METADATA - Only media_id → blob, nothing else
//
// Architecture:
// =============
// - construct-server issues one-time upload tokens
// - Client uploads encrypted blob with token
// - Client downloads via public URL (no auth - content is E2E encrypted)
// - Periodic cleanup deletes expired files
//
// Endpoints:
// ==========
// POST /upload              - Upload encrypted media (requires token)
// GET  /{media_id}          - Download encrypted media (public)
// GET  /health              - Health check
// DELETE /{media_id}        - Delete media (internal, requires admin token)
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{delete, get, post},
};
use media_service::{
    cleanup,
    config::MediaConfig,
    handlers::{self, AppState},
};
use std::sync::Arc;
use tokio::spawn;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "media_service=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Arc::new(MediaConfig::from_env());

    info!(
        bind_address = %config.bind_address,
        storage_dir = %config.storage_dir.display(),
        max_file_size = config.max_file_size,
        file_ttl_seconds = config.file_ttl_seconds,
        "Starting Media Service"
    );

    // Create storage directory
    tokio::fs::create_dir_all(&config.storage_dir)
        .await
        .context("Failed to create storage directory")?;

    // Initialize application state
    let state = AppState {
        config: config.clone(),
    };

    // Start cleanup task
    spawn(cleanup::cleanup_expired_files(config.clone()));

    // Create router
    let app = Router::new()
        .route("/upload", post(handlers::upload_media))
        .route("/health", get(handlers::health_check))
        .route("/:media_id", get(handlers::download_media))
        .route("/:media_id", delete(handlers::delete_media))
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    info!("Media Service listening on {}", config.bind_address);

    axum::serve(listener, app).await.context("Server failed")?;

    Ok(())
}
