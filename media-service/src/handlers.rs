// ============================================================================
// Media Service REST Handlers — RETIRED
// ============================================================================
//
// Production serves media exclusively over gRPC (`MediaService` in main.rs).
// These Axum handlers remain only so the library crate still compiles for any
// residual unit tests. They intentionally return 410 Gone / refuse to write
// files — do not re-enable without re-auditing path traversal and auth.
//
// ============================================================================

use super::types::*;
use crate::config::MediaConfig;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;
use tracing::warn;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<MediaConfig>,
}

/// Health check endpoint
pub async fn health_check(State(_state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// REST upload — permanently disabled (use gRPC UploadMedia).
pub async fn upload_media(
    State(_state): State<AppState>,
) -> Result<Json<UploadResponse>, StatusCode> {
    warn!("REST media upload rejected — use gRPC MediaService.UploadMedia");
    Err(StatusCode::GONE)
}

/// REST download — permanently disabled (use gRPC DownloadMedia).
pub async fn download_media(
    State(_state): State<AppState>,
    Path(_media_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    warn!("REST media download rejected — use gRPC MediaService.DownloadMedia");
    Err(StatusCode::GONE)
}

/// REST delete — permanently disabled (use gRPC DeleteMedia with admin token).
pub async fn delete_media(
    State(_state): State<AppState>,
    Path(_media_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    warn!("REST media delete rejected — use gRPC MediaService.DeleteMedia");
    Err(StatusCode::GONE)
}
