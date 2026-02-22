// ============================================================================
// Media Service Handlers
// ============================================================================

use super::types::*;
use super::utils::*;
use crate::config::MediaConfig;
use anyhow::Result;
use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, State},
    http::{StatusCode, header},
    response::Response,
};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::warn;
use uuid::Uuid;

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

/// Upload media endpoint
pub async fn upload_media(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, StatusCode> {
    let config = &state.config;

    // Extract token and file from multipart
    let mut upload_token = None;
    let mut file_data = None;
    let mut filename = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        match field.name() {
            Some("token") => {
                upload_token = Some(field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            Some("file") => {
                filename = field.file_name().map(|s| s.to_string());
                file_data = Some(field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?);
            }
            _ => continue,
        }
    }

    let token = upload_token.ok_or(StatusCode::BAD_REQUEST)?;
    let data = file_data.ok_or(StatusCode::BAD_REQUEST)?;

    // Validate token
    if !validate_upload_token(&token, &config.hmac_secret) {
        warn!("Invalid upload token provided");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Check file size
    if data.len() > config.max_file_size {
        warn!("File too large: {} bytes", data.len());
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Generate media ID
    let media_id = Uuid::new_v4().to_string();

    // Create storage directory if needed
    fs::create_dir_all(&config.storage_dir)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Save file
    let file_path = config.storage_dir.join(&media_id);
    let mut file = fs::File::create(&file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    file.write_all(&data)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Calculate expiration time
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs()
        + config.file_ttl_seconds;

    tracing::info!(
        media_id = %media_id,
        size_bytes = data.len(),
        filename = ?filename,
        expires_at = expires_at,
        "Media file uploaded successfully"
    );

    Ok(Json(UploadResponse {
        media_id,
        expires_at,
    }))
}

/// Download media endpoint
pub async fn download_media(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
) -> Result<Response<Body>, StatusCode> {
    let config = &state.config;
    let file_path = config.storage_dir.join(&media_id);

    // Check if file exists
    if !file_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Read file
    let data = fs::read(&file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create response with binary data
    let body = Body::from(data);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "public, max-age=86400") // 24 hours
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(response)
}

/// Delete media endpoint (admin only)
pub async fn delete_media(
    State(state): State<AppState>,
    Path(media_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let config = &state.config;
    let file_path = config.storage_dir.join(&media_id);

    // Check admin token (simplified - in production use proper auth)
    // TODO: Add proper admin authentication

    match fs::remove_file(&file_path).await {
        Ok(_) => {
            tracing::info!(media_id = %media_id, "Media file deleted");
            Ok(StatusCode::NO_CONTENT)
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}
