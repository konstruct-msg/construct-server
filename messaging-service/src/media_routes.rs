// ============================================================================
// Media Routes - REST API for Media Upload Tokens (legacy)
// ============================================================================
//
// Prefer gRPC MediaService.GenerateUploadToken on media-service.
// This REST path remains for transitional clients but now requires Bearer auth
// (no TrustedUser / x-user-id spoof) and mints tokens in the same v2 wire
// format as media-service: `{media_id}|{expires}|{max_size}|{user_id}|{hmac}`.
//
// Endpoints:
// - POST /api/v1/media/token - Generate upload token
//
// ============================================================================

use crate::context::MessagingServiceContext;
use crate::rest_auth::require_bearer_user_id;
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Request for media upload token
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenRequest {
    /// Optional: specify file size for validation (bound into the token)
    #[serde(default)]
    pub expected_size: Option<usize>,
}

/// Response with upload token
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenResponse {
    /// One-time upload token (opaque; format is media-service v2)
    pub upload_token: String,
    /// Media server upload URL
    pub upload_url: String,
    /// Maximum file size in bytes for this token
    pub max_file_size: usize,
    /// Token expiry (ISO 8601)
    pub expires_at: String,
}

/// Error response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenError {
    pub error: String,
    pub code: String,
}

/// Generate media upload token
/// POST /api/v1/media/token
pub async fn generate_media_token(
    State(ctx): State<Arc<MessagingServiceContext>>,
    headers: HeaderMap,
    Json(payload): Json<MediaTokenRequest>,
) -> Result<Json<MediaTokenResponse>, (StatusCode, Json<MediaTokenError>)> {
    let user_id = require_bearer_user_id(&ctx.auth_manager, &headers).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(MediaTokenError {
                error: e.to_string(),
                code: "AUTH_REQUIRED".to_string(),
            }),
        )
    })?;

    if !ctx.config.media.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(MediaTokenError {
                error: "Media uploads are not enabled".to_string(),
                code: "MEDIA_DISABLED".to_string(),
            }),
        ));
    }

    if ctx.config.media.upload_token_secret.is_empty() {
        tracing::error!("MEDIA_UPLOAD_TOKEN_SECRET is not configured");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MediaTokenError {
                error: "Media service is not configured".to_string(),
                code: "MEDIA_NOT_CONFIGURED".to_string(),
            }),
        ));
    }

    // Rate limiting
    let mut queue = ctx.queue.lock().await;
    let rate_key = format!("media_upload:{}", user_id);
    match queue.increment_rate_limit(&rate_key, 3600).await {
        Ok(count) => {
            if count > ctx.config.media.rate_limit_per_hour as i64 {
                tracing::warn!(
                    user_id = %user_id,
                    count = count,
                    limit = ctx.config.media.rate_limit_per_hour,
                    "Media upload rate limit exceeded"
                );
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(MediaTokenError {
                        error: format!(
                            "Upload rate limit exceeded. Maximum {} uploads per hour.",
                            ctx.config.media.rate_limit_per_hour
                        ),
                        code: "RATE_LIMIT_EXCEEDED".to_string(),
                    }),
                ));
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check media rate limit");
        }
    }
    drop(queue);

    let configured_max = ctx.config.media.max_file_size;
    let max_size = match payload.expected_size {
        Some(0) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(MediaTokenError {
                    error: "expected_size must be positive".to_string(),
                    code: "INVALID_SIZE".to_string(),
                }),
            ));
        }
        Some(n) if n > configured_max => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(MediaTokenError {
                    error: format!("expected_size exceeds maximum {configured_max}"),
                    code: "INVALID_SIZE".to_string(),
                }),
            ));
        }
        Some(n) => n,
        None => configured_max,
    };

    let token = generate_upload_token_v2(
        &ctx.config.media.upload_token_secret,
        user_id,
        max_size as i64,
    );

    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
    let upload_url = format!("{}/upload", ctx.config.media.base_url);

    tracing::info!(user_id = %user_id, max_size = max_size, "Generated media upload token (REST v2)");

    Ok(Json(MediaTokenResponse {
        upload_token: token,
        upload_url,
        max_file_size: max_size,
        expires_at: expires_at.to_rfc3339(),
    }))
}

/// media-service v2 wire format:
/// `{media_id}|{expires_at}|{max_size}|{user_id}|{hmac_hex}`
fn generate_upload_token_v2(secret: &str, user_id: Uuid, max_size: i64) -> String {
    use hmac::{Hmac, Mac, digest::KeyInit};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let media_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now().timestamp() + 300;
    let message = format!("{}|{}|{}|{}", media_id, expires_at, max_size, user_id);

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let hmac = hex::encode(mac.finalize().into_bytes());

    format!(
        "{}|{}|{}|{}|{}",
        media_id, expires_at, max_size, user_id, hmac
    )
}
