// ============================================================================
// Media Routes - REST API for Media Upload Tokens
// ============================================================================
//
// This module provides REST endpoints for generating media upload tokens.
// Clients use these tokens to upload encrypted media files to media-service.
//
// Endpoints:
// - POST /api/v1/media/token - Generate upload token
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::messaging_service::MessagingServiceContext;
use crate::routes::extractors::TrustedUser;

/// Request for media upload token
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenRequest {
    /// Optional: specify file size for validation
    #[serde(default)]
    pub expected_size: Option<usize>,
}

/// Response with upload token
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenResponse {
    /// One-time upload token
    pub upload_token: String,
    /// Media server upload URL
    pub upload_url: String,
    /// Maximum file size in bytes
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
    TrustedUser(user_id): TrustedUser,
    Json(_payload): Json<MediaTokenRequest>,
) -> Result<Json<MediaTokenResponse>, (StatusCode, Json<MediaTokenError>)> {
    // Check if media is enabled
    if !ctx.config.media.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(MediaTokenError {
                error: "Media uploads are not enabled".to_string(),
                code: "MEDIA_DISABLED".to_string(),
            }),
        ));
    }

    // Check if upload_token_secret is configured
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
            // Continue anyway - don't block uploads due to Redis issues
        }
    }
    drop(queue);

    // Generate upload token
    let token = generate_upload_token(&ctx.config.media.upload_token_secret);

    // Calculate expiry (5 minutes from now)
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);

    // Construct upload URL
    let upload_url = format!("{}/upload", ctx.config.media.base_url);

    tracing::info!(
        user_id = %user_id,
        "Generated media upload token"
    );

    Ok(Json(MediaTokenResponse {
        upload_token: token,
        upload_url,
        max_file_size: ctx.config.media.max_file_size,
        expires_at: expires_at.to_rfc3339(),
    }))
}

/// Generate a one-time upload token
/// Format: {timestamp_hex}.{random_hex}.{hmac_hex}
fn generate_upload_token(secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // SECURITY: Handle system time errors gracefully
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "System time is before UNIX_EPOCH, using fallback timestamp");
            // Fallback to a reasonable timestamp (2020-01-01) if system time is invalid
            std::time::Duration::from_secs(1577836800)
        })
        .as_secs();

    let timestamp_hex = format!("{:x}", timestamp);
    let random_bytes: [u8; 16] = rand::random();
    let random_hex = hex::encode(random_bytes);

    let message = format!("{}.{}", timestamp_hex, random_hex);

    // Compute HMAC
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let hmac = hex::encode(result.into_bytes());

    format!("{}.{}.{}", timestamp_hex, random_hex, hmac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_upload_token() {
        let secret = "test-secret-that-is-at-least-32-chars-long";
        let token = generate_upload_token(secret);

        // Token should have 3 parts
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Timestamp should be valid hex
        assert!(u64::from_str_radix(parts[0], 16).is_ok());

        // Random should be 32 hex chars (16 bytes)
        assert_eq!(parts[1].len(), 32);

        // HMAC should be 64 hex chars (32 bytes)
        assert_eq!(parts[2].len(), 64);
    }
}
