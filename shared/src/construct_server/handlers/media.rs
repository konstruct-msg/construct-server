// ============================================================================
// Media Token Handler - Generate Upload Tokens for Media Server
// ============================================================================
//
// This handler generates one-time upload tokens that clients use to upload
// encrypted media files to the media-server.
//
// Security:
// - Tokens are HMAC-signed with shared secret
// - Tokens expire after 5 minutes
// - One token = one upload (enforced by media-server)
// - User must be authenticated
// - Rate limited per user
//
// ============================================================================

use crate::context::AppContext;
use crate::handlers::connection::ConnectionHandler;
use construct_types::{RequestMediaTokenData, ServerMessage};
use crate::utils::log_safe_id;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Response with upload token
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenResponse {
    /// Request ID for correlation
    pub request_id: String,
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTokenError {
    pub request_id: String,
    pub error: String,
    pub code: String,
}

/// Handle request for media upload token (WebSocket)
pub async fn handle_media_token_request(
    handler: &mut ConnectionHandler,
    ctx: &AppContext,
    request: RequestMediaTokenData,
) {
    // Check if media is enabled
    if !ctx.config.media.enabled {
        let error = MediaTokenError {
            request_id: request.request_id,
            error: "Media uploads are not enabled".to_string(),
            code: "MEDIA_DISABLED".to_string(),
        };
        let _ = handler
            .send_msgpack(&ServerMessage::MediaTokenError(error))
            .await;
        return;
    }

    // Check if upload_token_secret is configured
    if ctx.config.media.upload_token_secret.is_empty() {
        tracing::error!("MEDIA_UPLOAD_TOKEN_SECRET is not configured");
        let error = MediaTokenError {
            request_id: request.request_id,
            error: "Media service is not configured".to_string(),
            code: "MEDIA_NOT_CONFIGURED".to_string(),
        };
        let _ = handler
            .send_msgpack(&ServerMessage::MediaTokenError(error))
            .await;
        return;
    }

    // Get authenticated user
    let user_id = match handler.user_id() {
        Some(id) => id.clone(),
        None => {
            let error = MediaTokenError {
                request_id: request.request_id,
                error: "Authentication required".to_string(),
                code: "AUTH_REQUIRED".to_string(),
            };
            let _ = handler
                .send_msgpack(&ServerMessage::MediaTokenError(error))
                .await;
            return;
        }
    };

    // Rate limiting
    let mut queue = ctx.queue.lock().await;
    let rate_key = format!("media_upload:{}", user_id);
    match queue.increment_rate_limit(&rate_key, 3600).await {
        Ok(count) => {
            if count > ctx.config.media.rate_limit_per_hour as i64 {
                tracing::warn!(
                    user_hash = %log_safe_id(&user_id, &ctx.config.logging.hash_salt),
                    count = count,
                    limit = ctx.config.media.rate_limit_per_hour,
                    "Media upload rate limit exceeded"
                );
                let error = MediaTokenError {
                    request_id: request.request_id,
                    error: format!(
                        "Upload rate limit exceeded. Maximum {} uploads per hour.",
                        ctx.config.media.rate_limit_per_hour
                    ),
                    code: "RATE_LIMIT_EXCEEDED".to_string(),
                };
                let _ = handler
                    .send_msgpack(&ServerMessage::MediaTokenError(error))
                    .await;
                return;
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

    let response = MediaTokenResponse {
        request_id: request.request_id,
        upload_token: token,
        upload_url,
        max_file_size: ctx.config.media.max_file_size,
        expires_at: expires_at.to_rfc3339(),
    };

    tracing::debug!(
        user_hash = %log_safe_id(&user_id, &ctx.config.logging.hash_salt),
        "Generated media upload token"
    );

    let _ = handler
        .send_msgpack(&ServerMessage::MediaToken(response))
        .await;
}

/// Generate a one-time upload token
/// Format: {timestamp_hex}.{random_hex}.{hmac_hex}
fn generate_upload_token(secret: &str) -> String {
    // SECURITY: Handle system time errors gracefully (e.g., if system time is before UNIX_EPOCH)
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
    let hmac = compute_hmac(&message, secret);

    format!("{}.{}.{}", timestamp_hex, random_hex, hmac)
}

fn compute_hmac(message: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());

    let result = mac.finalize();
    hex::encode(result.into_bytes())
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

    #[test]
    fn test_compute_hmac() {
        let hmac1 = compute_hmac("test", "secret");
        let hmac2 = compute_hmac("test", "secret");
        let hmac3 = compute_hmac("different", "secret");

        assert_eq!(hmac1, hmac2);
        assert_ne!(hmac1, hmac3);
    }
}
