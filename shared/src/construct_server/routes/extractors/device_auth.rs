// ============================================================================
// Device-Based Authentication Extractor
// ============================================================================
//
// Authenticates requests using device-based signature verification.
//
// Protocol:
// 1. Client sends headers:
//    - X-Device-ID: device identifier (16 hex chars)
//    - X-Timestamp: Unix timestamp in milliseconds
//    - X-Signature: Ed25519 signature of request
//
// 2. Server validates:
//    - Device exists in database
//    - Timestamp is within 5-minute window (replay protection)
//    - Signature matches using device's verifying_key
//
// 3. Signature payload format:
//    "{METHOD}\n{PATH}\n{TIMESTAMP}\n{BODY_SHA256}"
//
// Example:
//    "GET\n/api/v1/users/me/profile\n1738612345678\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
//
// ============================================================================

use axum::{
    async_trait,
    extract::{FromRequest, Request},
    http::header::HeaderMap,
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::context::AppContext;
use crate::db::Device;
use construct_error::AppError;

/// Maximum allowed time difference between request timestamp and server time (milliseconds)
/// 5 minutes = 300,000 ms
const MAX_TIMESTAMP_DIFF_MS: i64 = 300_000;

/// Extractor for device-based authentication
///
/// Validates Ed25519 signature of the request using device's public key.
///
/// Usage:
/// ```rust
/// async fn handler(device: DeviceAuth, ...) -> Result<...> {
///     let device_id = device.device_id;
///     let user_id = device.user_id; // Option<Uuid>
///     // ...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DeviceAuth {
    /// Device identifier (16 hex chars, SHA256 of identity_public)
    pub device_id: String,

    /// User ID if device is linked to a user (None for newly registered devices)
    pub user_id: Option<uuid::Uuid>,

    /// Full device record from database
    pub device: Device,

    /// Timestamp from request (for logging/auditing)
    pub timestamp: i64,
}

#[async_trait]
impl FromRequest<Arc<AppContext>> for DeviceAuth {
    type Rejection = Response;

    async fn from_request(req: Request, state: &Arc<AppContext>) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        // Extract headers
        let device_id = extract_header(&parts.headers, "x-device-id").map_err(error_response)?;

        let timestamp_str =
            extract_header(&parts.headers, "x-timestamp").map_err(error_response)?;

        let signature_hex =
            extract_header(&parts.headers, "x-signature").map_err(error_response)?;

        // Parse timestamp
        let timestamp: i64 = timestamp_str
            .parse()
            .map_err(|_| error_response(AppError::Auth("Invalid timestamp format".to_string())))?;

        // Validate timestamp (replay protection)
        validate_timestamp(timestamp).map_err(error_response)?;

        // Load device from database
        let device = crate::db::get_device_by_id(&state.db_pool, &device_id)
            .await
            .map_err(|e| {
                error_response(AppError::Internal(format!("Failed to load device: {}", e)))
            })?
            .ok_or_else(|| {
                error_response(AppError::NotFound(format!(
                    "Device not found: {}",
                    device_id
                )))
            })?;

        // Read body bytes for signature verification
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|e| {
            error_response(AppError::Internal(format!("Failed to read body: {}", e)))
        })?;

        // Compute body SHA256
        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        let body_hash = hex::encode(hasher.finalize());

        // Construct signature payload
        let method = parts.method.as_str();
        let path = parts.uri.path();
        let payload = format!("{}\n{}\n{}\n{}", method, path, timestamp, body_hash);

        tracing::debug!(
            device_id = %device_id,
            method = %method,
            path = %path,
            timestamp = %timestamp,
            body_hash = %body_hash,
            "Verifying device signature"
        );

        // Parse Ed25519 signature
        let signature_bytes = hex::decode(&signature_hex).map_err(|_| {
            error_response(AppError::Auth(
                "Invalid signature format (not hex)".to_string(),
            ))
        })?;

        let signature =
            Signature::from_bytes(signature_bytes.as_slice().try_into().map_err(|_| {
                error_response(AppError::Auth(
                    "Invalid signature length (expected 64 bytes)".to_string(),
                ))
            })?);

        // Parse device's verifying key
        let verifying_key_bytes: [u8; 32] =
            device.verifying_key.as_slice().try_into().map_err(|_| {
                error_response(AppError::Internal(
                    "Invalid verifying_key length in database".to_string(),
                ))
            })?;

        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes).map_err(|e| {
            error_response(AppError::Internal(format!("Invalid verifying_key: {}", e)))
        })?;

        // Verify signature
        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|e| {
                tracing::warn!(
                    device_id = %device_id,
                    error = %e,
                    "Signature verification failed"
                );
                error_response(AppError::Auth("Invalid signature".to_string()))
            })?;

        tracing::info!(
            device_id = %device_id,
            user_id = ?device.user_id,
            "Device authenticated successfully"
        );

        // Update last_active timestamp (fire-and-forget)
        let db_pool = state.db_pool.clone();
        let device_id_clone = device_id.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::db::update_device_last_active(&db_pool, &device_id_clone).await {
                tracing::warn!(device_id = %device_id_clone, error = %e, "Failed to update last_active");
            }
        });

        Ok(DeviceAuth {
            device_id,
            user_id: device.user_id,
            device,
            timestamp,
        })
    }
}

// Implement for UserServiceContext
#[async_trait]
impl FromRequest<Arc<crate::user_service::UserServiceContext>> for DeviceAuth {
    type Rejection = Response;

    async fn from_request(
        req: Request,
        state: &Arc<crate::user_service::UserServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        let app_context = Arc::new(state.to_app_context());
        <DeviceAuth as FromRequest<Arc<AppContext>>>::from_request(req, &app_context).await
    }
}

// Implement for AuthServiceContext
#[async_trait]
impl FromRequest<Arc<crate::auth_service::AuthServiceContext>> for DeviceAuth {
    type Rejection = Response;

    async fn from_request(
        req: Request,
        state: &Arc<crate::auth_service::AuthServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        let app_context = Arc::new(state.to_app_context());
        <DeviceAuth as FromRequest<Arc<AppContext>>>::from_request(req, &app_context).await
    }
}

// Implement for MessagingServiceContext
#[async_trait]
impl FromRequest<Arc<crate::messaging_service::MessagingServiceContext>> for DeviceAuth {
    type Rejection = Response;

    async fn from_request(
        req: Request,
        state: &Arc<crate::messaging_service::MessagingServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        let app_context = Arc::new(state.to_app_context());
        <DeviceAuth as FromRequest<Arc<AppContext>>>::from_request(req, &app_context).await
    }
}

// Implement for NotificationServiceContext
#[async_trait]
impl FromRequest<Arc<crate::notification_service::NotificationServiceContext>> for DeviceAuth {
    type Rejection = Response;

    async fn from_request(
        req: Request,
        state: &Arc<crate::notification_service::NotificationServiceContext>,
    ) -> Result<Self, Self::Rejection> {
        let app_context = Arc::new(state.to_app_context());
        <DeviceAuth as FromRequest<Arc<AppContext>>>::from_request(req, &app_context).await
    }
}

/// Extract header value as String
fn extract_header(headers: &HeaderMap, name: &str) -> Result<String, AppError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Auth(format!("Missing {} header", name)))
}

/// Validate timestamp is within acceptable window
fn validate_timestamp(timestamp_ms: i64) -> Result<(), AppError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AppError::Internal(format!("System time error: {}", e)))?
        .as_millis() as i64;

    let diff = (now_ms - timestamp_ms).abs();

    if diff > MAX_TIMESTAMP_DIFF_MS {
        tracing::warn!(
            timestamp = %timestamp_ms,
            now = %now_ms,
            diff_ms = %diff,
            max_allowed_ms = %MAX_TIMESTAMP_DIFF_MS,
            "Timestamp outside acceptable window"
        );
        return Err(AppError::Auth(format!(
            "Timestamp too old or too far in future (diff: {}ms, max: {}ms)",
            diff, MAX_TIMESTAMP_DIFF_MS
        )));
    }

    Ok(())
}

/// Convert AppError to HTTP response
fn error_response(error: AppError) -> Response {
    let status = error.status_code();
    let body = json!({
        "error": error.user_message(),
        "error_code": error.error_code(),
        "status": status.as_u16(),
    });

    (status, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_validation() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Valid: current time
        assert!(validate_timestamp(now_ms).is_ok());

        // Valid: 2 minutes ago
        assert!(validate_timestamp(now_ms - 120_000).is_ok());

        // Valid: 2 minutes in future (clock skew)
        assert!(validate_timestamp(now_ms + 120_000).is_ok());

        // Invalid: 10 minutes ago
        assert!(validate_timestamp(now_ms - 600_000).is_err());

        // Invalid: 10 minutes in future
        assert!(validate_timestamp(now_ms + 600_000).is_err());
    }

    #[test]
    fn test_signature_payload_format() {
        let method = "POST";
        let path = "/api/v1/users/me/profile";
        let timestamp = 1738612345678i64;
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let payload = format!("{}\n{}\n{}\n{}", method, path, timestamp, body_hash);

        assert_eq!(
            payload,
            "POST\n/api/v1/users/me/profile\n1738612345678\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
