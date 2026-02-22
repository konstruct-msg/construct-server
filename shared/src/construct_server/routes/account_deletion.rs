// ============================================================================
// Device-Signed Account Deletion
// ============================================================================
//
// Secure account deletion using device signing key (Ed25519).
// Prevents deletion with stolen access token - requires device's signing key.
//
// Flow:
// 1. GET /api/v1/users/me/delete-challenge - Get challenge (60s TTL)
// 2. POST /api/v1/users/me/delete-confirm - Submit signed challenge
//
// Per spec: DEVICE_SIGNED_ACCOUNT_DELETION_SPEC.md
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::context::AppContext;
use crate::db;
use crate::routes::extractors::TrustedUser;
use crate::utils::log_safe_id;
use construct_error::AppError;

// ============================================================================
// Constants
// ============================================================================

/// Challenge TTL in seconds
const CHALLENGE_TTL_SECONDS: i64 = 60;

/// Redis key prefix for delete challenges
const CHALLENGE_KEY_PREFIX: &str = "delete_challenge:";

/// Maximum allowed timestamp skew in seconds
const MAX_TIMESTAMP_SKEW: i64 = 60;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for GET /api/v1/users/me/delete-challenge
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteChallengeResponse {
    /// Random 32-char hex challenge
    pub challenge: String,
    /// Unix timestamp when challenge expires
    pub expires_at: i64,
    /// Device ID that must sign the challenge
    pub device_id: String,
}

/// Request body for POST /api/v1/users/me/delete-confirm
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteConfirmRequest {
    /// Device ID that signed the challenge
    pub device_id: String,
    /// The challenge from step 1
    pub challenge: String,
    /// Base64-encoded Ed25519 signature
    pub signature: String,
    /// Unix timestamp when signature was created
    pub ts: i64,
}

/// Success response for deletion
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteSuccessResponse {
    pub status: &'static str,
}

/// Stored challenge data in Redis
#[derive(Debug, Serialize, Deserialize)]
struct StoredChallenge {
    user_id: String,
    device_id: String,
    challenge: String,
    created_at: i64,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/v1/users/me/delete-challenge
///
/// Get a challenge for device-signed account deletion.
///
/// Security:
/// - Requires authentication (via Gateway X-User-Id header)
/// - Challenge expires in 60 seconds
/// - One challenge per user at a time
pub async fn get_delete_challenge(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // First, verify user exists (in case they were already deleted)
    let user_exists = db::get_user_by_id(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check if user exists");
            AppError::Unknown(e)
        })?;

    if user_exists.is_none() {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "User not found (already deleted?)"
        );
        return Err(AppError::NotFound("User not found".to_string()));
    }

    // Get user's primary device
    let device_opt = db::get_user_primary_device(&app_context.db_pool, &user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query user's primary device");
            AppError::Unknown(e)
        })?;

    // If no device found, this is a user registered without device-based auth
    // (should not happen with current registration flow)
    let device = device_opt.ok_or_else(|| {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "No device found for user - account without device registration"
        );
        AppError::Validation(
            "Your account does not have device-based authentication enabled. \
            Please contact support to enable secure account deletion."
                .to_string(),
        )
    })?;

    // Generate random 32-char hex challenge
    let challenge = generate_hex_challenge();
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + CHALLENGE_TTL_SECONDS;

    // Store challenge in Redis
    let stored = StoredChallenge {
        user_id: user_id.to_string(),
        device_id: device.device_id.clone(),
        challenge: challenge.clone(),
        created_at: now,
    };

    let redis_key = format!("{}{}", CHALLENGE_KEY_PREFIX, user_id);
    {
        let mut queue = app_context.queue.lock().await;
        queue
            .set_with_expiry(
                &redis_key,
                &serde_json::to_string(&stored).unwrap_or_default(),
                CHALLENGE_TTL_SECONDS as u64,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to store delete challenge in Redis");
                AppError::Unknown(e)
            })?;
    }

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        device_id = %device.device_id,
        "Delete challenge generated"
    );

    Ok((
        StatusCode::OK,
        Json(DeleteChallengeResponse {
            challenge,
            expires_at,
            device_id: device.device_id,
        }),
    ))
}

/// POST /api/v1/users/me/delete-confirm
///
/// Confirm account deletion with device signature.
///
/// Security:
/// - Requires authentication (via Gateway X-User-Id header)
/// - Verifies Ed25519 signature using device's verifying_key
/// - Challenge must be valid and not expired
/// - Timestamp must be within ±60s of server time
pub async fn confirm_delete(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    Json(request): Json<DeleteConfirmRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;
    let now = chrono::Utc::now().timestamp();

    // 1. Validate timestamp skew
    let ts_diff = (now - request.ts).abs();
    if ts_diff > MAX_TIMESTAMP_SKEW {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            ts_diff = ts_diff,
            "Delete request timestamp too far from server time"
        );
        return Err(AppError::Validation(
            "Request timestamp is too far from server time".to_string(),
        ));
    }

    // 2. Retrieve and validate challenge from Redis
    let redis_key = format!("{}{}", CHALLENGE_KEY_PREFIX, user_id);
    let stored_json: Option<String> = {
        let mut queue = app_context.queue.lock().await;
        queue.get(&redis_key).await.ok().flatten()
    };

    let stored: StoredChallenge = match stored_json {
        Some(json) => serde_json::from_str(&json)
            .map_err(|_| AppError::Validation("Invalid challenge data".to_string()))?,
        None => {
            tracing::warn!(
                user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
                "Delete challenge not found or expired"
            );
            return Err(AppError::Gone("Challenge not found or expired".to_string()));
        }
    };

    // 3. Validate challenge matches
    if stored.challenge != request.challenge {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Delete challenge mismatch"
        );
        return Err(AppError::Validation("Invalid challenge".to_string()));
    }

    // 4. Validate device ID matches
    if stored.device_id != request.device_id {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            expected_device = %stored.device_id,
            received_device = %request.device_id,
            "Delete request device ID mismatch"
        );
        return Err(AppError::Forbidden(
            "Device ID does not match challenge".to_string(),
        ));
    }

    // 5. Get device's verifying key
    let device = db::get_device_by_id(&app_context.db_pool, &request.device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get device");
            AppError::Unknown(e)
        })?
        .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    // 6. Verify device belongs to user
    if device.user_id != Some(user_id) {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            device_id = %request.device_id,
            "Device does not belong to user"
        );
        return Err(AppError::Forbidden(
            "Device does not belong to this user".to_string(),
        ));
    }

    // 7. Build canonical string and verify signature
    // Format: DELETE|<userId>|<deviceId>|<challenge>|<ts>
    let canonical = format!(
        "DELETE|{}|{}|{}|{}",
        user_id, request.device_id, request.challenge, request.ts
    );

    verify_ed25519_signature(
        &device.verifying_key,
        &canonical,
        &request.signature,
    ).map_err(|e| {
        tracing::warn!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            error = %e,
            "Delete signature verification failed"
        );
        AppError::Forbidden(format!("Invalid signature: {}", e))
    })?;

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        device_id = %request.device_id,
        "Delete signature verified, proceeding with deletion"
    );

    // 8. Delete challenge from Redis (one-time use)
    {
        let mut queue = app_context.queue.lock().await;
        let _ = queue.delete(&redis_key).await;
    }

    // 9. Perform account deletion
    perform_account_deletion(&app_context, &user_id).await?;

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Account deleted successfully via device signature"
    );

    Ok((StatusCode::OK, Json(DeleteSuccessResponse { status: "ok" })))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate random 32-character hex string
fn generate_hex_challenge() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Verify Ed25519 signature
fn verify_ed25519_signature(
    verifying_key_bytes: &[u8],
    message: &str,
    signature_base64: &str,
) -> Result<(), String> {
    // Parse verifying key
    if verifying_key_bytes.len() != 32 {
        return Err(format!(
            "Invalid verifying key length: expected 32, got {}",
            verifying_key_bytes.len()
        ));
    }

    let key_array: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| "Failed to convert verifying key to array")?;

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Invalid Ed25519 verifying key: {}", e))?;

    // Decode signature
    let signature_bytes = BASE64
        .decode(signature_base64)
        .map_err(|e| format!("Invalid base64 signature: {}", e))?;

    if signature_bytes.len() != 64 {
        return Err(format!(
            "Invalid signature length: expected 64, got {}",
            signature_bytes.len()
        ));
    }

    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Failed to convert signature to array")?;

    let signature = Signature::from_bytes(&sig_array);

    // Verify
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
}

/// Perform the actual account deletion
async fn perform_account_deletion(
    app_context: &AppContext,
    user_id: &uuid::Uuid,
) -> Result<(), AppError> {
    // 1. Revoke all tokens and sessions
    {
        let mut queue = app_context.queue.lock().await;

        if let Err(e) = queue.revoke_all_user_tokens(&user_id.to_string()).await {
            tracing::warn!(error = %e, "Failed to revoke user tokens");
        }

        if let Err(e) = queue.revoke_all_sessions(&user_id.to_string()).await {
            tracing::warn!(error = %e, "Failed to revoke user sessions");
        }
    }

    // 2. Delete delivery ACK data (GDPR compliance)
    if let Some(ack_manager) = &app_context.delivery_ack_manager
        && let Err(e) = ack_manager.delete_user_data(&user_id.to_string()).await
    {
        tracing::warn!(error = %e, "Failed to delete delivery ACK data");
    }

    // 3. Untrack user online status
    {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue.untrack_user_online(&user_id.to_string()).await {
            tracing::warn!(error = %e, "Failed to untrack user online status");
        }
    }

    // 4. Delete user account from database (CASCADE handles related records)
    db::delete_user_account(&app_context.db_pool, user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete user account");
            AppError::Unknown(e)
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hex_challenge() {
        let challenge = generate_hex_challenge();
        assert_eq!(challenge.len(), 32);
        assert!(challenge.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_canonical_string_format() {
        let user_id = "149610e0-ab52-4306-b7c9-d77f1b4d2080";
        let device_id = "b11a3b56782d71aeb6eab80fe7266cbb";
        let challenge = "d9c06a8bf6b64b8f8b82f39e4fca6c3e";
        let ts = 1770588950i64;

        let canonical = format!("DELETE|{}|{}|{}|{}", user_id, device_id, challenge, ts);

        assert_eq!(
            canonical,
            "DELETE|149610e0-ab52-4306-b7c9-d77f1b4d2080|b11a3b56782d71aeb6eab80fe7266cbb|d9c06a8bf6b64b8f8b82f39e4fca6c3e|1770588950"
        );
    }
}
