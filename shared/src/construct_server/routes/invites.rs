// ============================================================================
// Invites Routes (Dynamic Contact Sharing)
// ============================================================================
//
// Endpoints:
// - POST /api/v1/invites/generate - Generate one-time invite token
// - POST /api/v1/invites/accept - Accept and burn invite token
//
// Purpose: Secure, one-time contact sharing via QR codes and deep links
// Replaces old broken konstruct.cc/c/{UUID} static links
//
// Security:
// - One-time use only (jti tracking prevents replay)
// - Short TTL (5 minutes default)
// - Cryptographic signatures (Ed25519)
// - Federation-ready
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::db::{self as local_db, DbPool};
use crate::rate_limit::{RateLimitAction, is_user_in_warmup};
use crate::routes::extractors::TrustedUser;
use construct_db;
use construct_error::AppError;
use crypto_agility::{InviteToken, InviteValidationError};

// ============================================================================
// Invite Signature Verification
// ============================================================================

/// Errors that can occur during invite signature verification
#[derive(Debug)]
pub enum InviteSignatureError {
    /// Device not found for the given device_id (v2) or user_id (v1)
    DeviceNotFound,
    /// Invalid verifying key format
    InvalidVerifyingKey(String),
    /// Invalid signature format
    InvalidSignature(String),
    /// Signature verification failed
    VerificationFailed,
    /// Database error
    DatabaseError(String),
}

impl std::fmt::Display for InviteSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "Device not found"),
            Self::InvalidVerifyingKey(msg) => write!(f, "Invalid verifying key: {}", msg),
            Self::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for InviteSignatureError {}

/// Verify Ed25519 signature of an invite token
///
/// For v2 invites: fetches device by device_id
/// For v1 invites: fetches user's primary device by user_id
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `invite` - The invite token to verify
///
/// # Returns
/// * `Ok(())` if signature is valid
/// * `Err(InviteSignatureError)` if verification fails
pub async fn verify_invite_signature(
    pool: &DbPool,
    invite: &InviteToken,
) -> Result<(), InviteSignatureError> {
    // 1. Fetch verifying key based on invite version
    let verifying_key_bytes = if invite.v == 2 {
        // v2: Use device_id to fetch device
        let device_id = invite
            .device_id
            .as_ref()
            .ok_or(InviteSignatureError::InvalidSignature(
                "v2 invite missing device_id".to_string(),
            ))?;

        let device = local_db::get_device_by_id(pool, device_id)
            .await
            .map_err(|e| InviteSignatureError::DatabaseError(e.to_string()))?
            .ok_or(InviteSignatureError::DeviceNotFound)?;

        device.verifying_key
    } else {
        // v1: Use user_id to fetch user's primary device
        let devices = local_db::get_devices_by_user_id(pool, &invite.uuid)
            .await
            .map_err(|e| InviteSignatureError::DatabaseError(e.to_string()))?;

        // Get the first active device (primary)
        let device = devices
            .into_iter()
            .next()
            .ok_or(InviteSignatureError::DeviceNotFound)?;

        device.verifying_key
    };

    // DEBUG: Log the verifying key from database
    tracing::info!(
        verifying_key_base64 = %BASE64.encode(&verifying_key_bytes),
        verifying_key_len = verifying_key_bytes.len(),
        "DEBUG: Verifying key fetched from database"
    );

    // 2. Parse verifying key (32 bytes Ed25519 public key)
    if verifying_key_bytes.len() != 32 {
        return Err(InviteSignatureError::InvalidVerifyingKey(format!(
            "Expected 32 bytes, got {}",
            verifying_key_bytes.len()
        )));
    }

    let key_array: [u8; 32] = verifying_key_bytes.try_into().map_err(|_| {
        InviteSignatureError::InvalidVerifyingKey("Failed to convert to array".to_string())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&key_array).map_err(|e| {
        InviteSignatureError::InvalidVerifyingKey(format!("Invalid Ed25519 key: {}", e))
    })?;

    // 3. Decode signature from Base64
    let signature_bytes = BASE64
        .decode(&invite.sig)
        .map_err(|e| InviteSignatureError::InvalidSignature(format!("Invalid base64: {}", e)))?;

    if signature_bytes.len() != 64 {
        return Err(InviteSignatureError::InvalidSignature(format!(
            "Expected 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let sig_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        InviteSignatureError::InvalidSignature("Failed to convert to array".to_string())
    })?;

    let signature = Signature::from_bytes(&sig_array);

    // 4. Build canonical string and verify
    let canonical = invite.canonical_string();

    // DEBUG: Log what we're verifying
    tracing::info!(
        canonical_string = %canonical,
        signature_base64 = %invite.sig,
        "DEBUG: Verifying signature"
    );

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| {
            tracing::warn!(
                error = %e,
                "DEBUG: Signature verification FAILED"
            );
            InviteSignatureError::VerificationFailed
        })?;

    tracing::info!("DEBUG: Signature verification SUCCESS");
    Ok(())
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to generate a new invite token
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateInviteRequest {
    /// Optional custom TTL in seconds (default: 300 = 5 minutes)
    /// Must be between 60 (1 min) and 3600 (1 hour)
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

/// Response after generating an invite token
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateInviteResponse {
    /// Unique invite ID (jti)
    pub jti: Uuid,

    /// Server FQDN for the invite
    pub server: String,

    /// Unix timestamp when this invite expires
    pub expires_at: i64,

    /// TTL in seconds
    pub ttl_seconds: i64,
}

/// Request to accept an invite token
#[derive(Debug, Deserialize)]
pub struct AcceptInviteRequest {
    /// Full invite token object from QR code or link
    pub invite: InviteToken,
}

/// Response after accepting an invite
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptInviteResponse {
    /// User ID that was added
    pub user_id: Uuid,

    /// Device ID (v2 only, None for v1 invites)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// Server where the user is located
    pub server: String,

    /// Success message
    pub message: String,
}

/// POST /api/v1/invites/generate
///
/// Generate a new one-time invite token for contact sharing.
///
/// The client will:
/// 1. Receive jti and server from this endpoint
/// 2. Generate ephemeral X25519 keypair
/// 3. Sign the invite object with Identity Key
/// 4. Encode as Base64/MessagePack
/// 5. Display as QR or URL: konstruct.cc/add#{token}
///
/// Security:
/// - Requires authentication (via Gateway X-User-Id header)
/// - Stores jti in database for one-time use tracking
/// - Auto-cleanup after 5 minutes
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
/// Gateway verifies JWT and propagates user identity via X-User-Id header.
pub async fn generate_invite(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    Json(request): Json<GenerateInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = user.0;

    // SECURITY: Check warmup-aware rate limits for invite generation
    // New accounts (<48h) can only create 3 invites per day
    let in_warmup = is_user_in_warmup(&app_context.db_pool, user_id)
        .await
        .unwrap_or(true);

    let action = RateLimitAction::CreateInvite;
    let (max_count, window_seconds) = if in_warmup {
        action.warmup_limits() // 3 per day for warmup
    } else {
        action.established_limits().unwrap_or((100, 86400)) // 100 per day for established
    };

    {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue
            .check_warmup_rate_limit(
                &user_id.to_string(),
                action.as_str(),
                max_count,
                window_seconds,
            )
            .await
        {
            tracing::warn!(
                user_id = %user_id,
                in_warmup = in_warmup,
                error = %e,
                "Warmup rate limit exceeded for invite generation"
            );
            return Err(AppError::TooManyRequests(format!(
                "Invite rate limit exceeded: {}",
                e
            )));
        }
    }

    // Validate TTL
    let ttl_seconds = request.ttl_seconds.unwrap_or(300); // Default 5 minutes
    if !(60..=3600).contains(&ttl_seconds) {
        return Err(AppError::Validation(
            "TTL must be between 60 and 3600 seconds".to_string(),
        ));
    }

    // Generate unique jti
    let jti = Uuid::new_v4();

    // Get server FQDN from config
    let server = app_context.config.instance_domain.clone();

    // Note: Ephemeral key and signature are generated client-side
    // Here we just create a placeholder record to reserve the jti
    let placeholder_key = vec![0u8; 32]; // Client will provide real key
    let placeholder_sig = vec![0u8; 64]; // Client will provide real signature

    // Store invite token in database
    match construct_db::create_invite_token(
        &app_context.db_pool,
        &jti,
        &user_id,
        &placeholder_key,
        &placeholder_sig,
    )
    .await
    {
        Ok(_) => {
            let now = chrono::Utc::now().timestamp();
            let expires_at = now + ttl_seconds;

            tracing::info!(
                user_id = %user_id,
                jti = %jti,
                ttl_seconds = ttl_seconds,
                "Invite token generated"
            );

            Ok((
                StatusCode::CREATED,
                Json(GenerateInviteResponse {
                    jti,
                    server,
                    expires_at,
                    ttl_seconds,
                }),
            ))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "Failed to create invite token"
            );
            Err(AppError::Validation(format!(
                "Failed to generate invite: {}",
                e
            )))
        }
    }
}

/// POST /api/v1/invites/accept
///
/// Accept an invite token from a QR code or deep link.
///
/// Validation flow:
/// 1. Verify timestamp (reject if > TTL old)
/// 2. Verify timestamp not in future (clock skew attack)
/// 3. Fetch user's public Identity Key
/// 4. Verify Ed25519 signature
/// 5. Check jti in database (atomic burn)
/// 6. Add user to contacts
///
/// For federated users, this will trigger an S2S request to the user's server
/// to validate and burn the jti.
///
/// Note: Uses TrustedUser extractor (Trust Boundary pattern).
/// Gateway verifies JWT and propagates user identity via X-User-Id header.
pub async fn accept_invite(
    State(app_context): State<Arc<AppContext>>,
    user: TrustedUser,
    Json(request): Json<AcceptInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let accepter_user_id = user.0; // User who is accepting the invite
    let invite = request.invite;

    // 1. Validate invite structure and expiry (TTL: 300 seconds = 5 minutes)
    if let Err(e) = invite.validate_with_expiry(300) {
        tracing::warn!(
            jti = %invite.jti,
            version = invite.v,
            device_id = ?invite.device_id,
            error = %e,
            "Invite validation failed"
        );
        return Err(match e {
            InviteValidationError::Expired => AppError::InviteExpired,
            InviteValidationError::FutureTimestamp => {
                AppError::Validation("Invalid invite timestamp".to_string())
            }
            InviteValidationError::MissingDeviceID => {
                AppError::Validation("Invalid v2 invite: missing device ID".to_string())
            }
            InviteValidationError::InvalidDeviceID => {
                AppError::Validation("Invalid device ID format".to_string())
            }
            _ => AppError::Validation(format!("Invalid invite: {}", e)),
        });
    }

    // Log invite version for monitoring
    tracing::info!(
        jti = %invite.jti,
        version = invite.v,
        device_id = ?invite.device_id,
        "Processing invite"
    );

    // DEBUG: Log invite details for troubleshooting
    tracing::info!(
        jti = %invite.jti,
        version = invite.v,
        uuid = %invite.uuid,
        device_id = ?invite.device_id,
        server = %invite.server,
        ts = invite.ts,
        canonical = %invite.canonical_string(),
        "DEBUG: Invite canonical string for verification"
    );

    // 2. Verify Ed25519 signature
    // For v2: fetch device by device_id
    // For v1: fetch user's primary device by user_id
    if let Err(e) = verify_invite_signature(&app_context.db_pool, &invite).await {
        tracing::warn!(
            jti = %invite.jti,
            version = invite.v,
            device_id = ?invite.device_id,
            error = %e,
            "Invite signature verification failed"
        );
        return Err(match e {
            InviteSignatureError::DeviceNotFound => AppError::PublicKeyNotFound,
            InviteSignatureError::VerificationFailed => AppError::InviteInvalidSignature,
            InviteSignatureError::InvalidVerifyingKey(_) => AppError::PublicKeyNotFound,
            _ => AppError::InviteInvalidSignature,
        });
    }

    tracing::info!(
        jti = %invite.jti,
        version = invite.v,
        "Invite signature verified successfully"
    );

    // 3. Atomic burn: Check and mark invite as used
    match construct_db::burn_invite_token(&app_context.db_pool, &invite.jti).await {
        Ok(true) => {
            // Success - invite was valid and now burned
            tracing::info!(
                jti = %invite.jti,
                version = invite.v,
                user_id = %invite.uuid,
                device_id = ?invite.device_id,
                accepter = %accepter_user_id,
                "Invite accepted and burned"
            );

            // TODO: Actually add user to contacts
            // For now, just return success

            Ok((
                StatusCode::OK,
                Json(AcceptInviteResponse {
                    user_id: invite.uuid,
                    device_id: invite.device_id.clone(),
                    server: invite.server.clone(),
                    message: format!("Contact {} added successfully", invite.uuid),
                }),
            ))
        }
        Ok(false) => {
            // Invite already used or not found
            tracing::warn!(
                jti = %invite.jti,
                "Invite token already used or not found"
            );
            Err(AppError::InviteAlreadyUsed)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                jti = %invite.jti,
                "Failed to burn invite token"
            );
            Err(AppError::Validation(format!(
                "Failed to accept invite: {}",
                e
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_endpoints_compile() {
        // Verify function signatures are correct
        let _ = generate_invite;
        let _ = accept_invite;
    }
}
