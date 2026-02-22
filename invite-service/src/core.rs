// ============================================================================
// InviteService Core Business Logic
// ============================================================================
//
// Extracted from shared/src/construct_server/routes/invites.rs
// Pure business logic, independent of transport layer (REST/gRPC)
//
// ============================================================================

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uuid::Uuid;

use construct_server_shared::{
    AppError,
    db::{self as construct_db, DbPool},
};
use crypto_agility::{InviteToken, InviteValidationError};

use crate::InviteServiceContext;

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

        let device = construct_db::get_device_by_id(pool, device_id)
            .await
            .map_err(|e| InviteSignatureError::DatabaseError(e.to_string()))?
            .ok_or(InviteSignatureError::DeviceNotFound)?;

        device.verifying_key
    } else {
        // v1: Use user_id to fetch user's primary device
        let devices = construct_db::get_devices_by_user_id(pool, &invite.uuid)
            .await
            .map_err(|e| InviteSignatureError::DatabaseError(e.to_string()))?;

        // Get the first active device (primary)
        let device = devices
            .into_iter()
            .next()
            .ok_or(InviteSignatureError::DeviceNotFound)?;

        device.verifying_key
    };

    tracing::debug!(
        verifying_key_base64 = %BASE64.encode(&verifying_key_bytes),
        verifying_key_len = verifying_key_bytes.len(),
        "Verifying key fetched from database"
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

    tracing::debug!(
        canonical_string = %canonical,
        signature_base64 = %invite.sig,
        "Verifying signature"
    );

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| {
            tracing::warn!(
                error = %e,
                "Signature verification FAILED"
            );
            InviteSignatureError::VerificationFailed
        })?;

    tracing::debug!("Signature verification SUCCESS");
    Ok(())
}

// ============================================================================
// Core Business Logic
// ============================================================================

pub struct GenerateInviteInput {
    pub user_id: Uuid,
    pub device_id: Option<String>,
    pub ttl_seconds: Option<i64>,
}

pub struct GenerateInviteOutput {
    pub jti: String,
    pub server: String,
    pub expires_at: i64,
    pub user_id: String,
    pub device_id: Option<String>,
    pub ttl_seconds: i64,
}

/// Generate a new invite token (reserves jti in database)
pub async fn generate_invite(
    context: &InviteServiceContext,
    input: GenerateInviteInput,
) -> Result<GenerateInviteOutput> {
    // Validate TTL
    let ttl_seconds = input.ttl_seconds.unwrap_or(300); // Default 5 minutes
    if !(60..=3600).contains(&ttl_seconds) {
        return Err(
            AppError::Validation("TTL must be between 60 and 3600 seconds".to_string()).into(),
        );
    }

    // Generate unique jti
    let jti = Uuid::new_v4();

    // Get server FQDN from config
    let server = context.config.instance_domain.clone();

    // Note: We don't store anything in DB at generation time.
    // The jti will be checked/burned when someone tries to accept the invite.
    // This is a stateless invite generation.

    let now = Utc::now().timestamp();
    let expires_at = now + ttl_seconds;

    tracing::info!(
        user_id = %input.user_id,
        jti = %jti,
        ttl_seconds = ttl_seconds,
        "Invite token generated"
    );

    Ok(GenerateInviteOutput {
        jti: jti.to_string(),
        server,
        expires_at,
        user_id: input.user_id.to_string(),
        device_id: input.device_id,
        ttl_seconds,
    })
}

pub struct AcceptInviteInput {
    pub accepter_user_id: Uuid,
    pub invite: InviteToken,
}

pub struct AcceptInviteOutput {
    pub user_id: String,
    pub device_id: Option<String>,
    pub server: String,
    pub message: String,
}

/// Accept an invite token (validates and burns jti)
pub async fn accept_invite(
    context: &InviteServiceContext,
    input: AcceptInviteInput,
) -> Result<AcceptInviteOutput> {
    let invite = input.invite;

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
            InviteValidationError::Expired => AppError::InviteExpired.into(),
            InviteValidationError::FutureTimestamp => {
                AppError::Validation("Invalid invite timestamp".to_string()).into()
            }
            InviteValidationError::MissingDeviceID => {
                AppError::Validation("Invalid v2 invite: missing device ID".to_string()).into()
            }
            InviteValidationError::InvalidDeviceID => {
                AppError::Validation("Invalid device ID format".to_string()).into()
            }
            _ => AppError::Validation(format!("Invalid invite: {}", e)).into(),
        });
    }

    tracing::info!(
        jti = %invite.jti,
        version = invite.v,
        device_id = ?invite.device_id,
        canonical = %invite.canonical_string(),
        "Processing invite"
    );

    // 2. Verify Ed25519 signature
    if let Err(e) = verify_invite_signature(&context.db_pool, &invite).await {
        tracing::warn!(
            jti = %invite.jti,
            version = invite.v,
            device_id = ?invite.device_id,
            error = %e,
            "Invite signature verification failed"
        );
        return Err(match e {
            InviteSignatureError::DeviceNotFound => AppError::PublicKeyNotFound.into(),
            InviteSignatureError::VerificationFailed => AppError::InviteInvalidSignature.into(),
            InviteSignatureError::InvalidVerifyingKey(_) => AppError::PublicKeyNotFound.into(),
            _ => AppError::InviteInvalidSignature.into(),
        });
    }

    // 3. Check if jti has already been used (atomic burn)
    let jti_uuid = invite.jti;
    let creator_user_id = invite.uuid;

    // Try to insert into used_invites table (atomic operation)
    let burn_result = sqlx::query!(
        r#"
        INSERT INTO used_invites (jti, user_id, device_id, expires_at)
        VALUES ($1, $2, $3, NOW() + INTERVAL '180 seconds')
        ON CONFLICT (jti) DO NOTHING
        RETURNING jti
        "#,
        jti_uuid,
        creator_user_id,
        invite.device_id.as_deref(),
    )
    .fetch_optional(&*context.db_pool)
    .await
    .context("Failed to burn invite jti")?;

    if burn_result.is_none() {
        // Invite has already been used
        tracing::warn!(
            jti = %invite.jti,
            "Invite already used (replay attack detected)"
        );
        return Err(AppError::InviteAlreadyUsed.into());
    }

    tracing::info!(
        jti = %invite.jti,
        creator_user_id = %creator_user_id,
        accepter_user_id = %input.accepter_user_id,
        "Invite accepted and burned"
    );

    // 4. Establish mutual contact (TODO: implement Signal Protocol prekey exchange)
    // For now, just return success

    Ok(AcceptInviteOutput {
        user_id: creator_user_id.to_string(),
        device_id: invite.device_id.clone(),
        server: invite.server.clone(),
        message: format!("Successfully added user {}", creator_user_id),
    })
}

pub struct RevokeInviteInput {
    pub user_id: Uuid,
    pub jti: String,
}

pub struct RevokeInviteOutput {
    pub success: bool,
    pub message: String,
}

/// Revoke an invite token (marks as used to prevent acceptance)
pub async fn revoke_invite(
    context: &InviteServiceContext,
    input: RevokeInviteInput,
) -> Result<RevokeInviteOutput> {
    let jti_uuid = Uuid::parse_str(&input.jti).context("Invalid jti UUID")?;

    // Mark invite as used (revoked) by inserting into used_invites
    let revoke_result = sqlx::query!(
        r#"
        INSERT INTO used_invites (jti, user_id, device_id, expires_at)
        VALUES ($1, $2, NULL, NOW() + INTERVAL '180 seconds')
        ON CONFLICT (jti) DO NOTHING
        RETURNING jti
        "#,
        jti_uuid,
        input.user_id,
    )
    .fetch_optional(&*context.db_pool)
    .await
    .context("Failed to revoke invite")?;

    if revoke_result.is_some() {
        tracing::info!(
            jti = %input.jti,
            user_id = %input.user_id,
            "Invite revoked successfully"
        );
        Ok(RevokeInviteOutput {
            success: true,
            message: "Invite revoked".to_string(),
        })
    } else {
        tracing::warn!(
            jti = %input.jti,
            user_id = %input.user_id,
            "Invite not found or already used"
        );
        Ok(RevokeInviteOutput {
            success: false,
            message: "Invite not found or already used".to_string(),
        })
    }
}

pub struct ListInvitesInput {
    #[allow(dead_code)]
    pub user_id: Uuid,
    #[allow(dead_code)]
    pub limit: Option<i32>,
    #[allow(dead_code)]
    pub include_expired: bool,
}

pub struct InviteInfo {
    pub jti: String,
    pub user_id: String,
    pub device_id: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub used: bool,
    pub used_by: Option<String>,
    pub used_at: Option<i64>,
}

pub struct ListInvitesOutput {
    pub invites: Vec<InviteInfo>,
}

/// List active invites for a user
///
/// Note: This is a simplified implementation that returns empty list.
/// Full implementation would require storing invite metadata in database.
/// Currently, we only track used invites in `used_invites` table.
///
/// For production, consider:
/// 1. Create `invites` table with (jti, user_id, device_id, created_at, expires_at)
/// 2. LEFT JOIN with `used_invites` to check usage status
/// 3. Add pagination support
pub async fn list_invites(
    _context: &InviteServiceContext,
    _input: ListInvitesInput,
) -> Result<ListInvitesOutput> {
    // TODO: Implement invite listing once we have invites table
    // For now, return empty list
    tracing::debug!("ListInvites called - returning empty list (not implemented)");

    Ok(ListInvitesOutput { invites: vec![] })
}
