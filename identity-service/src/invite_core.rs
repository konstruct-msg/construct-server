use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uuid::Uuid;

use construct_server_shared::{
    AppError,
    db::{self as construct_db, DbPool},
};
use crypto_agility::{
    INVITE_BURN_RETENTION_SECONDS, INVITE_TTL_SECONDS, InviteToken, InviteValidationError,
};

use crate::context::IdentityServiceContext;

#[derive(Debug)]
pub enum InviteSignatureError {
    DeviceNotFound,
    InvalidVerifyingKey(String),
    InvalidSignature(String),
    VerificationFailed,
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

pub async fn verify_invite_signature(
    pool: &DbPool,
    invite: &InviteToken,
) -> Result<(), InviteSignatureError> {
    let verifying_key_bytes = if invite.v >= 2 {
        let device_id = invite
            .device_id
            .as_ref()
            .ok_or(InviteSignatureError::InvalidSignature(
                "v2/v3 invite missing device_id".to_string(),
            ))?;

        let device = construct_db::get_device_by_id(pool, device_id)
            .await
            .map_err(|e| InviteSignatureError::DatabaseError(e.to_string()))?
            .ok_or(InviteSignatureError::DeviceNotFound)?;

        device.verifying_key
    } else {
        let devices = construct_db::get_devices_by_user_id(pool, &invite.uuid)
            .await
            .map_err(|e| InviteSignatureError::DatabaseError(e.to_string()))?;

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
    let canonical = invite
        .canonical_string()
        .map_err(|e| InviteSignatureError::InvalidSignature(format!("canonical string: {e}")))?;

    tracing::debug!(
        canonical_string = %canonical,
        signature_base64 = %invite.sig,
        "Verifying invite signature"
    );

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| {
            tracing::warn!(error = %e, "Invite signature verification FAILED");
            InviteSignatureError::VerificationFailed
        })?;

    tracing::debug!("Invite signature verification SUCCESS");
    Ok(())
}

// GenerateInvite removed (INVITE_LIST_REVOKE_SERVER_SPEC): production clients
// mint+sign on device (v4, INVITE_TTL_SECONDS). A server issuer with a different
// TTL was a second parallel invite system by accretion — not allowed.

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

pub async fn accept_invite(
    context: &IdentityServiceContext,
    input: AcceptInviteInput,
) -> Result<AcceptInviteOutput> {
    let invite = input.invite;

    if let Err(e) = invite.validate_with_expiry(INVITE_TTL_SECONDS) {
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
        canonical = ?invite.canonical_string().ok(),
        "Processing invite"
    );

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

    let jti_uuid = invite.jti;
    let creator_user_id = invite.uuid;

    let burned = construct_db::burn_used_invite(
        &context.db_pool,
        &jti_uuid,
        &creator_user_id,
        invite.device_id.as_deref(),
        INVITE_BURN_RETENTION_SECONDS,
    )
    .await
    .context("Failed to burn invite jti")?;

    if !burned {
        tracing::warn!(jti = %invite.jti, "Invite already used (replay attack detected)");
        return Err(AppError::InviteAlreadyUsed.into());
    }

    tracing::info!(
        jti = %invite.jti,
        creator_user_id = %creator_user_id,
        accepter_user_id = %input.accepter_user_id,
        "Invite accepted and burned"
    );

    let secret = &context.config.security.contact_hmac_secret;
    let accepter_hmac = construct_db::contact_link_hmac(secret, &input.accepter_user_id);
    let creator_hmac = construct_db::contact_link_hmac(secret, &creator_user_id);

    construct_db::add_contact_link(&context.db_pool, &accepter_hmac, &creator_hmac)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store contact link (accepter→creator)");
            AppError::Unknown(e)
        })?;
    construct_db::add_contact_link(&context.db_pool, &creator_hmac, &accepter_hmac)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store contact link (creator→accepter)");
            AppError::Unknown(e)
        })?;

    tracing::info!(
        jti = %invite.jti,
        accepter = %input.accepter_user_id,
        creator  = %creator_user_id,
        "Mutual contact links established"
    );

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

/// Pre-burn `jti` so a still-valid invite cannot be redeemed.
///
/// Contract pinned for clients (INVITE_LIST_REVOKE_SERVER_SPEC §2):
/// - first burn of this jti → `success: true`
/// - already burned (redeemed or revoked) → `success: false` + message
///   (normal outcome, **not** an Err — UI shows "already used")
/// - DB failure → `Err` → gRPC `Status::internal` (retryable transport/server)
///
/// No issuer ownership check and no issuance table: jti is client-random and
/// unknown until redeem/revoke. Do not reintroduce ListInvites-by-issuance.
pub async fn revoke_invite(
    context: &IdentityServiceContext,
    input: RevokeInviteInput,
) -> Result<RevokeInviteOutput> {
    let jti_uuid = Uuid::parse_str(&input.jti).context("Invalid jti UUID")?;

    let revoked =
        // Revocation must outlive the invite it revokes. This was 180s against a
        // 300s TTL, so an invite revoked at t+10s came back to life at t+190s —
        // the row that says "dead" expired while the invite was still valid.
        // Deriving both from one constant is what stops that from recurring.
        construct_db::burn_used_invite(
            &context.db_pool,
            &jti_uuid,
            &input.user_id,
            None,
            INVITE_BURN_RETENTION_SECONDS,
        )
        .await
        .context("Failed to revoke invite")?;

    if revoked {
        tracing::info!(jti = %input.jti, user_id = %input.user_id, "Invite revoked");
        Ok(RevokeInviteOutput {
            success: true,
            message: "Invite revoked".to_string(),
        })
    } else {
        tracing::warn!(jti = %input.jti, user_id = %input.user_id, "Invite not found or already used");
        Ok(RevokeInviteOutput {
            success: false,
            message: "Invite not found or already used".to_string(),
        })
    }
}

// ListInvites removed: issuance is not recorded server-side. A successful empty
// list was indistinguishable from "user has no invites" and invited clients to
// build a false server-backed list. Clients list from a local mint journal.
