use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uuid::Uuid;

use construct_crypto::hmac_sha256;
use construct_server_shared::{
    AppError,
    db::{self as construct_db, DbPool},
};
use crypto_agility::{InviteToken, InviteValidationError};

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
    let canonical = invite.canonical_string();

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

pub async fn generate_invite(
    context: &IdentityServiceContext,
    input: GenerateInviteInput,
) -> Result<GenerateInviteOutput> {
    let ttl_seconds = input.ttl_seconds.unwrap_or(300);
    if !(60..=3600).contains(&ttl_seconds) {
        return Err(
            AppError::Validation("TTL must be between 60 and 3600 seconds".to_string()).into(),
        );
    }

    let jti = Uuid::new_v4();
    let server = context.config.instance_domain.clone();
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

pub async fn accept_invite(
    context: &IdentityServiceContext,
    input: AcceptInviteInput,
) -> Result<AcceptInviteOutput> {
    let invite = input.invite;

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
        600,
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
    let accepter_hmac = hmac_sha256(secret, input.accepter_user_id.to_string().as_bytes());
    let creator_hmac = hmac_sha256(secret, creator_user_id.to_string().as_bytes());

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

pub async fn revoke_invite(
    context: &IdentityServiceContext,
    input: RevokeInviteInput,
) -> Result<RevokeInviteOutput> {
    let jti_uuid = Uuid::parse_str(&input.jti).context("Invalid jti UUID")?;

    let revoked =
        construct_db::burn_used_invite(&context.db_pool, &jti_uuid, &input.user_id, None, 180)
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

pub async fn list_invites(
    _context: &IdentityServiceContext,
    _input: ListInvitesInput,
) -> Result<ListInvitesOutput> {
    Ok(ListInvitesOutput { invites: vec![] })
}
