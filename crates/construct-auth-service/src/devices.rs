// ============================================================================
// Device Registration Routes - Passwordless Authentication
// ============================================================================
//
// Endpoints:
// - POST /api/v1/auth/register-device - Register new device (passwordless)
// - POST /api/v1/auth/device - Authenticate existing device
// - GET /api/v1/users/:device_id/profile - Get device profile (public)
//
// Security:
// - Argon2id PoW validation (anti-spam)
// - Unique device_id enforcement
// - Ed25519 signature verification
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};
use std::sync::Arc;

use construct_context::AppContext;
use construct_crypto::hash_username;
use construct_db::{self as db, CreateDeviceData};
use construct_error::{AppError, DeviceRefusal};

// ============================================================================
// Request/Response Types
// ============================================================================

/// Binary public keys received from the gRPC path as proto `bytes` fields.
#[derive(Debug, Clone)]
pub struct DevicePublicKeysBinary {
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    /// Crypto suite identifier (e.g., "Curve25519+Ed25519")
    pub crypto_suite: String,

    /// Client capability for the post-quantum ratchet.
    pub supports_pq_ratchet: bool,
}

/// Proof of Work solution
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PowSolution {
    /// Original challenge from GET /challenge
    pub challenge: String,

    /// Nonce that solves the puzzle
    pub nonce: u64,

    /// Argon2id hash (hex-encoded)
    pub hash: String,
}

/// Response for successful device registration
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    /// User ID (UUID, same for all user's devices)
    #[serde(rename = "userId")]
    pub user_id: String,

    /// Access token (PASETO v4.public)
    #[serde(rename = "accessToken")]
    pub access_token: String,

    /// Refresh token (PASETO v4.public)
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    /// Token expiration time in seconds
    #[serde(rename = "expiresIn")]
    pub expires_in: u64,
}

/// Longest accepted suite name. The one clients send is 18 bytes.
const MAX_CRYPTO_SUITE_LEN: usize = 64;

// ============================================================================
// Registration Endpoint
// ============================================================================

/// What the caller is told when a unique index refused the new account, if one did.
fn registration_conflict(e: &anyhow::Error) -> Option<&'static str> {
    // `insert_device_impl` names this one itself.
    if e.to_string().contains("IDENTITY_KEY_CONFLICT") {
        return Some("Identity key already registered by another device");
    }
    let sqlx::Error::Database(db_err) = e.downcast_ref::<sqlx::Error>()? else {
        return None;
    };
    if !db_err.is_unique_violation() {
        return None;
    }
    match db_err.constraint() {
        Some("idx_users_username_hash") => Some("Username is already taken"),
        Some("devices_pkey") => Some("Device already exists"),
        _ => None,
    }
}

/// Core registration logic with binary key inputs.
///
/// Called by the gRPC adapter; proto `bytes` fields are already `Vec<u8>`.
#[allow(clippy::too_many_arguments)]
pub async fn register_device_core(
    app_context: Arc<AppContext>,
    username: Option<String>,
    device_id: String,
    keys: DevicePublicKeysBinary,
    pow_solution: PowSolution,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    tracing::info!(
        device_id = %device_id,
        has_username = username.is_some(),
        "Device registration attempt"
    );

    // 1. Validate device_id format (32 lowercase hex characters = 16 bytes)
    if device_id.len() != 32 {
        return Err(AppError::Validation(
            "device_id must be exactly 32 characters (16 bytes hex)".to_string(),
        ));
    }

    if !device_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "device_id must be hex characters (0-9a-f)".to_string(),
        ));
    }

    if device_id.to_lowercase() != device_id {
        return Err(AppError::Validation(
            "device_id must be lowercase".to_string(),
        ));
    }

    // 2. Validate and normalize username (optional)
    let normalized_username = username.as_ref().map(|u| u.to_lowercase());

    if let Some(ref uname) = normalized_username {
        if uname.len() < 3 || uname.len() > 20 {
            return Err(AppError::Validation(
                "username must be 3-20 characters".to_string(),
            ));
        }

        if !uname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(AppError::Validation(
                "username can only contain letters, numbers, and underscores".to_string(),
            ));
        }
    }

    // 3. Validate public keys (already decoded from base64)
    let verifying_key = keys.verifying_key;

    if verifying_key.len() != 32 {
        return Err(AppError::Validation(
            "verifying_key must be exactly 32 bytes (Ed25519)".to_string(),
        ));
    }

    let identity_public = keys.identity_public;
    let signed_prekey_public = keys.signed_prekey_public;
    let signed_prekey_signature = keys.signed_prekey_signature;

    // Both are X25519 keys peers will be handed; without this a caller stores any size.
    if identity_public.len() != 32 {
        return Err(AppError::Validation(
            "identity_public must be exactly 32 bytes (X25519)".to_string(),
        ));
    }

    if signed_prekey_public.len() != 32 {
        return Err(AppError::Validation(
            "signed_prekey_public must be exactly 32 bytes (X25519)".to_string(),
        ));
    }

    if keys.crypto_suite.len() > MAX_CRYPTO_SUITE_LEN {
        return Err(AppError::Validation(format!(
            "crypto_suite must be at most {MAX_CRYPTO_SUITE_LEN} bytes"
        )));
    }

    if signed_prekey_signature.len() != 64 {
        return Err(AppError::Validation(
            "signed_prekey_signature must be exactly 64 bytes (Ed25519 signature)".to_string(),
        ));
    }

    // Cryptographically verify signed_prekey_signature.
    {
        let vk_bytes: [u8; 32] = verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| AppError::Validation("verifying_key must be 32 bytes".to_string()))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| {
            AppError::Validation("verifying_key is not a valid Ed25519 key".to_string())
        })?;
        let sig_bytes: [u8; 64] = signed_prekey_signature.as_slice().try_into().map_err(|_| {
            AppError::Validation(
                "signed_prekey_signature must be exactly 64 bytes (Ed25519 signature)".to_string(),
            )
        })?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        let mut msg = Vec::with_capacity(18 + signed_prekey_public.len());
        msg.extend_from_slice(b"KonstruktX3DH-v1");
        msg.extend_from_slice(&[0x00, 0x01]);
        msg.extend_from_slice(&signed_prekey_public);
        vk.verify(&msg, &sig).map_err(|_| {
            AppError::Validation("signed_prekey_signature verification failed".to_string())
        })?;
    }

    // 4. Verify device_id matches identity_public (SHA256 first 16 bytes = 32 hex chars)
    let computed_device_id = {
        let hash = Sha256::digest(&identity_public);
        hex::encode(&hash[0..16])
    };

    if computed_device_id != device_id {
        tracing::warn!(
            provided = %device_id,
            computed = %computed_device_id,
            "device_id mismatch with identity_public"
        );
        return Err(AppError::Validation(
            "device_id must be SHA256(identity_public)[0..16]".to_string(),
        ));
    }

    // 5. Check if device_id already exists
    if db::device_exists(&app_context.db_pool, &device_id)
        .await
        .unwrap_or(false)
    {
        tracing::warn!(
            device_id = %device_id,
            "Attempted to register existing device_id"
        );
        return Err(AppError::Conflict("Device already exists".to_string()));
    }

    // 6. Verify PoW solution
    let pow_challenge = app_context
        .queue
        .lock()
        .await
        .get_pow_challenge(&pow_solution.challenge)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch PoW challenge: {}", e)))?
        .ok_or_else(|| AppError::Validation("Invalid or expired PoW challenge".to_string()))?;

    if pow_challenge.expires_at < chrono::Utc::now() {
        return Err(AppError::Validation("PoW challenge expired".to_string()));
    }

    if !construct_pow::verify_pow_solution(
        &pow_solution.challenge,
        pow_solution.nonce,
        &pow_solution.hash,
        pow_challenge.difficulty as u32,
    ) {
        tracing::warn!(
            device_id = %device_id,
            challenge = %pow_solution.challenge,
            nonce = %pow_solution.nonce,
            "Invalid PoW solution"
        );
        return Err(AppError::Validation("Invalid PoW solution".to_string()));
    }

    // The solution was read above and is spent here, by whoever Redis hands the record to.
    app_context
        .queue
        .lock()
        .await
        .consume_pow_challenge(&pow_solution.challenge)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to consume PoW challenge: {}", e)))?
        .filter(|record| !record.used)
        .ok_or_else(|| AppError::Validation("PoW challenge already used".to_string()))?;

    // 7. Create user + device atomically
    let server_hostname = app_context.config.instance_domain.clone();

    let crypto_suites = db::crypto_suites_json(&keys.crypto_suite);

    let device_data = CreateDeviceData {
        device_id: device_id.clone(),
        server_hostname: server_hostname.clone(),
        verifying_key,
        identity_public,
        signed_prekey_public,
        signed_prekey_signature,
        crypto_suites,
        supports_pq_ratchet: keys.supports_pq_ratchet,
    };

    let username_hash_opt: Option<Vec<u8>> = normalized_username
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|uname| {
            let secret = &app_context.config.security.username_hmac_secret;
            hash_username(secret, uname)
        });

    if let Some(ref hash) = username_hash_opt
        && let Ok(Some(_existing_user)) =
            db::get_user_by_username_hash(&app_context.db_pool, hash).await
    {
        tracing::warn!(
            device_id = %device_id,
            "Registration failed: username already taken"
        );
        return Err(AppError::Conflict("Username is already taken".to_string()));
    }

    let (user, _device) = db::create_user_with_first_device(
        &app_context.db_pool,
        username_hash_opt.as_deref(),
        device_data,
    )
    .await
    .map_err(|e| {
        // The checks above read; the unique indexes decide. Two registrations of one name or
        // one device that pass the reads together meet here.
        if let Some(conflict) = registration_conflict(&e) {
            tracing::warn!(device_id = %device_id, conflict, "Registration lost a race");
            return AppError::Conflict(conflict.to_string());
        }
        tracing::error!(error = %e, "Failed to create user with device");
        AppError::Unknown(e)
    })?;

    tracing::info!(
        user_id = %user.id,
        device_id = %device_id,
        has_username = user.username_hash.is_some(),
        "User + device registered successfully (passwordless)"
    );

    // 8. Generate tokens with device_id
    let (access_token, _, exp_timestamp) = app_context
        .auth_manager
        .create_token_for_device(&user.id, Some(&device_id))
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (refresh_token, refresh_jti, _) = app_context
        .auth_manager
        .create_refresh_token_for_device(&user.id, Some(&device_id))
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds =
            app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

        if let Err(e) = queue
            .store_refresh_token(&refresh_jti, &user.id.to_string(), refresh_ttl_seconds)
            .await
        {
            tracing::error!(error = %e, "Failed to store refresh token");
        }
    }

    let now = chrono::Utc::now().timestamp();
    let expires_in = (exp_timestamp - now) as u64;

    // 9. Return success response with tokens
    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse {
            user_id: user.id.to_string(),
            access_token,
            refresh_token,
            expires_in,
        }),
    ))
}

// ============================================================================
// Device Authentication Endpoint
// ============================================================================

/// Core authentication logic with binary signature.
///
/// Called from:
/// - REST path (via `handlers.rs` which decodes base64 at the JSON boundary)
/// - gRPC path (proto `bytes` field is already `Vec<u8>`)
pub async fn authenticate_device_core(
    app_context: Arc<AppContext>,
    device_id: String,
    timestamp: i64,
    signature: Vec<u8>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    // 1. Validate timestamp (±5 minutes window)
    let now = chrono::Utc::now().timestamp();
    if now.abs_diff(timestamp) > 300 {
        return Err(AppError::validation(
            "Timestamp expired (must be within ±5 minutes)",
        ));
    }

    // 2. Find device in database
    let device = db::get_device_by_id(&app_context.db_pool, &device_id)
        .await
        .map_err(|e| AppError::internal(format!("Database error: {}", e)))?
        .ok_or(AppError::DeviceRefused(DeviceRefusal::NotFound))?;

    // 3. Verify device is active
    if !device.is_active {
        return Err(AppError::DeviceRefused(DeviceRefusal::Removed));
    }

    // 4. Verify Ed25519 signature
    let message = format!("{}{}", device_id, timestamp);
    let message_bytes = message.as_bytes();

    let signature_bytes = signature;

    if signature_bytes.len() != 64 {
        return Err(AppError::validation(
            "Invalid signature length (expected 64 bytes)",
        ));
    }

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(
        device
            .verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| AppError::internal("Invalid verifying_key format"))?,
    )
    .map_err(|_| AppError::internal("Invalid verifying_key"))?;

    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| AppError::validation("Invalid signature"))?,
    );

    if verifying_key.verify(message_bytes, &signature).is_err() {
        // Counted, never per device: the signature did not verify, so nothing says the caller
        // has anything to do with the device they named.
        construct_metrics::AUTH_FAILURES_TOTAL
            .with_label_values(&["device_signature"])
            .inc();
        return Err(AppError::auth("Invalid signature"));
    }

    // 5. Get user_id from device
    let user_id = device
        .user_id
        .ok_or_else(|| AppError::internal("Device has no user_id"))?;

    // 6. Generate tokens with device_id
    let (access_token, _, exp_timestamp) = app_context
        .auth_manager
        .create_token_for_device(&user_id, Some(&device.device_id))
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (refresh_token, refresh_jti, _) = app_context
        .auth_manager
        .create_refresh_token_for_device(&user_id, Some(&device.device_id))
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds =
            app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

        if let Err(e) = queue
            .store_refresh_token(&refresh_jti, &user_id.to_string(), refresh_ttl_seconds)
            .await
        {
            tracing::error!(error = %e, "Failed to store refresh token");
        }
    }

    let expires_in = (exp_timestamp - now) as u64;

    tracing::info!(
        device_id = %device_id,
        user_id = %user_id,
        "Device authenticated successfully"
    );

    // 7. Return tokens
    Ok((
        StatusCode::OK,
        Json(RegisterDeviceResponse {
            user_id: user_id.to_string(),
            access_token,
            refresh_token,
            expires_in,
        }),
    ))
}

// ============================================================================
// Profile Endpoints
// ============================================================================

// ============================================================================
// TODO: Add authenticated endpoints
// ============================================================================
// - PATCH /api/v1/users/me/profile - Update profile
// - GET /api/v1/users/me/devices - List user's devices
// - PATCH /api/v1/users/me/devices/:device_id/public-key - Update keys
//
// These will require DeviceAuth extractor (X-Device-ID, X-Signature headers)

// ============================================================================
// PoW Challenge Endpoint
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: i64, // Unix timestamp
}

/// Issue a proof-of-work challenge for registration.
///
/// The difficulty is the same for everyone and no address is read: a relay front, the QUIC
/// gateway and a carrier NAT each put many people behind one address, so a rule by address
/// refuses the people it should serve. Volume is watched, not limited
/// (`construct_pow_challenges_issued_total`, `construct_account_registrations_total`).
pub async fn get_pow_challenge(
    State(app_context): State<Arc<AppContext>>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let difficulty = app_context.config.security.pow_difficulty;
    let challenge = construct_pow::generate_challenge();
    let ttl_seconds = 600; // 10 minutes
    let pow_challenge = app_context
        .queue
        .lock()
        .await
        .create_pow_challenge(&challenge, difficulty as i16, ttl_seconds)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create challenge: {}", e)))?;
    construct_metrics::POW_CHALLENGES_ISSUED_TOTAL.inc();

    Ok(Json(ChallengeResponse {
        challenge,
        difficulty,
        expires_at: pow_challenge.expires_at.timestamp(),
    }))
}
