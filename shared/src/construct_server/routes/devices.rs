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
// - Rate limiting per IP (5 challenges/hour)
// - Unique device_id enforcement
// - Ed25519 signature verification
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::context::AppContext;
use crate::db::{self, CreateDeviceData};
use construct_error::AppError;

// ============================================================================
// IP Extraction & Adaptive PoW
// ============================================================================

/// Extract client IP from X-Forwarded-For / X-Real-IP headers (set by Traefik/Envoy).
/// Falls back to "unknown" if not present.
pub fn extract_client_ip(headers: &HeaderMap) -> String {
    // X-Forwarded-For: client, proxy1, proxy2 — take first (real client)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            let ip = val.split(',').next().unwrap_or("").trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    // X-Real-IP set by Envoy/nginx
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(val) = real_ip.to_str() {
            return val.trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Adaptive PoW parameters based on per-IP request count.
///
/// As an IP makes more registration attempts, difficulty increases and
/// a Retry-After delay is added — doubling the cost of each successive attempt.
///
/// Difficulty formula: base + floor(log2(count / threshold + 1)) * step
/// Retry-After formula: base_delay_secs * 2^floor(count / threshold)  (capped at 3600s)
pub struct AdaptivePowParams {
    pub difficulty: u32,
    /// Seconds client should wait before retrying (0 = no delay)
    pub retry_after_secs: u64,
}

pub fn adaptive_pow_params(base_difficulty: u32, count: i64) -> AdaptivePowParams {
    // Each tier = 10 requests from same IP within the window
    const TIER_SIZE: i64 = 10;
    const DIFFICULTY_STEP: u32 = 2;
    const MAX_DIFFICULTY: u32 = 20;
    const BASE_RETRY_SECS: u64 = 30;
    const MAX_RETRY_SECS: u64 = 3600;

    let tier = (count / TIER_SIZE) as u32;

    let difficulty = (base_difficulty + tier * DIFFICULTY_STEP).min(MAX_DIFFICULTY);

    // Exponential backoff starts at tier 2 (20+ requests/hour from same IP)
    let retry_after_secs = if tier >= 2 {
        (BASE_RETRY_SECS * (1u64 << (tier - 2).min(6))).min(MAX_RETRY_SECS)
    } else {
        0
    };

    AdaptivePowParams {
        difficulty,
        retry_after_secs,
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Public keys for device registration
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicKeys {
    /// Ed25519 verifying key for request signature verification (base64, 32 bytes)
    pub verifying_key: String,

    /// Identity public key for E2EE (base64, varies by suite)
    pub identity_public: String,

    /// Signed prekey public for Double Ratchet (base64)
    pub signed_prekey_public: String,

    /// Ed25519 signature of (prologue || signed_prekey_public) (base64, 64 bytes)
    /// Required for X3DH session initialization
    /// Prologue = "KonstruktX3DH-v1" || suite_id (2 bytes BE)
    pub signed_prekey_signature: String,

    /// Crypto suite identifier (e.g., "Curve25519+Ed25519", "ML-KEM-768+Ed25519")
    #[serde(default = "default_suite_id")]
    pub suite_id: String,
}

fn default_suite_id() -> String {
    "Curve25519+Ed25519".to_string()
}

/// Request to register a new device (privacy-focused)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    /// Username (optional, for search/discovery)
    /// None or empty string = maximum privacy (QR/invite only)
    /// Some(username) = searchable via @username
    pub username: Option<String>,

    /// Device ID (client-computed: SHA256(identity_public)[0..16])
    pub device_id: String,

    /// Public keys for authentication and E2EE
    pub public_keys: DevicePublicKeys,

    /// Proof of Work solution
    pub pow_solution: PowSolution,
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

    /// Access token (JWT, 1 hour TTL)
    #[serde(rename = "accessToken")]
    pub access_token: String,

    /// Refresh token (JWT, 30 days TTL)
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    /// Token expiration time in seconds
    #[serde(rename = "expiresIn")]
    pub expires_in: u64,
}

/// Public profile response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProfileResponse {
    pub device_id: String,
    pub server: String,
    pub registered_at: String,

    // Public keys for establishing E2EE
    pub public_keys: DevicePublicKeys,
}

/// Request to update user profile
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub bio: Option<String>,
}

// ============================================================================
// Registration Endpoint
// ============================================================================

/// POST /api/v1/register/v2
///
/// Register a new device with passwordless authentication.
///
/// Security:
/// - Validates device_id format (16 hex chars)
/// - Checks device_id uniqueness
/// - Validates public keys (base64, correct lengths)
/// - PoW validation (Argon2id with 8 leading zeros)
/// - Rate limiting: Configurable via MAX_REGISTRATIONS_PER_HOUR (default: 3)
pub async fn register_device_v2(
    State(app_context): State<Arc<AppContext>>,
    headers: HeaderMap,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    let client_ip = extract_client_ip(&headers);

    tracing::info!(
        device_id = %request.device_id,
        username = ?request.username,
        client_ip = %client_ip,
        "Device registration attempt (username will be normalized to lowercase)"
    );

    // 0. Check rate limiting + adaptive PoW difficulty
    let max_registrations = app_context.config.security.max_registrations_per_hour;

    if max_registrations > 0 {
        let count = crate::db::count_registrations_by_ip(&app_context.db_pool, &client_ip, 60)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to check rate limit: {}", e)))?;

        if count >= max_registrations as i64 {
            let params = adaptive_pow_params(app_context.config.security.pow_difficulty, count);
            let mut err = AppError::Validation(format!(
                "Rate limit exceeded: max {} registrations per hour from this IP",
                max_registrations
            ));
            if params.retry_after_secs > 0 {
                err = AppError::TooManyRequests(format!(
                    "Too many registrations from this IP. Retry after {}s",
                    params.retry_after_secs
                ));
            }
            tracing::warn!(
                target: "audit",
                event_type = "REGISTRATION_RATE_LIMIT",
                client_ip = %client_ip,
                count = count,
                retry_after_secs = params.retry_after_secs,
                "Registration rate limit exceeded"
            );
            return Err(err);
        }
    }

    // 1. Validate device_id format (32 lowercase hex characters = 16 bytes)
    if request.device_id.len() != 32 {
        return Err(AppError::Validation(
            "device_id must be exactly 32 characters (16 bytes hex)".to_string(),
        ));
    }

    if !request.device_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(
            "device_id must be hex characters (0-9a-f)".to_string(),
        ));
    }

    if request.device_id.to_lowercase() != request.device_id {
        return Err(AppError::Validation(
            "device_id must be lowercase".to_string(),
        ));
    }

    // 2. Validate and normalize username (optional)
    // - Convert to lowercase (users can type "Ninshi" but it stores as "ninshi")
    // - Must be 3-20 chars, alphanumeric + underscore only
    let normalized_username = request.username.as_ref().map(|u| u.to_lowercase());

    if let Some(ref username) = normalized_username {
        if username.len() < 3 || username.len() > 20 {
            return Err(AppError::Validation(
                "username must be 3-20 characters".to_string(),
            ));
        }

        if !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(AppError::Validation(
                "username can only contain letters, numbers, and underscores".to_string(),
            ));
        }
    }

    // 3. Decode and validate public keys
    let verifying_key = BASE64
        .decode(&request.public_keys.verifying_key)
        .map_err(|_| AppError::Validation("verifying_key must be valid base64".to_string()))?;

    if verifying_key.len() != 32 {
        return Err(AppError::Validation(
            "verifying_key must be exactly 32 bytes (Ed25519)".to_string(),
        ));
    }

    let identity_public = BASE64
        .decode(&request.public_keys.identity_public)
        .map_err(|_| AppError::Validation("identity_public must be valid base64".to_string()))?;

    let signed_prekey_public = BASE64
        .decode(&request.public_keys.signed_prekey_public)
        .map_err(|_| {
            AppError::Validation("signed_prekey_public must be valid base64".to_string())
        })?;

    // Decode and validate signed_prekey_signature (Ed25519, 64 bytes)
    let signed_prekey_signature = BASE64
        .decode(&request.public_keys.signed_prekey_signature)
        .map_err(|_| {
            AppError::Validation("signed_prekey_signature must be valid base64".to_string())
        })?;

    if signed_prekey_signature.len() != 64 {
        return Err(AppError::Validation(
            "signed_prekey_signature must be exactly 64 bytes (Ed25519 signature)".to_string(),
        ));
    }

    // 4. Verify device_id matches identity_public (SHA256 first 16 bytes = 32 hex chars)
    let computed_device_id = {
        let hash = Sha256::digest(&identity_public);
        hex::encode(&hash[0..16]) // First 16 bytes = 32 hex chars
    };

    if computed_device_id != request.device_id {
        tracing::warn!(
            provided = %request.device_id,
            computed = %computed_device_id,
            "device_id mismatch with identity_public"
        );
        return Err(AppError::Validation(
            "device_id must be SHA256(identity_public)[0..16]".to_string(),
        ));
    }

    // 5. Check if device_id already exists
    if db::device_exists(&app_context.db_pool, &request.device_id)
        .await
        .unwrap_or(false)
    {
        tracing::warn!(
            device_id = %request.device_id,
            "Attempted to register existing device_id"
        );
        return Err(AppError::Conflict("Device already exists".to_string()));
    }

    // 6. Verify PoW solution
    let pow_challenge =
        crate::db::get_pow_challenge(&app_context.db_pool, &request.pow_solution.challenge)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to fetch PoW challenge: {}", e)))?
            .ok_or_else(|| AppError::Validation("Invalid or expired PoW challenge".to_string()))?;

    // Check challenge not expired
    if pow_challenge.expires_at < chrono::Utc::now() {
        return Err(AppError::Validation("PoW challenge expired".to_string()));
    }

    // Check challenge not already used
    if pow_challenge.used {
        return Err(AppError::Validation(
            "PoW challenge already used".to_string(),
        ));
    }

    // Verify PoW solution
    if !crate::pow::verify_pow_solution(
        &request.pow_solution.challenge,
        request.pow_solution.nonce,
        &request.pow_solution.hash,
        pow_challenge.difficulty as u32,
    ) {
        tracing::warn!(
            device_id = %request.device_id,
            challenge = %request.pow_solution.challenge,
            nonce = %request.pow_solution.nonce,
            "Invalid PoW solution"
        );
        return Err(AppError::Validation("Invalid PoW solution".to_string()));
    }

    // Mark challenge as used (prevent reuse)
    crate::db::mark_challenge_used(&app_context.db_pool, &request.pow_solution.challenge)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to mark challenge as used: {}", e)))?;

    // 7. Create user + device atomically
    let server_hostname = app_context.config.instance_domain.clone();

    // Convert suite_id to crypto_suites JSONB format
    let crypto_suites = format!(r#"["{}"]"#, request.public_keys.suite_id);

    let device_data = CreateDeviceData {
        device_id: request.device_id.clone(),
        server_hostname: server_hostname.clone(),
        verifying_key,
        identity_public,
        signed_prekey_public,
        signed_prekey_signature,
        crypto_suites,
    };

    // Convert normalized username: Option<String> to Option<&str> for database
    // None or empty string = maximum privacy (no username)
    let username_opt = normalized_username
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| s.as_str());

    // Check if username already exists (before attempting DB insert)
    if let Some(username) = username_opt
        && let Ok(Some(_existing_user)) =
            db::get_user_by_username(&app_context.db_pool, username).await
    {
        tracing::warn!(
            username = username,
            device_id = %request.device_id,
            "Registration failed: username already taken"
        );
        return Err(AppError::Conflict(format!(
            "Username '{}' is already taken",
            username
        )));
    }

    let (user, _device) =
        db::create_user_with_first_device(&app_context.db_pool, username_opt, device_data)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create user with device");
                AppError::Unknown(e)
            })?;

    tracing::info!(
        user_id = %user.id,
        device_id = %request.device_id,
        username = ?user.username,
        "User + device registered successfully (passwordless)"
    );

    // 8. Generate JWT tokens
    let (access_token, _, exp_timestamp) = app_context
        .auth_manager
        .create_token(&user.id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (refresh_token, refresh_jti, _) = app_context
        .auth_manager
        .create_refresh_token(&user.id)
        .map_err(|e| {
        tracing::error!(error = %e, "Failed to create refresh token");
        AppError::Unknown(e)
    })?;

    // Store refresh token in Redis
    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds =
            app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

        if let Err(e) = queue
            .store_refresh_token(&refresh_jti, &user.id.to_string(), refresh_ttl_seconds)
            .await
        {
            tracing::error!(error = %e, "Failed to store refresh token");
            // Continue anyway - token was created, just not tracked
        }
    }

    let now = chrono::Utc::now().timestamp();
    let expires_in = (exp_timestamp - now) as u64;

    // 9. Return success response with JWT tokens
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

/// POST /api/v1/auth/device
///
/// Authenticate existing device using Ed25519 signature.
///
/// Request:
/// ```json
/// {
///   "device_id": "2a68bbf6425855903b7ba45aa570f91a",
///   "timestamp": 1738700000,
///   "signature": "base64_ed25519_signature"
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateDeviceRequest {
    pub device_id: String,
    pub timestamp: i64,
    pub signature: String, // base64-encoded Ed25519 signature
}

pub async fn authenticate_device(
    State(app_context): State<Arc<AppContext>>,
    Json(request): Json<AuthenticateDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    // 1. Validate timestamp (±5 minutes window)
    let now = chrono::Utc::now().timestamp();
    let time_diff = (now - request.timestamp).abs();
    if time_diff > 300 {
        return Err(AppError::validation(
            "Timestamp expired (must be within ±5 minutes)",
        ));
    }

    // 1b. Check if this device_id is temporarily blocked (brute force protection)
    {
        let mut queue = app_context.queue.lock().await;
        if let Ok(Some(reason)) = queue.is_user_blocked(&request.device_id).await {
            return Err(AppError::auth(format!(
                "Authentication temporarily blocked: {}",
                reason
            )));
        }
    }

    // 2. Find device in database
    let device = db::get_device_by_id(&app_context.db_pool, &request.device_id)
        .await
        .map_err(|e| AppError::internal(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::auth("Device not found"))?;

    // 3. Verify device is active
    if !device.is_active {
        return Err(AppError::auth("Device is inactive"));
    }

    // 4. Verify Ed25519 signature
    // Message format: "{device_id}{timestamp}"
    let message = format!("{}{}", request.device_id, request.timestamp);
    let message_bytes = message.as_bytes();

    // Decode signature from base64
    let signature_bytes = BASE64
        .decode(&request.signature)
        .map_err(|_| AppError::validation("Invalid signature encoding"))?;

    if signature_bytes.len() != 64 {
        return Err(AppError::validation(
            "Invalid signature length (expected 64 bytes)",
        ));
    }

    // Verify with verifying_key from database
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

    verifying_key
        .verify(message_bytes, &signature)
        .map_err(|_| {
            // Track failed authentication attempts for brute force protection
            let device_id = request.device_id.clone();
            let max_failed = app_context.config.security.max_failed_login_attempts;
            let block_duration = app_context
                .config
                .security
                .rate_limit_block_duration_seconds;
            let queue = app_context.queue.clone();
            tokio::spawn(async move {
                let mut q = queue.lock().await;
                if let Ok(count) = q.increment_failed_login_count(&device_id).await
                    && count >= max_failed
                {
                    let _ = q
                        .block_user_temporarily(
                            &device_id,
                            block_duration,
                            &format!("Too many failed auth attempts ({}/{})", count, max_failed),
                        )
                        .await;
                }
            });
            AppError::auth("Invalid signature")
        })?;

    // Reset failed attempt counter on successful authentication
    {
        let mut queue = app_context.queue.lock().await;
        let _ = queue.reset_failed_login_count(&request.device_id).await;
    }

    // 5. Get user_id from device
    let user_id = device
        .user_id
        .ok_or_else(|| AppError::internal("Device has no user_id"))?;

    // 6. Generate JWT tokens
    let (access_token, _, exp_timestamp) = app_context
        .auth_manager
        .create_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (refresh_token, refresh_jti, _) = app_context
        .auth_manager
        .create_refresh_token(&user_id)
        .map_err(|e| {
        tracing::error!(error = %e, "Failed to create refresh token");
        AppError::Unknown(e)
    })?;

    // Store refresh token in Redis
    {
        let mut queue = app_context.queue.lock().await;
        let refresh_ttl_seconds =
            app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

        if let Err(e) = queue
            .store_refresh_token(&refresh_jti, &user_id.to_string(), refresh_ttl_seconds)
            .await
        {
            tracing::error!(error = %e, "Failed to store refresh token");
            // Continue anyway - token was created, just not tracked
        }
    }

    let expires_in = (exp_timestamp - now) as u64;

    tracing::info!(
        device_id = %request.device_id,
        user_id = %user_id,
        "Device authenticated successfully"
    );

    // 7. Return JWT tokens
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

/// GET /api/v1/users/:device_id/profile
///
/// Get public profile for a device.
///
/// This is a PUBLIC endpoint - no authentication required.
/// Used for looking up users before starting a chat.
pub async fn get_device_profile(
    State(app_context): State<Arc<AppContext>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Fetch device from database
    let device = db::get_device_by_id(&app_context.db_pool, &device_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to fetch device");
            AppError::Unknown(e)
        })?
        .ok_or_else(|| AppError::NotFound("Device not found".to_string()))?;

    let server_hostname = app_context.config.instance_domain.clone();

    // Extract first suite from crypto_suites JSONB array
    let suite_id = device
        .crypto_suites
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("Curve25519+Ed25519")
        .to_string();

    // Return public profile
    // signed_prekey_signature may be None for legacy devices
    let signed_prekey_signature = device
        .signed_prekey_signature
        .as_ref()
        .map(|s| BASE64.encode(s))
        .unwrap_or_else(|| BASE64.encode(vec![0u8; 64]));

    Ok(Json(DeviceProfileResponse {
        device_id: device.device_id,
        server: server_hostname,
        registered_at: device.registered_at.to_rfc3339(),
        public_keys: DevicePublicKeys {
            verifying_key: BASE64.encode(&device.verifying_key),
            identity_public: BASE64.encode(&device.identity_public),
            signed_prekey_public: BASE64.encode(&device.signed_prekey_public),
            signed_prekey_signature,
            suite_id,
        },
    }))
}

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

/// GET /api/v1/register/challenge
///
/// Generate a PoW challenge for registration.
/// Difficulty scales up with request volume from the same IP (adaptive PoW).
/// A Retry-After header is added when the IP is in a higher abuse tier.
///
/// Rate limiting: Configurable via MAX_POW_CHALLENGES_PER_HOUR (default: 5)
pub async fn get_pow_challenge(
    State(app_context): State<Arc<AppContext>>,
    headers: HeaderMap,
) -> Result<(axum::http::HeaderMap, Json<ChallengeResponse>), AppError> {
    let client_ip = extract_client_ip(&headers);

    // 1. Count how many challenges this IP has requested in the last hour
    let max_challenges = app_context.config.security.max_pow_challenges_per_hour;
    let count = if max_challenges > 0 {
        crate::db::count_challenges_by_ip(&app_context.db_pool, &client_ip, 60)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to check rate limit: {}", e)))?
    } else {
        0
    };

    if max_challenges > 0 && count >= max_challenges as i64 {
        tracing::warn!(
            target: "audit",
            event_type = "POW_CHALLENGE_RATE_LIMIT",
            client_ip = %client_ip,
            count = count,
            "PoW challenge rate limit exceeded"
        );
        return Err(AppError::TooManyRequests(format!(
            "Rate limit exceeded: max {} challenges per hour",
            max_challenges
        )));
    }

    // 2. Compute adaptive difficulty + retry-after based on IP request volume
    let base_difficulty = app_context.config.security.pow_difficulty;
    let params = adaptive_pow_params(base_difficulty, count);

    // 3. Generate and store challenge with adaptive difficulty
    let challenge = crate::pow::generate_challenge();
    let ttl_seconds = 600; // 10 minutes
    let pow_challenge = crate::db::create_pow_challenge(
        &app_context.db_pool,
        &challenge,
        params.difficulty as i16,
        Some(&client_ip),
        ttl_seconds,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create challenge: {}", e)))?;

    tracing::info!(
        challenge = %challenge,
        difficulty = %params.difficulty,
        retry_after_secs = %params.retry_after_secs,
        client_ip = %client_ip,
        "PoW challenge generated (adaptive)"
    );

    // 4. Build response headers — include Retry-After if IP is in abuse tier
    let mut resp_headers = axum::http::HeaderMap::new();
    if params.retry_after_secs > 0 {
        resp_headers.insert(
            axum::http::header::RETRY_AFTER,
            params.retry_after_secs.to_string().parse().unwrap(),
        );
    }

    Ok((
        resp_headers,
        Json(ChallengeResponse {
            challenge,
            difficulty: params.difficulty,
            expires_at: pow_challenge.expires_at.timestamp(),
        }),
    ))
}

#[cfg(test)]
mod adaptive_pow_tests {
    use super::adaptive_pow_params;

    #[test]
    fn test_base_tier_no_throttle() {
        let p = adaptive_pow_params(8, 0);
        assert_eq!(p.difficulty, 8);
        assert_eq!(p.retry_after_secs, 0);

        let p = adaptive_pow_params(8, 9);
        assert_eq!(p.difficulty, 8);
        assert_eq!(p.retry_after_secs, 0);
    }

    #[test]
    fn test_tier1_difficulty_increases() {
        let p = adaptive_pow_params(8, 10);
        assert_eq!(p.difficulty, 10);
        assert_eq!(p.retry_after_secs, 0);
    }

    #[test]
    fn test_tier2_backoff_starts() {
        let p = adaptive_pow_params(8, 20);
        assert_eq!(p.difficulty, 12);
        assert_eq!(p.retry_after_secs, 30);
    }

    #[test]
    fn test_tier3_backoff_doubles() {
        let p = adaptive_pow_params(8, 30);
        assert_eq!(p.difficulty, 14);
        assert_eq!(p.retry_after_secs, 60);
    }

    #[test]
    fn test_difficulty_capped_at_20() {
        let p = adaptive_pow_params(8, 100);
        assert_eq!(p.difficulty, 20);
    }

    #[test]
    fn test_retry_after_capped_at_3600() {
        // tier >= 8 (count=80): 30 * 2^6 = 1920, cap is applied before 3600
        // Actually max is BASE_RETRY * 2^6 = 30*64 = 1920 due to .min(6) shift cap
        // Use a very high count to confirm cap holds
        let p = adaptive_pow_params(8, 1000);
        assert!(p.retry_after_secs <= 3600);
        assert!(p.retry_after_secs > 0);
    }
}
