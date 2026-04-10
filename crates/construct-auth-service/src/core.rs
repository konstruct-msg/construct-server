use std::sync::Arc;

use crate::devices;
use axum::Json;
use chrono::Utc;
use construct_context::AppContext;
use construct_error::AppError;
use construct_utils::log_safe_id;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RefreshTokenResult {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct DevicePublicKeysInput {
    pub verifying_key: String,
    pub identity_public: String,
    pub signed_prekey_public: String,
    pub signed_prekey_signature: String,
    pub crypto_suite: String,
}

#[derive(Debug, Clone)]
pub struct PowSolutionInput {
    pub challenge: String,
    pub nonce: u64,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct RegisterDeviceInput {
    pub username: Option<String>,
    pub device_id: String,
    pub public_keys: DevicePublicKeysInput,
    pub pow_solution: PowSolutionInput,
}

#[derive(Debug, Clone)]
pub struct AuthenticateDeviceInput {
    pub device_id: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: i64,
}

pub async fn refresh_tokens(
    app_context: Arc<AppContext>,
    refresh_token: &str,
) -> Result<RefreshTokenResult, AppError> {
    // 1. Verify refresh token signature and expiry
    let claims = app_context
        .auth_manager
        .verify_token(refresh_token)
        .map_err(|e| {
            tracing::warn!(error = %e, "Invalid refresh token");
            AppError::Auth("Invalid or expired refresh token".to_string())
        })?;

    // 2. Create the new tokens BEFORE touching Redis so that if token generation
    //    fails we haven't consumed the old token yet.
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user ID in refresh token".to_string()))?;

    let (new_access_token, _access_jti, access_expires) = app_context
        .auth_manager
        .create_token_for_device(&user_id, claims.device_id.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    let (new_refresh_token, refresh_jti, _refresh_expires) = app_context
        .auth_manager
        .create_refresh_token_for_device(&user_id, claims.device_id.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    // 3. Atomically consume the old token and store the new one in a single
    //    Redis Lua script — eliminates the crash window between DEL and SET.
    let refresh_ttl_seconds =
        app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;

    let user_id_from_token = {
        let mut queue = app_context.queue.lock().await;
        match queue
            .rotate_refresh_token(
                &claims.jti,
                &refresh_jti,
                &user_id.to_string(),
                refresh_ttl_seconds,
            )
            .await
        {
            Ok(Some(uid)) => uid,
            Ok(None) => {
                tracing::warn!(
                    jti = %claims.jti,
                    user_hash = %log_safe_id(&claims.sub, &app_context.config.logging.hash_salt),
                    "Refresh token was already used or revoked"
                );
                return Err(AppError::Auth(
                    "Refresh token was already used or revoked".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to rotate refresh token — fail closed");
                return Err(AppError::Auth("Cannot verify refresh token".to_string()));
            }
        }
    };

    // 4. Defense-in-depth: verify user_id in Redis matches JWT sub
    if user_id_from_token != claims.sub {
        tracing::error!(
            jti = %claims.jti,
            token_user_id = %claims.sub,
            redis_user_id = %user_id_from_token,
            "User ID mismatch between JWT and Redis"
        );
        return Err(AppError::Auth("Token validation failed".to_string()));
    }

    tracing::info!(
        user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
        "Token refreshed successfully"
    );

    Ok(RefreshTokenResult {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        expires_at: access_expires,
    })
}

pub async fn get_pow_challenge(
    app_context: Arc<AppContext>,
    headers: axum::http::HeaderMap,
) -> Result<(axum::http::HeaderMap, Json<devices::ChallengeResponse>), AppError> {
    devices::get_pow_challenge(axum::extract::State(app_context), headers).await
}

pub async fn register_device(
    app_context: Arc<AppContext>,
    headers: axum::http::HeaderMap,
    input: RegisterDeviceInput,
) -> Result<
    (
        axum::http::StatusCode,
        Json<devices::RegisterDeviceResponse>,
    ),
    AppError,
> {
    devices::register_device_v2(
        axum::extract::State(app_context),
        headers,
        Json(devices::RegisterDeviceRequest {
            username: input.username,
            device_id: input.device_id,
            public_keys: devices::DevicePublicKeys {
                verifying_key: input.public_keys.verifying_key,
                identity_public: input.public_keys.identity_public,
                signed_prekey_public: input.public_keys.signed_prekey_public,
                signed_prekey_signature: input.public_keys.signed_prekey_signature,
                crypto_suite: input.public_keys.crypto_suite,
            },
            pow_solution: devices::PowSolution {
                challenge: input.pow_solution.challenge,
                nonce: input.pow_solution.nonce,
                hash: input.pow_solution.hash,
            },
        }),
    )
    .await
}

pub async fn authenticate_device(
    app_context: Arc<AppContext>,
    input: AuthenticateDeviceInput,
) -> Result<
    (
        axum::http::StatusCode,
        Json<devices::RegisterDeviceResponse>,
    ),
    AppError,
> {
    devices::authenticate_device(
        axum::extract::State(app_context),
        Json(devices::AuthenticateDeviceRequest {
            device_id: input.device_id,
            timestamp: input.timestamp,
            signature: input.signature,
        }),
    )
    .await
}

pub async fn logout_user(
    app_context: Arc<AppContext>,
    user_id: Uuid,
    all_devices: bool,
    access_jti: Option<&str>,
    access_exp: Option<i64>,
) -> Result<(), AppError> {
    // Invalidate the current access token so it cannot be reused after logout.
    // TTL is set to the token's remaining lifetime so the entry self-expires.
    if let (Some(jti), Some(exp)) = (access_jti, access_exp) {
        let remaining = (exp - Utc::now().timestamp()).max(0);
        if remaining > 0 {
            let mut queue = app_context.queue.lock().await;
            if let Err(e) = queue.invalidate_access_token(jti, remaining).await {
                tracing::error!(error = %e, "Failed to add access token to blocklist");
                // Continue logout — best-effort blocklist, short TTL limits exposure
            }
        }
    }

    if all_devices {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue.revoke_all_user_tokens(&user_id.to_string()).await {
            tracing::error!(error = %e, "Failed to revoke all user tokens");
            // Continue anyway
        }
        drop(queue);

        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Logged out from all devices"
        );
    } else {
        tracing::info!(
            user_hash = %log_safe_id(&user_id.to_string(), &app_context.config.logging.hash_salt),
            "Logout requested (single device logout requires refresh token)"
        );
    }

    Ok(())
}
