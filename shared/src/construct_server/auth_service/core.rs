use std::sync::Arc;

use crate::context::AppContext;
use crate::routes::devices;
use crate::shared::proto::services::v1 as proto_services;
use crate::utils::log_safe_id;
use axum::Json;
use construct_error::AppError;
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
    pub suite_id: String,
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
    // 1. Verify refresh token
    let claims = app_context
        .auth_manager
        .verify_token(refresh_token)
        .map_err(|e| {
            tracing::warn!(error = %e, "Invalid refresh token");
            AppError::Auth("Invalid or expired refresh token".to_string())
        })?;

    // 2. Check if refresh token is revoked (soft logout)
    {
        let mut queue = app_context.queue.lock().await;
        match queue.check_refresh_token(&claims.jti).await {
            Ok(Some(_)) => {
                // Token is valid, continue
            }
            Ok(None) => {
                drop(queue);
                tracing::warn!(
                    jti = %claims.jti,
                    user_hash = %log_safe_id(&claims.sub, &app_context.config.logging.hash_salt),
                    "Refresh token was revoked"
                );
                return Err(AppError::Auth("Refresh token was revoked".to_string()));
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check refresh token");
                // Fail open - continue but log error
            }
        }

        // 3. Revoke old refresh token (token rotation)
        if let Err(e) = queue.revoke_refresh_token(&claims.jti).await {
            tracing::error!(error = %e, "Failed to revoke old refresh token");
            // Continue anyway - token rotation is best effort
        }
        drop(queue);
    }

    // 4. Parse user ID
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Validation("Invalid user ID in refresh token".to_string()))?;

    // 5. Create new access token (1 hour)
    let (new_access_token, _access_jti, access_expires) = app_context
        .auth_manager
        .create_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create access token");
            AppError::Unknown(e)
        })?;

    // 6. Create new refresh token (30 days)
    let (new_refresh_token, refresh_jti, _refresh_expires) = app_context
        .auth_manager
        .create_refresh_token(&user_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create refresh token");
            AppError::Unknown(e)
        })?;

    // 7. Store new refresh token in Redis
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

pub async fn refresh_tokens_proto(
    app_context: Arc<AppContext>,
    request: proto_services::RefreshTokenRequest,
) -> Result<proto_services::RefreshTokenResponse, AppError> {
    let result = refresh_tokens(app_context, &request.refresh_token).await?;
    Ok(proto_services::RefreshTokenResponse {
        access_token: result.access_token,
        refresh_token: Some(result.refresh_token),
        expires_at: result.expires_at,
    })
}

pub async fn get_pow_challenge(
    app_context: Arc<AppContext>,
    headers: axum::http::HeaderMap,
) -> Result<(axum::http::HeaderMap, Json<devices::ChallengeResponse>), AppError> {
    devices::get_pow_challenge(
        axum::extract::State(app_context),
        headers,
    )
    .await
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
                suite_id: input.public_keys.suite_id,
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
) -> Result<(), AppError> {
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
