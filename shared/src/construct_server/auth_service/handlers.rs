// ============================================================================
// Auth Service Handlers - Passwordless Authentication
// ============================================================================
//
// Wrapper handlers that convert AuthServiceContext to AppContext
// for use with existing device-based authentication handlers.
//
// This service handles ONLY passwordless device-based authentication:
// - PoW challenge generation
// - Device registration (with Ed25519 keys)
// - Device authentication (Ed25519 signature verification)
// - JWT token management (refresh, logout)
//
// ============================================================================

use axum::{Json, extract::State, response::IntoResponse};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::auth_service::core;
use crate::auth_service::AuthServiceContext;
use crate::routes::extractors::TrustedUser;
use crate::shared::proto::services::v1 as proto_services;
use construct_error::AppError;

fn app_state(context: &Arc<AuthServiceContext>) -> State<Arc<crate::context::AppContext>> {
    State(Arc::new(context.to_app_context()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    #[serde(default)]
    pub all_devices: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePublicKeys {
    pub verifying_key: String,
    pub identity_public: String,
    pub signed_prekey_public: String,
    pub signed_prekey_signature: String,
    #[serde(default = "default_suite_id")]
    pub suite_id: String,
}

fn default_suite_id() -> String {
    "Curve25519+Ed25519".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PowSolution {
    pub challenge: String,
    pub nonce: u64,
    pub hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub username: Option<String>,
    pub device_id: String,
    pub public_keys: DevicePublicKeys,
    pub pow_solution: PowSolution,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateDeviceRequest {
    pub device_id: String,
    pub timestamp: i64,
    pub signature: String,
}

/// Wrapper for get_pow_challenge handler
pub async fn get_pow_challenge(
    State(context): State<Arc<AuthServiceContext>>,
) -> Result<impl IntoResponse, AppError> {
    core::get_pow_challenge(app_state(&context).0).await
}

/// Wrapper for register_device handler
pub async fn register_device(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    core::register_device(
        app_state(&context).0,
        core::RegisterDeviceInput {
            username: request.username,
            device_id: request.device_id,
            public_keys: core::DevicePublicKeysInput {
                verifying_key: request.public_keys.verifying_key,
                identity_public: request.public_keys.identity_public,
                signed_prekey_public: request.public_keys.signed_prekey_public,
                signed_prekey_signature: request.public_keys.signed_prekey_signature,
                suite_id: request.public_keys.suite_id,
            },
            pow_solution: core::PowSolutionInput {
                challenge: request.pow_solution.challenge,
                nonce: request.pow_solution.nonce,
                hash: request.pow_solution.hash,
            },
        },
    )
    .await
}

/// Wrapper for authenticate_device handler
pub async fn authenticate_device(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<AuthenticateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    core::authenticate_device(
        app_state(&context).0,
        core::AuthenticateDeviceInput {
            device_id: request.device_id,
            timestamp: request.timestamp,
            signature: request.signature,
        },
    )
    .await
}

/// Wrapper for refresh_token handler
pub async fn refresh_token(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = core::refresh_tokens_proto(
        app_state(&context).0,
        proto_services::RefreshTokenRequest {
            refresh_token: request.refresh_token,
            device_id: String::new(),
        },
    )
    .await?;
    Ok((
        StatusCode::OK,
        Json(RefreshTokenResponse {
            access_token: result.access_token,
            refresh_token: result.refresh_token.unwrap_or_default(),
            expires_at: result.expires_at,
        }),
    ))
}

/// Wrapper for logout handler
pub async fn logout(
    State(context): State<Arc<AuthServiceContext>>,
    user: TrustedUser,
    Json(request): Json<LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    let TrustedUser(user_id) = user;
    core::logout_user(app_state(&context).0, user_id, request.all_devices).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Logged out successfully"
        })),
    ))
}
