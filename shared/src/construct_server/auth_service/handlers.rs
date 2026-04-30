// ============================================================================
// Auth Service Handlers - Passwordless Authentication
// ============================================================================

use axum::http::StatusCode;
use axum::{Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::construct_server::context::AppContext;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use construct_error::AppError;
use construct_extractors::TrustedUser;

use super::{AuthServiceContext, core};

fn app_state(context: &Arc<AuthServiceContext>) -> State<Arc<AppContext>> {
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
    #[serde(default = "default_crypto_suite")]
    pub crypto_suite: String,
}

fn default_crypto_suite() -> String {
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

pub async fn get_pow_challenge(
    State(context): State<Arc<AuthServiceContext>>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    core::get_pow_challenge(app_state(&context).0, headers).await
}

pub async fn register_device(
    State(context): State<Arc<AuthServiceContext>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let verifying_key = BASE64
        .decode(&request.public_keys.verifying_key)
        .map_err(|_| AppError::Validation("verifying_key must be valid base64".to_string()))?;
    let identity_public = BASE64
        .decode(&request.public_keys.identity_public)
        .map_err(|_| AppError::Validation("identity_public must be valid base64".to_string()))?;
    let signed_prekey_public = BASE64
        .decode(&request.public_keys.signed_prekey_public)
        .map_err(|_| {
            AppError::Validation("signed_prekey_public must be valid base64".to_string())
        })?;
    let signed_prekey_signature = BASE64
        .decode(&request.public_keys.signed_prekey_signature)
        .map_err(|_| {
            AppError::Validation("signed_prekey_signature must be valid base64".to_string())
        })?;
    core::register_device(
        app_state(&context).0,
        headers,
        core::RegisterDeviceInput {
            username: request.username,
            device_id: request.device_id,
            public_keys: core::DevicePublicKeysInput {
                verifying_key,
                identity_public,
                signed_prekey_public,
                signed_prekey_signature,
                crypto_suite: request.public_keys.crypto_suite,
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

pub async fn authenticate_device(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<AuthenticateDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let signature = BASE64
        .decode(&request.signature)
        .map_err(|_| AppError::Validation("signature must be valid base64".to_string()))?;
    core::authenticate_device(
        app_state(&context).0,
        core::AuthenticateDeviceInput {
            device_id: request.device_id,
            timestamp: request.timestamp,
            signature,
        },
    )
    .await
}

pub async fn refresh_token(
    State(context): State<Arc<AuthServiceContext>>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = core::refresh_tokens_proto(
        app_state(&context).0,
        crate::shared::proto::services::v1::RefreshTokenRequest {
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

pub async fn logout(
    State(context): State<Arc<AuthServiceContext>>,
    user: TrustedUser,
    Json(request): Json<LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    let TrustedUser(user_id) = user;
    core::logout_user(
        app_state(&context).0,
        user_id,
        request.all_devices,
        None,
        None,
    )
    .await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Logged out successfully"
        })),
    ))
}
