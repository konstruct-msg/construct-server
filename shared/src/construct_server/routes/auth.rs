// ============================================================================
// Authentication Routes
// ============================================================================
//
// Endpoints:
// - POST /auth/refresh - Refresh access token using refresh token
// - POST /auth/logout - Soft logout (invalidate tokens from all devices)
//
// REMOVED legacy password-based endpoints:
// - POST /api/v1/auth/register (use POST /api/v1/auth/register-device in auth-service)
// - POST /api/v1/auth/login (use POST /api/v1/auth/device in auth-service)
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::auth_service::core;
use crate::context::AppContext;
use crate::routes::extractors::TrustedUser;
use construct_error::AppError;

/// Request body for token refresh
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenRequest {
    /// Refresh token (JWT)
    pub refresh_token: String,
}

/// Response for token refresh
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshTokenResponse {
    /// New access token (short-lived, 1 hour)
    pub access_token: String,
    /// New refresh token (long-lived, 30 days)
    pub refresh_token: String,
    /// Access token expiration timestamp (Unix epoch seconds)
    pub expires_at: i64,
}

/// POST /auth/refresh
/// Refreshes access token using a valid refresh token
///
/// Security:
/// - Validates refresh token signature and expiration
/// - Checks if refresh token is revoked (soft logout)
/// - Issues new access token (1 hour TTL) and new refresh token (30 days TTL)
/// - Revokes old refresh token (token rotation)
pub async fn refresh_token(
    State(app_context): State<Arc<AppContext>>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = core::refresh_tokens(app_context, &request.refresh_token).await?;

    Ok((
        StatusCode::OK,
        Json(RefreshTokenResponse {
            access_token: result.access_token,
            refresh_token: result.refresh_token,
            expires_at: result.expires_at,
        }),
    ))
}

/// Request body for logout
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    /// Optional: If true, logout from all devices (revoke all refresh tokens)
    #[serde(default)]
    pub all_devices: bool,
}

/// POST /auth/logout
/// Soft logout: invalidates access token and refresh token
///
/// Security:
/// - Invalidates current access token (prevents reuse)
/// - Revokes current refresh token
/// - Optionally revokes all refresh tokens for user (all_devices=true)
pub async fn logout(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    core::logout_user(app_context, user_id, request.all_devices).await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Logged out successfully"
        })),
    ))
}

// ============================================================================
// REMOVED: Legacy Password-Based Authentication (Phase 2.5)
// ============================================================================
//
// The following endpoints have been REMOVED in favor of device-based auth:
// - POST /api/v1/auth/register (replaced by POST /api/v1/auth/register-device)
// - POST /api/v1/auth/login (replaced by POST /api/v1/auth/device)
//
// Use auth-service endpoints instead (in auth-service/src/main.rs):
// - POST /api/v1/auth/challenge - Get PoW challenge
// - POST /api/v1/auth/register-device - Register new device (passwordless)
// - POST /api/v1/auth/device - Authenticate existing device (passwordless)
//
// Kept endpoints:
// - POST /auth/refresh - Refresh access token (used by all clients)
// - POST /auth/logout - Logout from all devices (security feature)
//
// ============================================================================
