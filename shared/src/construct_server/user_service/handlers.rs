// ============================================================================
// User Service Handlers - Phase 2.6.3
// ============================================================================
//
// Wrapper handlers that convert UserServiceContext to AppContext
// for use with existing user-related route handlers.
//
// This is a temporary solution until handlers are refactored to use traits.
//
// ============================================================================

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::routes::account;
use crate::routes::account_deletion;
use crate::routes::devices;
use crate::routes::extractors::TrustedUser;
use crate::routes::invites;
use crate::routes::keys::UpdateVerifyingKeyRequest;
use crate::user_service::UserServiceContext;
use crate::user_service::core as user_core;
use construct_error::AppError;

fn app_state(context: &Arc<UserServiceContext>) -> State<Arc<crate::context::AppContext>> {
    State(Arc::new(context.to_app_context()))
}

/// Wrapper for get_account handler
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfoResponse {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

pub async fn get_account(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    let info = user_core::get_account_info(app_context, user.0).await?;

    Ok((
        StatusCode::OK,
        Json(AccountInfoResponse {
            user_id: info.user_id,
            username: info.username,
        }),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccountRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// Wrapper for update_account handler
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn update_account(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    _headers: HeaderMap,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());

    user_core::update_account(
        app_context,
        user.0,
        user_core::UpdateAccountInput {
            username: request.username,
        },
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "message": "Account updated successfully"
        })),
    ))
}

// Note: Legacy delete_account removed - use device-signed deletion instead
// (GET /api/v1/users/me/delete-challenge + POST /api/v1/users/me/delete-confirm)

/// Wrapper for get_public_key_bundle handler (GET /api/v1/users/:id/public-key)
/// Also handles legacy GET /keys/:user_id
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn get_public_key_bundle(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    user_core::get_public_key_bundle(app_context, user.0, id).await
}

/// Wrapper for legacy get_keys handler (GET /keys/:user_id)
/// This is the same as get_public_key_bundle, but kept for backward compatibility
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn get_keys_legacy(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Legacy endpoint uses same handler as modern API
    get_public_key_bundle(State(context), user, Path(user_id)).await
}

/// Wrapper for upload_keys handler (POST /api/v1/keys/upload)
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn upload_keys(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    headers: HeaderMap,
    Json(bundle): Json<construct_crypto::UploadableKeyBundle>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    user_core::upload_keys(app_context, user.0, headers, bundle).await
}

/// Wrapper for update_verifying_key handler (PATCH /api/v1/users/me/public-key)
pub async fn update_verifying_key(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    headers: HeaderMap,
    Json(request): Json<UpdateVerifyingKeyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    user_core::update_verifying_key(
        app_context,
        user.0,
        headers,
        user_core::UpdateVerifyingKeyInput {
            verifying_key: request.verifying_key,
            reason: request.reason,
        },
    )
    .await
}

pub async fn get_device_profile(
    State(context): State<Arc<UserServiceContext>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    devices::get_device_profile(app_state(&context), Path(device_id)).await
}

/// Wrapper for check_username_availability handler
/// GET /api/v1/users/username/availability?username=<string>
/// This endpoint does NOT require authentication
pub async fn check_username_availability(
    State(context): State<Arc<UserServiceContext>>,
    headers: HeaderMap,
    Query(query): Query<account::UsernameAvailabilityQuery>,
) -> Result<impl IntoResponse, AppError> {
    account::check_username_availability(app_state(&context), headers, Query(query)).await
}

/// Wrapper for generate_invite handler
/// POST /api/v1/invites/generate
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn generate_invite(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<invites::GenerateInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    invites::generate_invite(app_state(&context), user, Json(request)).await
}

/// Wrapper for accept_invite handler
/// POST /api/v1/invites/accept
/// Note: Uses TrustedUser (Trust Boundary pattern) - Gateway sets X-User-Id header
pub async fn accept_invite(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<invites::AcceptInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    invites::accept_invite(app_state(&context), user, Json(request)).await
}

// ============================================================================
// Device-Signed Account Deletion (Phase 5.0.1)
// ============================================================================

/// Wrapper for get_delete_challenge handler
/// GET /api/v1/users/me/delete-challenge
/// Note: Uses TrustedUser (Trust Boundary pattern)
pub async fn get_delete_challenge(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    account_deletion::get_delete_challenge(app_state(&context), user).await
}

/// Wrapper for confirm_delete handler
/// POST /api/v1/users/me/delete-confirm
/// Note: Uses TrustedUser (Trust Boundary pattern)
pub async fn confirm_delete(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<account_deletion::DeleteConfirmRequest>,
) -> Result<impl IntoResponse, AppError> {
    account_deletion::confirm_delete(app_state(&context), user, Json(request)).await
}
