// ============================================================================
// User Service Handlers
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

use super::{UserServiceContext, account, account_deletion, core as user_core, invites};
use crate::construct_server::auth_service::devices;
use crate::construct_server::context::AppContext;
use construct_error::AppError;
use construct_extractors::TrustedUser;

fn app_state(context: &Arc<UserServiceContext>) -> State<Arc<AppContext>> {
    State(Arc::new(context.to_app_context()))
}

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

pub async fn get_device_profile(
    State(context): State<Arc<UserServiceContext>>,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    devices::get_device_profile(app_state(&context), Path(device_id)).await
}

pub async fn check_username_availability(
    State(context): State<Arc<UserServiceContext>>,
    headers: HeaderMap,
    Query(query): Query<account::UsernameAvailabilityQuery>,
) -> Result<impl IntoResponse, AppError> {
    account::check_username_availability(app_state(&context), headers, Query(query)).await
}

pub async fn generate_invite(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<invites::GenerateInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    invites::generate_invite(app_state(&context), user, Json(request)).await
}

pub async fn accept_invite(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<invites::AcceptInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    invites::accept_invite(app_state(&context), user, Json(request)).await
}

pub async fn get_delete_challenge(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
) -> Result<impl IntoResponse, AppError> {
    account_deletion::get_delete_challenge(app_state(&context), user).await
}

pub async fn confirm_delete(
    State(context): State<Arc<UserServiceContext>>,
    user: TrustedUser,
    Json(request): Json<account_deletion::DeleteConfirmRequest>,
) -> Result<impl IntoResponse, AppError> {
    account_deletion::confirm_delete(app_state(&context), user, Json(request)).await
}
