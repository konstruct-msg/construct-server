// ============================================================================
// User Service Handlers
// ============================================================================

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::{UserServiceContext, account_deletion};
use crate::construct_server::context::AppContext;
use construct_error::AppError;
use construct_extractors::TrustedUser;

fn app_state(context: &Arc<UserServiceContext>) -> State<Arc<AppContext>> {
    State(Arc::new(context.to_app_context()))
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
