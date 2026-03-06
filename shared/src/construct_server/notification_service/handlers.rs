// ============================================================================
// Notification Service Handlers
// ============================================================================

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use super::{NotificationServiceContext, notifications};
use construct_error::AppError;
use construct_extractors::TrustedUser;

pub async fn register_device(
    State(context): State<Arc<NotificationServiceContext>>,
    user: TrustedUser,
    Json(request): Json<notifications::RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    notifications::register_device(State(app_context), user, Json(request)).await
}

pub async fn unregister_device(
    State(context): State<Arc<NotificationServiceContext>>,
    user: TrustedUser,
    Json(request): Json<notifications::UnregisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    notifications::unregister_device(State(app_context), user, Json(request)).await
}

pub async fn update_preferences(
    State(context): State<Arc<NotificationServiceContext>>,
    user: TrustedUser,
    Json(request): Json<notifications::UpdatePreferencesRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    notifications::update_preferences(State(app_context), user, Json(request)).await
}
