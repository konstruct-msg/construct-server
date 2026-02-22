// ============================================================================
// Notification Service Handlers - Phase 2.6.5
// ============================================================================
//
// Wrapper handlers that convert NotificationServiceContext to AppContext
// for use with existing notification-related route handlers.
//
// This is a temporary solution until handlers are refactored to use traits.
//
// ============================================================================

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use crate::notification_service::NotificationServiceContext;
use crate::routes::extractors::TrustedUser;
use crate::routes::notifications;
use construct_error::AppError;

/// Wrapper for register_device handler (POST /api/v1/notifications/register-device)
pub async fn register_device(
    State(context): State<Arc<NotificationServiceContext>>,
    user: TrustedUser,
    Json(request): Json<notifications::RegisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    notifications::register_device(State(app_context), user, Json(request)).await
}

/// Wrapper for unregister_device handler (POST /api/v1/notifications/unregister-device)
pub async fn unregister_device(
    State(context): State<Arc<NotificationServiceContext>>,
    user: TrustedUser,
    Json(request): Json<notifications::UnregisterDeviceRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    notifications::unregister_device(State(app_context), user, Json(request)).await
}

/// Wrapper for update_preferences handler (PUT /api/v1/notifications/preferences)
pub async fn update_preferences(
    State(context): State<Arc<NotificationServiceContext>>,
    user: TrustedUser,
    Json(request): Json<notifications::UpdatePreferencesRequest>,
) -> Result<impl IntoResponse, AppError> {
    let app_context = Arc::new(context.to_app_context());
    notifications::update_preferences(State(app_context), user, Json(request)).await
}
