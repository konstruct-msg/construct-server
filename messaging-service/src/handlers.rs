// ============================================================================
// Messaging Service Handlers
// ============================================================================

use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use std::sync::Arc;
use uuid::Uuid;

use crate::context::MessagingServiceContext;
use crate::core as messaging_core;
use crate::notification_core;
use construct_context::AppContext;
use construct_error::AppError;
use construct_extractors::TrustedUser;
use construct_server_shared::notification_service::NotificationServiceContext;
use construct_types::api::ConfirmMessageRequest;
use construct_types::message::EndSessionData;

fn app_state(context: &Arc<MessagingServiceContext>) -> State<Arc<AppContext>> {
    State(Arc::new(context.to_app_context()))
}

pub async fn send_control_message(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    headers: HeaderMap,
    Json(data): Json<EndSessionData>,
) -> Result<impl IntoResponse, AppError> {
    messaging_core::send_control_message(
        app_state(&context),
        TrustedUser(user_id),
        headers,
        Json(data),
    )
    .await
}

/// Extract NotificationServiceContext from MessagingServiceContext state.
fn notif_state(
    context: &Arc<MessagingServiceContext>,
) -> Result<Arc<NotificationServiceContext>, AppError> {
    context
        .notification_context
        .clone()
        .ok_or_else(|| AppError::Internal("Notification service not initialized".to_string()))
}

/// POST /api/v1/notifications/register-device
pub async fn register_device(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<
        construct_server_shared::notification_service::notifications::RegisterDeviceRequest,
    >,
) -> Result<impl IntoResponse, AppError> {
    if request.device_token.is_empty() || request.device_token.len() > 128 {
        return Err(AppError::Validation(
            "Device token format is invalid".to_string(),
        ));
    }

    let filter = request
        .notification_filter
        .unwrap_or_else(|| "silent".to_string());
    let valid_filters = [
        "silent",
        "visible_all",
        "visible_dm",
        "visible_mentions",
        "visible_contacts",
    ];
    if !valid_filters.contains(&filter.as_str()) {
        return Err(AppError::Validation(format!(
            "Invalid notification filter. Must be one of: {:?}",
            valid_filters
        )));
    }

    let notif_ctx = notif_state(&context)?;
    let input = notification_core::RegisterDeviceTokenInput {
        user_id,
        device_token: request.device_token,
        device_name: request.device_name,
        notification_filter: match filter.as_str() {
            "visible_all" => 2,
            "visible_dm" => 3,
            "visible_mentions" => 4,
            "visible_contacts" => 5,
            _ => 1,
        },
        device_id: None,
        push_provider: "apns".to_string(),
        push_environment: "production".to_string(),
    };

    let output = notification_core::register_device_token(&notif_ctx, input)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok((
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": "Device token registered",
            "tokenId": output.token_id,
        })),
    ))
}

/// POST /api/v1/notifications/unregister-device
pub async fn unregister_device(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<
        construct_server_shared::notification_service::notifications::UnregisterDeviceRequest,
    >,
) -> Result<impl IntoResponse, AppError> {
    let notif_ctx = notif_state(&context)?;
    let input = notification_core::UnregisterDeviceTokenInput {
        user_id,
        device_token: request.device_token,
    };

    let output = notification_core::unregister_device_token(&notif_ctx, input)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if output.success {
        Ok((
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "message": "Device token unregistered"
            })),
        ))
    } else {
        Err(AppError::Validation("Device token not found".to_string()))
    }
}

/// PUT /api/v1/notifications/preferences
pub async fn update_preferences(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(request): Json<
        construct_server_shared::notification_service::notifications::UpdatePreferencesRequest,
    >,
) -> Result<impl IntoResponse, AppError> {
    let valid_filters = [
        "silent",
        "visible_all",
        "visible_dm",
        "visible_mentions",
        "visible_contacts",
    ];
    if !valid_filters.contains(&request.notification_filter.as_str()) {
        return Err(AppError::Validation(format!(
            "Invalid notification filter. Must be one of: {:?}",
            valid_filters
        )));
    }

    let notif_ctx = notif_state(&context)?;
    let input = notification_core::UpdateNotificationPreferencesInput {
        user_id,
        device_token: request.device_token,
        notification_filter: match request.notification_filter.as_str() {
            "visible_all" => 2,
            "visible_dm" => 3,
            "visible_mentions" => 4,
            "visible_contacts" => 5,
            _ => 1,
        },
        enabled: request.enabled,
    };

    let output = notification_core::update_notification_preferences(&notif_ctx, input)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if output.success {
        Ok((
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "message": "Preferences updated"
            })),
        ))
    } else {
        Err(AppError::Validation("Device token not found".to_string()))
    }
}

#[allow(dead_code)]
pub async fn confirm_message(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(data): Json<ConfirmMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = Uuid::parse_str(&user_id.to_string())
        .map_err(|_| AppError::Validation("Invalid authenticated user ID".to_string()))?;
    let result =
        messaging_core::confirm_pending_message(app_state(&context).0, user_id, &data.temp_id)
            .await?;
    Ok((axum::http::StatusCode::OK, Json(result)))
}
