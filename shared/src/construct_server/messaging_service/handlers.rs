// ============================================================================
// Messaging Service Handlers
// ============================================================================

use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use std::sync::Arc;
use uuid::Uuid;

use super::{MessagingServiceContext, core as messaging_core};
use crate::construct_server::context::AppContext;
use crate::construct_server::utils::log_safe_id;
use construct_error::AppError;
use construct_extractors::TrustedUser;
use construct_types::api::ConfirmMessageRequest;
use construct_types::message::EndSessionData;

fn app_state(context: &Arc<MessagingServiceContext>) -> State<Arc<AppContext>> {
    State(Arc::new(context.to_app_context()))
}

#[allow(dead_code)]
pub async fn send_push_notification(
    context: &MessagingServiceContext,
    recipient_id: &str,
) -> anyhow::Result<()> {
    #[derive(sqlx::FromRow)]
    struct DeviceTokenRow {
        device_token_encrypted: Vec<u8>,
    }

    let rows = sqlx::query_as::<_, DeviceTokenRow>(
        "SELECT device_token_encrypted FROM device_tokens
         WHERE user_id = $1::uuid AND enabled = true",
    )
    .bind(recipient_id)
    .fetch_all(&*context.db_pool)
    .await?;

    if rows.is_empty() {
        tracing::debug!(
            recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
            "No active device tokens for recipient - push not sent"
        );
        return Ok(());
    }

    let mut send_errors = 0;
    let mut send_success = 0;

    for row in &rows {
        let token = match context
            .token_encryption
            .decrypt(&row.device_token_encrypted)
        {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
                    error = %e,
                    "Failed to decrypt device token"
                );
                send_errors += 1;
                continue;
            }
        };

        match context.apns_client.send_silent_push(&token, None).await {
            Ok(_) => {
                send_success += 1;
            }
            Err(e) => {
                send_errors += 1;
                tracing::warn!(
                    recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
                    error = %e,
                    "Failed to send push notification to device"
                );
            }
        }
    }

    if send_errors > 0 {
        tracing::warn!(
            recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
            total_devices = rows.len(),
            success = send_success,
            failed = send_errors,
            "Push notification partially failed"
        );
    }

    Ok(())
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
