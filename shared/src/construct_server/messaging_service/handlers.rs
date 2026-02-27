// ============================================================================
// Messaging Service Handlers - Phase 2.6.4 + APNs Integration
// ============================================================================
//
// Wrapper handlers that convert MessagingServiceContext to AppContext
// for use with existing messaging-related route handlers.
//
// Phase 2.9: Added APNs push notification support
// - send_push_notification: Send silent push when message arrives
// - Non-blocking push sends (don't fail message delivery if push fails)
//
// ============================================================================

use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use std::sync::Arc;

use crate::messaging_service::MessagingServiceContext;
use crate::messaging_service::core as messaging_core;
use crate::routes::extractors::TrustedUser;
use crate::routes::messages;
use crate::utils::log_safe_id;
use construct_error::AppError;
use construct_types::message::EndSessionData;
use uuid::Uuid;

fn app_state(context: &Arc<MessagingServiceContext>) -> State<Arc<crate::context::AppContext>> {
    State(Arc::new(context.to_app_context()))
}

// ============================================================================
// APNs Push Notification Helper
// ============================================================================

/// Send silent push notification to wake up recipient's app
///
/// This is called asynchronously after message is stored, so failures don't
/// affect message delivery. The push notification is silent (no content)
/// and only wakes the app to fetch messages via long-polling.
#[allow(dead_code)]
async fn send_push_notification(
    context: &MessagingServiceContext,
    recipient_id: &str,
) -> anyhow::Result<()> {
    // ✅ FIXED: Query encrypted device tokens (not plain text)
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

    tracing::debug!(
        recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
        token_count = rows.len(),
        "Sending push notification to {} device(s)",
        rows.len()
    );

    // Decrypt each token and send push notification
    let mut send_errors = 0;
    let mut send_success = 0;

    for row in &rows {
        // Decrypt the token using token_encryption from context
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

        // Send silent push to wake up the app
        match context.apns_client.send_silent_push(&token, None).await {
            Ok(_) => {
                tracing::debug!(
                    recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
                    "Silent push notification sent successfully"
                );
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
    } else if send_success > 0 {
        tracing::debug!(
            recipient_hash = %log_safe_id(recipient_id, &context.config.logging.hash_salt),
            total_devices = send_success,
            "All push notifications sent successfully"
        );
    }

    Ok(())
}

// ============================================================================
// Phase 4.5: Control Messages Handler
// ============================================================================

/// Wrapper for send_control_message handler (POST /api/v1/control)
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

/// Wrapper for confirm_message handler (POST /api/v1/messages/confirm)
pub async fn confirm_message(
    State(context): State<Arc<MessagingServiceContext>>,
    TrustedUser(user_id): TrustedUser,
    Json(data): Json<messages::ConfirmMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let user_id = Uuid::parse_str(&user_id.to_string())
        .map_err(|_| AppError::Validation("Invalid authenticated user ID".to_string()))?;
    let result =
        messaging_core::confirm_pending_message(app_state(&context).0, user_id, &data.temp_id)
            .await?;
    Ok((axum::http::StatusCode::OK, Json(result)))
}
