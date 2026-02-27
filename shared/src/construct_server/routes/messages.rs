// ============================================================================
// Messages Routes (Double Ratchet Protocol)
// ============================================================================
//
// Endpoints:
// - POST /api/v1/messages - Send an E2E-encrypted message
// - GET /api/v1/messages - Get messages (long polling)
//
// See docs/PROTOCOL_SPECIFICATION.md for protocol details.
// ============================================================================

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::context::AppContext;
use crate::kafka::types::KafkaMessageEnvelope;
use crate::messaging_service::core as messaging_core;
use crate::routes::extractors::TrustedUser;
use crate::utils::{extract_client_ip, log_safe_id};
use construct_error::AppError;
use construct_types::message::{ChatMessage, EndSessionData};

/// POST /api/v1/control
/// Sends a control message (e.g., END_SESSION) to notify recipient
#[allow(unreachable_code)]
pub async fn send_control_message(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(sender_id): TrustedUser,
    headers: HeaderMap,
    Json(data): Json<EndSessionData>,
) -> Result<impl IntoResponse, AppError> {
    return messaging_core::send_control_message(
        State(app_context),
        TrustedUser(sender_id),
        headers,
        Json(data),
    )
    .await;

    let sender_id_str = sender_id.to_string();

    // SECURITY: Check rate limiting BEFORE processing (DoS protection)
    {
        let mut queue = app_context.queue.lock().await;
        if let Ok(Some(reason)) = queue.is_user_blocked(&sender_id_str).await {
            drop(queue);
            tracing::warn!(
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                reason = %reason,
                "Blocked user attempted to send control message"
            );
            return Err(AppError::Auth(format!(
                "Your account is temporarily blocked: {}",
                reason
            )));
        }

        // Check combined rate limit (user_id + IP) for authenticated operations
        let client_ip = extract_client_ip(&headers, None);

        // Use combined rate limiting if enabled
        if app_context.config.security.combined_rate_limiting_enabled {
            match queue
                .increment_combined_rate_limit(&sender_id_str, &client_ip, 3600)
                .await
            {
                Ok(count) => {
                    let max_combined = app_context
                        .config
                        .security
                        .max_requests_per_user_ip_per_hour;
                    if count > max_combined {
                        drop(queue);
                        tracing::warn!(
                            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                            ip = %client_ip,
                            count = count,
                            limit = max_combined,
                            "Combined rate limit exceeded for control messages"
                        );
                        return Err(AppError::Validation(format!(
                            "Rate limit exceeded: maximum {} requests per hour",
                            max_combined
                        )));
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to check combined rate limit");
                }
            }
        }

        // Also check user_id-only rate limit
        match queue.increment_message_count(&sender_id_str).await {
            Ok(count) => {
                let max_messages = app_context.config.security.max_messages_per_hour;
                if count > max_messages {
                    drop(queue);
                    tracing::warn!(
                        sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                        count = count,
                        limit = max_messages,
                        "Control message rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} control messages per hour",
                        max_messages
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to check control message rate limit");
            }
        }
        drop(queue);
    }

    // Parse recipient_id
    let recipient_id = Uuid::parse_str(&data.recipient_id)
        .map_err(|_| AppError::Validation("Invalid recipient ID format".to_string()))?;

    // Security check: prevent sending to self
    if sender_id == recipient_id {
        return Err(AppError::Validation(
            "Cannot send control message to self".to_string(),
        ));
    }

    // Check if recipient exists in database
    {
        let user_exists: Option<bool> =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)")
                .bind(recipient_id)
                .fetch_one(&*app_context.db_pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to check if recipient exists");
                    AppError::Database(e)
                })?;

        if !user_exists.unwrap_or(false) {
            return Err(AppError::Validation("Recipient does not exist".to_string()));
        }
    }

    // Create END_SESSION ChatMessage
    let chat_message =
        ChatMessage::new_end_session(sender_id_str.clone(), data.recipient_id.clone());

    let message_id = chat_message.id.clone();

    // Validate the control message
    if !chat_message.is_valid() {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
            "Failed to create valid END_SESSION message"
        );
        return Err(AppError::Internal(
            "Failed to create valid control message".to_string(),
        ));
    }

    // Convert to Kafka envelope (will automatically map to ControlMessage type)
    let envelope = KafkaMessageEnvelope::from(chat_message);

    // Write to Kafka (Phase 5: source of truth) or directly to Redis (test mode)
    let salt = &app_context.config.logging.hash_salt;
    if let Some(kafka_producer) = &app_context.kafka_producer {
        // Production path: send to Kafka, delivery worker will write to Redis
        if kafka_producer.is_enabled() {
            if let Err(e) = kafka_producer.send_message(&envelope).await {
                tracing::error!(
                    error = %e,
                    sender_hash = %log_safe_id(&sender_id_str, salt),
                    recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                    message_id = %message_id,
                    "Failed to send END_SESSION to Kafka"
                );
                return Err(AppError::Kafka(e.to_string()));
            }
        } else {
            // Test mode: Kafka disabled, write directly to Redis
            tracing::info!(
                sender_hash = %log_safe_id(&sender_id_str, salt),
                recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                message_id = %message_id,
                "Kafka disabled - writing END_SESSION directly to Redis (test mode)"
            );

            let mut queue = app_context.queue.lock().await;
            if let Err(e) = queue
                .write_message_to_user_stream(&recipient_id.to_string(), &envelope)
                .await
            {
                drop(queue);
                tracing::error!(
                    error = %e,
                    sender_hash = %log_safe_id(&sender_id_str, salt),
                    recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
                    message_id = %message_id,
                    "Failed to write END_SESSION to Redis"
                );
                return Err(AppError::Internal(format!(
                    "Failed to deliver control message: {}",
                    e
                )));
            }
            drop(queue);
        }
    } else {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id_str, salt),
            recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
            message_id = %message_id,
            "Kafka producer not available - cannot send control message"
        );
        return Err(AppError::Kafka("Kafka producer not available".to_string()));
    }

    tracing::info!(
        sender_hash = %log_safe_id(&sender_id_str, salt),
        recipient_hash = %log_safe_id(&recipient_id.to_string(), salt),
        message_id = %message_id,
        reason = ?data.reason,
        "END_SESSION control message sent successfully"
    );

    // Return success with proper status and camelCase naming
    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "sent",
            "messageId": message_id,
            "type": "END_SESSION"
        })),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ConfirmMessageRequest {
    /// Temporary ID from Phase 1 (send_message response)
    #[serde(rename = "tempId")]
    pub temp_id: String,
}

/// POST /api/v1/messages/confirm - Phase 2 of 2-phase commit
///
/// Client calls this after successfully receiving message_id from send_message.
/// If network failed and client never received the response, they retry send_message
/// with the same temp_id (idempotent).
///
/// This endpoint is fire-and-forget - even if confirmation fails, the auto-cleanup
/// worker will confirm pending messages after 5 minutes.
#[allow(unreachable_code)]
pub async fn confirm_message(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(sender_id): TrustedUser,
    Json(data): Json<ConfirmMessageRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result =
        messaging_core::confirm_pending_message(app_context, sender_id, &data.temp_id).await?;
    return Ok((StatusCode::OK, Json(result)));

    let sender_id_str = sender_id.to_string();

    // Check if 2-phase commit is enabled
    let Some(pending_storage) = &app_context.pending_message_storage else {
        // 2-phase commit disabled, return success (backward compatibility)
        return Ok((
            StatusCode::OK,
            Json(json!({
                "status": "confirmed",
                "message": "2-phase commit not enabled"
            })),
        ));
    };

    // Confirm the pending message (Phase 2)
    match pending_storage.confirm_pending(&data.temp_id).await {
        Ok(true) => {
            tracing::debug!(
                temp_id = %data.temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Message confirmed (Phase 2)"
            );

            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "confirmed",
                    "tempId": data.temp_id
                })),
            ))
        }
        Ok(false) => {
            // temp_id not found (already confirmed or expired)
            tracing::warn!(
                temp_id = %data.temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Attempted to confirm non-existent pending message"
            );

            // Return success anyway (fire-and-forget, idempotent)
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "confirmed",
                    "tempId": data.temp_id,
                    "message": "Already confirmed or expired"
                })),
            ))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                temp_id = %data.temp_id,
                "Failed to confirm pending message"
            );

            // Return success anyway (fire-and-forget)
            // Auto-cleanup worker will confirm after 5 minutes
            Ok((
                StatusCode::OK,
                Json(json!({
                    "status": "confirmed",
                    "tempId": data.temp_id,
                    "message": "Confirmation queued"
                })),
            ))
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_since_always_serialized() {
        // Test that nextSince field is always present in JSON (never omitted)

        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct TestResponse {
            messages: Vec<String>,
            next_since: Option<String>,
        }

        // Case 1: Some(value) → "nextSince": "value"
        let response1 = TestResponse {
            messages: vec![],
            next_since: Some("1234567890-0".to_string()),
        };

        let json1 = serde_json::to_value(&response1).unwrap();
        assert!(json1.get("nextSince").is_some());
        assert_eq!(json1["nextSince"], "1234567890-0");

        // Case 2: None → "nextSince": null (field still present!)
        let response2 = TestResponse {
            messages: vec![],
            next_since: None,
        };

        let json2 = serde_json::to_value(&response2).unwrap();
        assert!(
            json2.get("nextSince").is_some(),
            "nextSince field must exist"
        );
        assert!(json2["nextSince"].is_null());
    }
}
