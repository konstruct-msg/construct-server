use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use uuid::Uuid;

use construct_broker::KafkaMessageEnvelope;
use construct_context::AppContext;
use construct_error::AppError;
use construct_extractors::TrustedUser;
use construct_types::message::{ChatMessage, EndSessionData};
use construct_utils::{extract_client_ip, log_safe_id};

/// Look up active device IDs for a recipient.
/// Returns an empty Vec on error so callers fall back to the user-level stream.
async fn fetch_recipient_device_ids(
    app_context: &Arc<AppContext>,
    recipient_id: &str,
) -> Vec<String> {
    let Ok(uid) = Uuid::parse_str(recipient_id) else {
        return vec![];
    };
    match construct_db::get_devices_by_user_id(&app_context.db_pool, &uid).await {
        Ok(devices) => devices.into_iter().map(|d| d.device_id).collect(),
        Err(e) => {
            tracing::warn!(error = %e, recipient = %recipient_id, "Failed to fetch recipient devices for fan-out");
            vec![]
        }
    }
}

/// Dispatch a pre-built KafkaMessageEnvelope to Kafka (or Redis fallback).
///
/// Used by the gRPC path where the envelope is constructed without going
/// through `EncryptedMessage` deserialization.
pub async fn dispatch_envelope(
    app_context: &Arc<AppContext>,
    envelope: KafkaMessageEnvelope,
) -> Result<(), AppError> {
    let salt = &app_context.config.logging.hash_salt;
    let message_id = &envelope.message_id;
    let sender_id = &envelope.sender_id;
    let recipient_id = &envelope.recipient_id;

    // Idempotency: reject duplicate message_ids (client retry with same UUID).
    // Receipt and control envelopes are excluded — they are server-generated.
    use construct_broker::MessageType;
    let is_user_message = matches!(
        envelope.message_type,
        MessageType::DirectMessage | MessageType::MLSMessage | MessageType::SenderSync
    );
    if is_user_message {
        let mut queue = app_context.queue.lock().await;
        match queue.is_message_duplicate(message_id).await {
            Ok(true) => {
                tracing::debug!(message_id = %message_id, "Duplicate message_id — skipping (idempotent retry)");
                return Ok(());
            }
            Ok(false) => {
                let _ = queue.mark_message_dispatched(message_id).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to check dedup key — proceeding anyway");
            }
        }
    }

    if let Some(kafka_producer) = &app_context.kafka_producer {
        if kafka_producer.is_enabled() {
            match kafka_producer.send_message(&envelope).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        sender_hash = %log_safe_id(sender_id, salt),
                        recipient_hash = %log_safe_id(recipient_id, salt),
                        message_id = %message_id,
                        "Kafka unavailable — falling back to Redis direct delivery"
                    );
                    let device_ids = fetch_recipient_device_ids(app_context, recipient_id).await;
                    let mut queue = app_context.queue.lock().await;
                    queue
                        .write_message_to_device_streams(recipient_id, &device_ids, &envelope)
                        .await
                        .map_err(|re| {
                            AppError::Internal(format!(
                                "Both Kafka and Redis delivery failed: {e} / {re}"
                            ))
                        })?;
                }
            }
        } else {
            // Kafka disabled (test mode) — write directly to Redis
            let device_ids = fetch_recipient_device_ids(app_context, recipient_id).await;
            let mut queue = app_context.queue.lock().await;
            queue
                .write_message_to_device_streams(recipient_id, &device_ids, &envelope)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to deliver message: {e}")))?;
        }
    } else {
        return Err(AppError::Kafka("Kafka producer not available".to_string()));
    }

    tracing::info!(
        sender_hash = %log_safe_id(sender_id, salt),
        recipient_hash = %log_safe_id(recipient_id, salt),
        message_id = %message_id,
        "Message dispatched successfully (gRPC path)"
    );

    // Store sender mapping for receipt routing — non-critical, log and continue on error.
    // Stored in both Redis (fast path) and DB (durability fallback).
    if !sender_id.is_empty() {
        let mut queue = app_context.queue.lock().await;
        if let Err(e) = queue.store_message_sender(message_id, sender_id).await {
            tracing::warn!(error = %e, message_id = %message_id, "Failed to store receipt sender mapping in Redis (non-critical)");
        }
        drop(queue);
        // DB fallback: persist to delivery_pending so receipts survive Redis restarts.
        let hash_salt = app_context.config.logging.hash_salt.clone();
        let msg_id = message_id.clone();
        let snd_id = sender_id.clone();
        let pool = app_context.db_pool.clone();
        tokio::spawn(async move {
            let message_hash = receipt_routing_hash(&msg_id, &hash_salt);
            let result = sqlx::query(
                "INSERT INTO delivery_pending (message_hash, sender_id, expires_at) \
                 VALUES ($1, $2, NOW() + INTERVAL '30 days') \
                 ON CONFLICT (message_hash) DO NOTHING",
            )
            .bind(&message_hash)
            .bind(&snd_id)
            .execute(&*pool)
            .await;
            if let Err(e) = result {
                tracing::warn!(error = %e, message_id = %msg_id, "Failed to persist receipt sender to DB (non-critical)");
            }
        });
    }

    // Send silent push notification asynchronously — failures do not affect delivery
    if app_context.config.apns.enabled {
        let ctx = app_context.clone();
        let recipient = recipient_id.clone();
        tokio::spawn(async move {
            if let Err(e) = send_push_notification(&ctx, &recipient).await {
                tracing::warn!(error = %e, "Failed to send push notification (non-critical)");
            }
        });
    }

    Ok(())
}

/// Send silent push notification to all active devices of a recipient.
///
/// Non-blocking helper — always called via `tokio::spawn`. Failures are logged
/// but never propagate to the caller.
async fn send_push_notification(
    app_context: &Arc<AppContext>,
    recipient_id: &str,
) -> anyhow::Result<()> {
    // Only send to devices matching the server's configured APNs environment.
    // dev server (APNS_ENVIRONMENT=development) → sandbox tokens only
    // prod server (APNS_ENVIRONMENT=production) → production tokens only
    let env_str = match app_context.config.apns.environment {
        construct_config::ApnsEnvironment::Production => "production",
        _ => "sandbox",
    };

    #[derive(sqlx::FromRow)]
    struct DeviceTokenRow {
        device_token_encrypted: Vec<u8>,
    }

    let rows = sqlx::query_as::<_, DeviceTokenRow>(
        "SELECT device_token_encrypted FROM device_tokens \
         WHERE user_id = $1::uuid AND enabled = true AND push_provider = 'apns' \
         AND push_environment = $2",
    )
    .bind(recipient_id)
    .bind(env_str)
    .fetch_all(&*app_context.db_pool)
    .await?;

    if rows.is_empty() {
        tracing::debug!(
            recipient_hash = %log_safe_id(recipient_id, &app_context.config.logging.hash_salt),
            "No active device tokens — push skipped"
        );
        return Ok(());
    }

    let mut success = 0u32;
    let mut failed = 0u32;
    for row in &rows {
        match app_context
            .token_encryption
            .decrypt(&row.device_token_encrypted)
        {
            Ok(token) => match app_context.apns_client.send_silent_push(&token, None).await {
                Ok(_) => success += 1,
                Err(e) => {
                    failed += 1;
                    tracing::warn!(
                        recipient_hash = %log_safe_id(recipient_id, &app_context.config.logging.hash_salt),
                        error = %e,
                        "Silent push failed for device"
                    );
                }
            },
            Err(e) => {
                failed += 1;
                tracing::error!(
                    recipient_hash = %log_safe_id(recipient_id, &app_context.config.logging.hash_salt),
                    error = %e,
                    "Failed to decrypt device token"
                );
            }
        }
    }

    tracing::debug!(
        recipient_hash = %log_safe_id(recipient_id, &app_context.config.logging.hash_salt),
        success,
        failed,
        "Push notification attempt complete"
    );
    Ok(())
}

pub async fn send_control_message(
    State(app_context): State<Arc<AppContext>>,
    TrustedUser(sender_id): TrustedUser,
    headers: HeaderMap,
    Json(data): Json<EndSessionData>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let sender_id_str = sender_id.to_string();

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

        let client_ip = extract_client_ip(&headers, None);

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

    let recipient_id = Uuid::parse_str(&data.recipient_id)
        .map_err(|_| AppError::Validation("Invalid recipient ID format".to_string()))?;

    if sender_id == recipient_id {
        return Err(AppError::Validation(
            "Cannot send control message to self".to_string(),
        ));
    }

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

    let chat_message =
        ChatMessage::new_end_session(sender_id_str.clone(), data.recipient_id.clone());
    let message_id = chat_message.id.clone();

    if !chat_message.is_valid() {
        tracing::error!(
            sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
            "Failed to create valid END_SESSION message"
        );
        return Err(AppError::Internal(
            "Failed to create valid control message".to_string(),
        ));
    }

    let envelope = KafkaMessageEnvelope::from(chat_message);
    let salt = &app_context.config.logging.hash_salt;

    if let Some(kafka_producer) = &app_context.kafka_producer {
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

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "sent",
            "messageId": message_id,
            "type": "END_SESSION"
        })),
    ))
}

pub async fn confirm_pending_message(
    app_context: Arc<AppContext>,
    sender_id: Uuid,
    temp_id: &str,
) -> Result<Value, AppError> {
    let sender_id_str = sender_id.to_string();

    let Some(pending_storage) = &app_context.pending_message_storage else {
        return Ok(json!({
            "status": "confirmed",
            "message": "2-phase commit not enabled"
        }));
    };

    match pending_storage.confirm_pending(temp_id).await {
        Ok(true) => {
            tracing::debug!(
                temp_id = %temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Message confirmed (Phase 2)"
            );
            Ok(json!({
                "status": "confirmed",
                "tempId": temp_id
            }))
        }
        Ok(false) => {
            tracing::warn!(
                temp_id = %temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Attempted to confirm non-existent pending message"
            );
            Ok(json!({
                "status": "confirmed",
                "tempId": temp_id,
                "message": "Already confirmed or expired"
            }))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                temp_id = %temp_id,
                "Failed to confirm pending message"
            );
            Ok(json!({
                "status": "confirmed",
                "tempId": temp_id,
                "message": "Confirmation queued"
            }))
        }
    }
}

/// Compute HMAC-SHA256(message_id, salt) as a hex string for delivery_pending lookups.
/// UUIDs have 122 bits of entropy — brute force is impractical without the salt.
pub fn receipt_routing_hash(message_id: &str, salt: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").unwrap());
    mac.update(message_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
