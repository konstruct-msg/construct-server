use serde_json::{Value, json};
use std::sync::Arc;

use uuid::Uuid;

use construct_context::AppContext;
use construct_error::AppError;
use construct_message::MessageEnvelope;
use construct_utils::log_safe_id;

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

/// Dispatch a pre-built MessageEnvelope to the recipient's Redis offline stream.
///
/// Used by the gRPC path where the envelope is constructed without going
/// through `EncryptedMessage` deserialization. Push notification is handled
/// by the messaging-service binary directly — this shared copy is for tests
/// and skips push.
pub async fn dispatch_envelope(
    app_context: &Arc<AppContext>,
    envelope: MessageEnvelope,
) -> Result<(), AppError> {
    let t_start = std::time::Instant::now();
    let salt = &app_context.config.logging.hash_salt;
    let message_id = &envelope.message_id;
    let sender_id = &envelope.sender_id;
    let recipient_id = &envelope.recipient_id;

    use construct_message::MessageType;
    let is_user_message = matches!(
        envelope.message_type,
        MessageType::DirectMessage | MessageType::MLSMessage | MessageType::SenderSync
    );

    let t_lock = std::time::Instant::now();
    let mut queue = app_context.queue.lock().await;
    tracing::debug!(
        wait_ms = t_lock.elapsed().as_millis(),
        "queue lock acquired (dispatch)"
    );

    if is_user_message {
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

        if let (Ok(sender_uuid), Ok(recipient_uuid)) =
            (Uuid::parse_str(sender_id), Uuid::parse_str(recipient_id))
        {
            match construct_db::is_blocked_by(&app_context.db_pool, &recipient_uuid, &sender_uuid)
                .await
            {
                Ok(true) => {
                    tracing::debug!(
                        sender_hash = %log_safe_id(sender_id, salt),
                        recipient_hash = %log_safe_id(recipient_id, salt),
                        "Message silently dropped — sender is blocked by recipient"
                    );
                    return Ok(());
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to check user_blocks — proceeding with delivery");
                }
            }
        }
    }

    drop(queue);

    let device_ids = fetch_recipient_device_ids(app_context, recipient_id).await;
    let mut queue = app_context.queue.lock().await;
    queue
        .write_message_to_device_streams(recipient_id, &device_ids, &envelope)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to deliver message: {e}")))?;

    if !sender_id.is_empty()
        && let Err(e) = queue.store_message_sender(message_id, sender_id).await
    {
        tracing::warn!(error = %e, message_id = %message_id, "Failed to store receipt sender mapping in Redis (non-critical)");
    }
    drop(queue);

    let elapsed = t_start.elapsed();
    tracing::info!(
        elapsed_ms = elapsed.as_millis(),
        sender_hash = %log_safe_id(sender_id, salt),
        recipient_hash = %log_safe_id(recipient_id, salt),
        message_id = %message_id,
        "Message dispatched"
    );

    if !sender_id.is_empty() {
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

    Ok(())
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
    use hmac::{Hmac, Mac, digest::KeyInit};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .unwrap_or_else(|_| HmacSha256::new_from_slice(b"fallback").unwrap());
    mac.update(message_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
