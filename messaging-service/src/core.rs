use std::sync::Arc;

use serde_json::{Value, json};
use uuid::Uuid;

use construct_context::AppContext;
use construct_error::AppError;
use construct_message::MessageEnvelope;
use construct_metrics::{MESSAGE_DELIVERY_TIME, MESSAGES_SENT_TOTAL, record_abuse_fail_open};
use construct_server_shared::notification_service::NotificationServiceContext;
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
/// through `EncryptedMessage` deserialization.
pub async fn dispatch_envelope(
    app_context: &Arc<AppContext>,
    envelope: MessageEnvelope,
    notification_context: Option<Arc<NotificationServiceContext>>,
) -> Result<(), AppError> {
    let t_start = std::time::Instant::now();
    let salt = &app_context.config.logging.hash_salt;
    let message_id = &envelope.message_id;
    let sender_id = &envelope.sender_id;
    let recipient_id = &envelope.recipient_id;

    // Idempotency: reject duplicate message_ids (client retry with same UUID).
    // Receipt and control envelopes are excluded — they are server-generated.
    use construct_message::MessageType;
    let is_user_message = matches!(
        envelope.message_type,
        MessageType::DirectMessage | MessageType::MLSMessage | MessageType::SenderSync
    );

    // All Redis operations are batched inside ONE lock acquisition to avoid
    // releasing and re-acquiring the mutex between the dedup check, the
    // stream write, and the receipt-sender mapping.
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
                record_abuse_fail_open("dispatch_dedup");
            }
        }

        // Block enforcement: silently drop if recipient has blocked sender.
        // Returns Ok(()) to avoid leaking block status to the sender.
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

    // Fan-out to per-device streams (multi-device support) + legacy user stream.
    // drop(queue) before the blocking DB call to minimize lock contention.
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
    tracing::debug!(
        redis_ms = t_lock.elapsed().as_millis(),
        "dispatch redis batch done"
    );

    let elapsed = t_start.elapsed();
    tracing::info!(
        elapsed_ms = elapsed.as_millis(),
        sender_hash = %log_safe_id(sender_id, salt),
        recipient_hash = %log_safe_id(recipient_id, salt),
        message_id = %message_id,
        "Message dispatched"
    );

    MESSAGES_SENT_TOTAL.inc();
    MESSAGE_DELIVERY_TIME.observe(elapsed.as_secs_f64());

    // ── Non-critical background tasks ─────────────────────────────────────────
    // DB fallback for receipt routing (survives Redis restarts).
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

    // Send silent push notification directly via APNs (non-critical background task)
    if let Some(notif_ctx) = notification_context {
        let ctx = notif_ctx;
        let recipient = recipient_id.clone();
        tokio::spawn(async move {
            let Ok(recipient_uuid) = Uuid::parse_str(&recipient) else {
                return;
            };
            let input = crate::notification_core::SendBlindNotificationInput {
                user_id: recipient_uuid,
                badge_count: None,
                activity_type: Some("new_message".to_string()),
                conversation_id: None,
            };
            match crate::notification_core::send_blind_notification(&ctx, input).await {
                Ok(_) => tracing::debug!("Blind notification sent via embedded APNs"),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to send blind notification (non-critical)")
                }
            }
        });
    }

    Ok(())
}

/// Confirm a pending message by temp_id (internal / test helper).
/// Client REST path was removed — prefer gRPC delivery ack when wired.
#[allow(dead_code)]
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
///
/// `salt` should come from configured `LOG_HASH_SALT` / `logging.hash_salt`.
/// HMAC-SHA256 accepts any key length (including empty); we never substitute a
/// fixed global key such as `"fallback"` — that would make hashes predictable
/// across all deployments that hit a key-init failure path.
pub fn receipt_routing_hash(message_id: &str, salt: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(message_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::receipt_routing_hash;

    #[test]
    fn receipt_hash_is_stable_for_same_inputs() {
        let a = receipt_routing_hash("msg-1", "deploy-salt-alpha");
        let b = receipt_routing_hash("msg-1", "deploy-salt-alpha");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn receipt_hash_differs_when_salt_differs() {
        let a = receipt_routing_hash("msg-1", "salt-a");
        let b = receipt_routing_hash("msg-1", "salt-b");
        assert_ne!(a, b);
    }

    #[test]
    fn receipt_hash_does_not_use_literal_fallback_key() {
        // The old bug substituted b"fallback" when key init "failed".
        // With a real salt, the MAC must not equal HMAC(message, "fallback").
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let with_salt = receipt_routing_hash("msg-1", "production-salt");
        let mut mac = HmacSha256::new_from_slice(b"fallback").unwrap();
        mac.update(b"msg-1");
        let with_fallback = hex::encode(mac.finalize().into_bytes());
        assert_ne!(
            with_salt, with_fallback,
            "routing hash must not collapse to the fixed fallback key"
        );
    }

    #[test]
    fn empty_salt_still_computes_without_panic() {
        // Empty salt is a misconfig, but must not panic or switch to a fixed key.
        let h = receipt_routing_hash("msg-1", "");
        assert_eq!(h.len(), 64);
    }
}
