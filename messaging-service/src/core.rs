use std::sync::Arc;

use uuid::Uuid;

use construct_context::AppContext;
use construct_error::AppError;
use construct_message::MessageEnvelope;
use construct_metrics::{
    MESSAGE_DELIVERY_TIME, MESSAGES_SENT_TOTAL, MSG_DELIVERY_ROUTING_TOTAL,
    MSG_MAILBOX_WRITE_TOTAL, MSG_PUSH_SKIPPED_ONLINE_TOTAL, record_abuse_fail_open,
};
use construct_server_shared::notification_service::NotificationServiceContext;
use construct_utils::log_safe_id;

/// Whether dispatch should fire a silent APNs wake for this recipient.
///
/// When the recipient already has a live MessageStream, Redis `inbox:wakeup`
/// delivers in real time. An APNs silent push is redundant and historically
/// caused the iOS client to force-reconnect the stream on every message,
/// re-XREADing the entire untrimmed offline backlog (reconnect storm).
///
/// Presence is user-level (`user:{id}:server_instance_id`), not per-device:
/// if any device holds a stream we skip push. Offline secondary devices still
/// pick up from Redis on next open; multi-device online tracking is a separate
/// improvement.
pub(crate) fn should_send_wake_push(recipient_online: bool) -> bool {
    !recipient_online
}

/// Look up active device IDs for a recipient.
/// Returns an empty Vec on error so callers fall back to the user-level stream.
pub(crate) async fn fetch_recipient_device_ids_for_user(
    db_pool: &construct_db::DbPool,
    recipient_id: &str,
) -> Vec<String> {
    let Ok(uid) = Uuid::parse_str(recipient_id) else {
        return vec![];
    };
    match construct_db::get_devices_by_user_id(db_pool, &uid).await {
        Ok(devices) => devices.into_iter().map(|d| d.device_id).collect(),
        Err(e) => {
            tracing::warn!(error = %e, recipient = %recipient_id, "Failed to fetch recipient devices for fan-out");
            vec![]
        }
    }
}

async fn fetch_recipient_device_ids(
    app_context: &Arc<AppContext>,
    recipient_id: &str,
) -> Vec<String> {
    fetch_recipient_device_ids_for_user(&app_context.db_pool, recipient_id).await
}

/// Turn a wire device id into the internal `Option<String>`, in one place.
///
/// **An empty id is the same as no id.** Both wire spellings of "no device" —
/// an absent `Envelope.recipient_device` message and a present-but-empty
/// `SealedInner.recipient_device` string — become `None` here, so the internal
/// envelope only ever holds "a device" or "no device". `Some("")` would be a
/// third state that every later reader would have to know about, and the two
/// sealed and unsealed ingress paths would each have had to invent the same
/// rule; the second copy of one rule is where they stop agreeing.
///
/// Callers below this do not re-normalise. `select_target_devices` still guards
/// its own input because it is a total function over whatever it is handed, but
/// it is not where the decision is made.
pub(crate) fn normalize_device_id(device_id: &str) -> Option<String> {
    Some(device_id)
        .filter(|d| !d.is_empty())
        .map(str::to_string)
}

/// The device a proto envelope names, or `None` when it names none.
///
/// Takes the field rather than the envelope: by this point in `send_message` the
/// envelope is partially moved, and a whole-struct borrow does not compile.
pub(crate) fn named_recipient_device(
    recipient_device: Option<&construct_server_shared::shared::proto::core::v1::DeviceId>,
) -> Option<String> {
    recipient_device.and_then(|d| normalize_device_id(&d.device_id))
}

/// Which mailboxes an envelope is written to, and under which label.
///
/// The whole of §A's first step is this function. Before it, `recipient_device`
/// had exactly one reader — the Sentinel block in `grpc.rs` — so a sender that
/// had encrypted for one device was answered by a copy in every device's mailbox,
/// and every *other* device then tried to decrypt ciphertext that was never for
/// it. See `construct-docs/decisions/multidevice-gate-three-asymmetries.md`.
///
/// **An unknown device falls back to every device; it is never dropped.** A named
/// device can be absent from the active set for reasons that are none of the
/// sender's fault — the device was revoked or re-registered between the bundle
/// fetch and the send, or the lookup itself failed and returned an empty list,
/// which is indistinguishable here from an account with no devices. Dropping on
/// that would be a silent loss of ciphertext decided by a stale cache, which is
/// the failure this whole line of work exists to remove. The disagreement is
/// counted instead, and that count is the evidence for whether the sender has to
/// be *told* (the 409/410-shaped answer in §A.3) rather than quietly corrected.
pub(crate) fn select_target_devices(
    active_devices: &[String],
    named_device: Option<&str>,
) -> (Vec<String>, &'static str) {
    let Some(named) = named_device.filter(|d| !d.is_empty()) else {
        return (active_devices.to_vec(), "unnamed");
    };
    if active_devices.iter().any(|d| d == named) {
        (vec![named.to_string()], "named")
    } else {
        (active_devices.to_vec(), "unknown_device")
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

    // Dedup EXISTS is a fast path only. The SETEX that makes a retry a no-op
    // happens *after* the mailbox XADD — marking first turned a write failure
    // into an idempotent success (ACK without a stream entry).
    if is_user_message {
        let t_lock = std::time::Instant::now();
        let mut queue = app_context.queue.lock().await;
        tracing::debug!(
            wait_ms = t_lock.elapsed().as_millis(),
            "queue lock acquired (dedup)"
        );
        match queue.is_message_duplicate(message_id).await {
            Ok(true) => {
                tracing::debug!(message_id = %message_id, "Duplicate message_id — skipping (idempotent retry)");
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Failed to check dedup key — proceeding anyway");
                record_abuse_fail_open("dispatch_dedup");
            }
        }
        drop(queue);
    }

    // Block check is Postgres — do not hold the Redis queue Mutex across it.
    if is_user_message
        && let (Ok(sender_uuid), Ok(recipient_uuid)) =
            (Uuid::parse_str(sender_id), Uuid::parse_str(recipient_id))
    {
        match construct_db::is_blocked_by(&app_context.db_pool, &recipient_uuid, &sender_uuid).await
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

    let active_devices = fetch_recipient_device_ids(app_context, recipient_id).await;
    let (device_ids, routing) =
        select_target_devices(&active_devices, envelope.recipient_device.as_deref());
    MSG_DELIVERY_ROUTING_TOTAL
        .with_label_values(&[routing])
        .inc();
    if routing == "unknown_device" {
        tracing::warn!(
            recipient_hash = %log_safe_id(recipient_id, salt),
            active_devices = active_devices.len(),
            "Envelope named a device that is not active for its recipient — delivering to all              devices rather than dropping it"
        );
    }
    let t_lock = std::time::Instant::now();
    let mut queue = app_context.queue.lock().await;
    let write_user = queue.mailbox_user_write_enabled();
    queue
        .write_message_to_device_streams(recipient_id, &device_ids, &envelope)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to deliver message: {e}")))?;
    if is_user_message {
        // Commit the idempotency key only after the stream entry exists. A
        // SETEX failure here can double-deliver on retry — better than
        // ACK-without-write. Log and proceed: the mailbox is the source of
        // truth.
        if let Err(e) = queue.mark_message_dispatched(message_id).await {
            tracing::warn!(
                error = %e,
                message_id = %message_id,
                "Failed to mark message dispatched after mailbox write — retry may duplicate"
            );
        }
    }
    if write_user {
        MSG_MAILBOX_WRITE_TOTAL.with_label_values(&["user"]).inc();
    }
    if !device_ids.is_empty() {
        MSG_MAILBOX_WRITE_TOTAL
            .with_label_values(&["device"])
            .inc_by(device_ids.len() as u64);
    }

    if !sender_id.is_empty()
        && let Err(e) = queue.store_message_sender(message_id, sender_id).await
    {
        tracing::warn!(error = %e, message_id = %message_id, "Failed to store receipt sender mapping in Redis (non-critical)");
    }

    // Presence check under the same lock as the stream write so we observe the
    // online flag set by an active MessageStream on this (or another) instance.
    // Redis error → treat as offline (fail-open: still send APNs wake).
    let recipient_online = match queue.get_user_server_instance(recipient_id).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            tracing::debug!(
                error = %e,
                recipient_hash = %log_safe_id(recipient_id, salt),
                "Failed to check recipient online status — will send wake push"
            );
            false
        }
    };
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

    // Silent APNs only when the recipient has no live MessageStream. Online
    // recipients are woken via inbox:wakeup; pushing them causes reconnect storms.
    if let Some(notif_ctx) = notification_context {
        if should_send_wake_push(recipient_online) {
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
                        tracing::warn!(
                            error = %e,
                            "Failed to send blind notification (non-critical)"
                        )
                    }
                }
            });
        } else {
            MSG_PUSH_SKIPPED_ONLINE_TOTAL.inc();
            tracing::debug!(
                recipient_hash = %log_safe_id(recipient_id, salt),
                message_id = %message_id,
                "Skipping silent push — recipient has active MessageStream"
            );
        }
    }

    Ok(())
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
    use super::{
        normalize_device_id, receipt_routing_hash, select_target_devices, should_send_wake_push,
    };

    #[test]
    fn an_empty_wire_device_id_is_no_device() {
        // Both wire spellings of "no device" must land on the same internal value. If an
        // empty string survived as Some(""), the envelope would carry a third state and
        // every later reader would need to know about it.
        assert_eq!(normalize_device_id(""), None);
    }

    #[test]
    fn a_present_wire_device_id_is_carried_verbatim() {
        assert_eq!(
            normalize_device_id("6f5e37ac9b1d4e2f8a0c3b5d7e9f1a2b").as_deref(),
            Some("6f5e37ac9b1d4e2f8a0c3b5d7e9f1a2b")
        );
    }

    fn devices(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unnamed_envelope_goes_to_every_active_device() {
        let all = devices(&["dev-a", "dev-b", "dev-c"]);
        let (targets, routing) = select_target_devices(&all, None);
        assert_eq!(targets, all);
        assert_eq!(routing, "unnamed");
    }

    #[test]
    fn named_active_device_gets_the_only_copy() {
        let all = devices(&["dev-a", "dev-b", "dev-c"]);
        let (targets, routing) = select_target_devices(&all, Some("dev-b"));
        assert_eq!(targets, devices(&["dev-b"]));
        assert_eq!(routing, "named");
    }

    #[test]
    fn empty_device_name_is_the_same_as_naming_none() {
        // The field is optional on the wire; an empty string is a malformed sender,
        // and reading it as "deliver nowhere" would drop the message.
        let all = devices(&["dev-a", "dev-b"]);
        let (targets, routing) = select_target_devices(&all, Some(""));
        assert_eq!(targets, all);
        assert_eq!(routing, "unnamed");
    }

    #[test]
    fn unknown_device_falls_back_to_every_device_and_is_counted() {
        // The named device was revoked or re-registered between the sender's bundle
        // fetch and this send. Dropping here would be a silent loss of ciphertext
        // decided by a stale cache — deliver to all, and record the disagreement.
        let all = devices(&["dev-a", "dev-b"]);
        let (targets, routing) = select_target_devices(&all, Some("dev-gone"));
        assert_eq!(targets, all);
        assert_eq!(routing, "unknown_device");
    }

    #[test]
    fn a_named_device_never_shrinks_an_empty_active_set_into_a_delivery() {
        // `fetch_recipient_device_ids` returns an empty vec both for a DB error and
        // for a user with no devices, and the two are indistinguishable here. Neither
        // may become "deliver to the device the sender named" on the sender's word:
        // that would let a lookup failure invent a mailbox. Empty stays empty, and
        // the "nowhere to land" check downstream decides what that means.
        let (targets, routing) = select_target_devices(&[], Some("dev-a"));
        assert!(targets.is_empty());
        assert_eq!(routing, "unknown_device");
    }

    #[test]
    fn naming_the_only_device_is_still_a_narrowing_not_a_no_op() {
        // Single-device accounts are the common case and must take the `named` label,
        // otherwise the ratio the counter exists for reads as "nobody targets anything".
        let all = devices(&["dev-only"]);
        let (targets, routing) = select_target_devices(&all, Some("dev-only"));
        assert_eq!(targets, all);
        assert_eq!(routing, "named");
    }

    #[test]
    fn wake_push_skipped_when_recipient_online() {
        assert!(!should_send_wake_push(true));
    }

    #[test]
    fn wake_push_sent_when_recipient_offline() {
        assert!(should_send_wake_push(false));
    }

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
