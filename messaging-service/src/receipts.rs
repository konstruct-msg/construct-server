use std::collections::HashMap;
use std::sync::Arc;

use crate::context::MessagingServiceContext;
use crate::core;
use construct_server_shared::shared::proto::services::v1 as proto;

/// Relay a DeliveryReceipt from the recipient to the original sender's stream.
///
/// Looks up the original sender via the Redis `receipt:sender:{message_id}` mapping
/// stored by `dispatch_envelope()`. Writes a Receipt-type envelope to the sender's
/// offline delivery stream so they pick it up on the next poll.
pub(crate) async fn relay_delivery_receipt(
    context: &Arc<MessagingServiceContext>,
    direct: construct_server_shared::shared::proto::signaling::v1::DirectReceipt,
    receipt_sender_id: String,
) -> anyhow::Result<()> {
    use construct_server_shared::kafka::types::KafkaMessageEnvelope;

    if direct.message_ids.is_empty() {
        return Ok(());
    }

    let status = match direct.status {
        1 => "delivered",
        2 => "read",
        3 => "failed",
        _ => "delivered",
    };

    // Group message_ids by original sender.
    //
    // Fast path: client now populates DirectReceipt.recipient_user_id — use it
    // directly and skip the Redis/DB lookup entirely.
    //
    // Slow path (legacy / missing field): look up sender via Redis cache, with
    // fallback to delivery_pending DB table (survives Redis restarts).
    let mut sender_map: HashMap<String, Vec<String>> = HashMap::new();

    if !direct.recipient_user_id.is_empty() {
        // Fast path: all message_ids in this receipt share the same original sender.
        tracing::info!(
            sender = %direct.recipient_user_id,
            msg_count = direct.message_ids.len(),
            status,
            "Receipt routing via recipient_user_id (fast path)"
        );
        sender_map.insert(direct.recipient_user_id.clone(), direct.message_ids.clone());
    } else {
        // Slow path: look up sender per message_id via Redis → DB fallback.
        for message_id in &direct.message_ids {
            let redis_result = {
                let mut queue = context.queue.lock().await;
                queue.get_message_sender(message_id).await
            };

            let sender_id = match redis_result {
                Ok(Some(id)) => Some(id),
                Ok(None) => {
                    // Redis miss — fall back to DB
                    let hash_salt = &context.config.logging.hash_salt;
                    let message_hash = core::receipt_routing_hash(message_id, hash_salt);
                    match sqlx::query_scalar::<_, String>(
                        "DELETE FROM delivery_pending WHERE message_hash = $1 RETURNING sender_id",
                    )
                    .bind(&message_hash)
                    .fetch_optional(&*context.db_pool)
                    .await
                    {
                        Ok(Some(id)) => {
                            tracing::debug!(message_id = %message_id, "Receipt sender found in DB fallback");
                            Some(id)
                        }
                        Ok(None) => {
                            tracing::debug!(message_id = %message_id, "No sender mapping found for receipt (expired or unknown)");
                            None
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, message_id = %message_id, "DB fallback lookup failed for receipt");
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, message_id = %message_id, "Failed to look up sender for receipt");
                    None
                }
            };

            if let Some(id) = sender_id {
                sender_map.entry(id).or_default().push(message_id.clone());
            }
        }
    }

    // Write receipt envelope per sender
    let mut queue = context.queue.lock().await;
    for (sender_id, msg_ids) in sender_map {
        // Relay the receipt — FAILED status alone is enough signal for the sender.
        // The recipient client already sends an END_SESSION envelope (content_type =
        // SESSION_RESET) through the normal message stream, so we must NOT also queue
        // a server-generated SESSION_RESET here — that would cause the sender to
        // receive two reset signals and double-initialise the X3DH session.
        let receipt_envelope = KafkaMessageEnvelope::from_receipt(
            sender_id.clone(),
            receipt_sender_id.clone(),
            msg_ids,
            status,
        );
        if let Err(e) = queue
            .write_message_to_user_stream(&sender_id, &receipt_envelope)
            .await
        {
            tracing::warn!(error = %e, sender_id = %sender_id, "Failed to relay receipt to sender stream (non-critical)");
        } else {
            tracing::info!(sender_id = %sender_id, status, msg_count = receipt_envelope.encrypted_payload.len(), "Relayed delivery receipt to sender stream");
        }
    }

    Ok(())
}

/// Build a MessageStreamResponse::Receipt from a Receipt-type KafkaMessageEnvelope.
pub(crate) fn build_receipt_response(
    envelope: &construct_server_shared::kafka::types::KafkaMessageEnvelope,
) -> anyhow::Result<proto::MessageStreamResponse> {
    use construct_server_shared::shared::proto::signaling::v1 as signaling;

    #[derive(serde::Deserialize)]
    struct ReceiptPayload {
        message_ids: Vec<String>,
        status: String,
        timestamp: i64,
    }

    let payload: ReceiptPayload = serde_json::from_str(&envelope.encrypted_payload)
        .map_err(|e| anyhow::anyhow!("Invalid receipt payload: {}", e))?;

    let status = match payload.status.as_str() {
        "read" => 2i32,
        "failed" => 3i32,
        _ => 1i32, // delivered
    };

    let direct = signaling::DirectReceipt {
        message_ids: payload.message_ids,
        status,
        timestamp: payload.timestamp,
        sender_device_id: String::new(),
        // envelope.sender_id = who sent the receipt (device 1).
        // The original sender (device 2) needs this to know which contact
        // acknowledged their message.
        recipient_user_id: envelope.sender_id.clone(),
    };

    let receipt = signaling::DeliveryReceipt {
        receipt_type: Some(signaling::delivery_receipt::ReceiptType::Direct(direct)),
    };

    Ok(proto::MessageStreamResponse {
        response: Some(proto::message_stream_response::Response::Receipt(receipt)),
        response_id: None,
        stream_cursor: None,
    })
}
