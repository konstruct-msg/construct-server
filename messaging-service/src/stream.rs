use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::context::MessagingServiceContext;
use crate::core;
use crate::envelope::{convert_kafka_envelope_to_proto, dispatch_sealed_sender};
use crate::receipts::{build_receipt_response, relay_delivery_receipt};
use construct_server_shared::shared::proto::services::v1 as proto;

/// Handle incoming MessageStreamRequest from client
pub(crate) async fn handle_stream_request(
    req: proto::MessageStreamRequest,
    context: &Arc<MessagingServiceContext>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    user_id: &mut Option<uuid::Uuid>,
) -> anyhow::Result<()> {
    use proto::message_stream_request::Request as StreamReq;

    match req.request {
        Some(StreamReq::Send(envelope)) => {
            // Extract user_id from envelope if not set yet (regular messages only)
            if user_id.is_none()
                && envelope.sealed_sender.is_none()
                && let Some(sender) = &envelope.sender
            {
                *user_id = Some(uuid::Uuid::parse_str(&sender.user_id)?);
            }

            // ── Sealed Sender path ──────────────────────────────────────────
            if let Some(sealed) = &envelope.sealed_sender {
                let message_id = match dispatch_sealed_sender(context, sealed).await {
                    Ok(resp) => resp.message_id,
                    Err(e) => {
                        let error = proto::MessageError {
                            message_id: String::new(),
                            error_code: proto::ErrorCode::Unspecified.into(),
                            error_message: e.to_string(),
                            retryable: false,
                        };
                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                        };
                        tx.send(Ok(response)).await?;
                        return Ok(());
                    }
                };

                let ack = proto::MessageAck {
                    message_id,
                    message_number: 0,
                    server_timestamp: chrono::Utc::now().timestamp_millis(),
                    delivery_count: 1,
                };
                let response = proto::MessageStreamResponse {
                    response: Some(proto::message_stream_response::Response::Ack(ack)),
                    response_id: Some(req.request_id.clone()),
                };
                tx.send(Ok(response)).await?;
                return Ok(());
            }

            // ── Regular message path ────────────────────────────────────────
            if let Some(uid) = user_id {
                let recipient_id = envelope
                    .recipient
                    .as_ref()
                    .map(|r| r.user_id.clone())
                    .unwrap_or_default();
                if recipient_id.is_empty() {
                    return Err(anyhow::anyhow!("recipient is required"));
                }
                if envelope.encrypted_payload.is_empty() {
                    return Err(anyhow::anyhow!("encrypted_payload is required"));
                }
                let message_id = uuid::Uuid::new_v4().to_string();

                use construct_server_shared::kafka::types::{
                    KafkaMessageEnvelope, ProtoEnvelopeContext,
                };
                let kafka_envelope =
                    KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
                        sender_id: uid.to_string(),
                        recipient_id,
                        message_id: message_id.clone(),
                        encrypted_payload: envelope.encrypted_payload.to_vec(),
                    });

                let app_context = Arc::new(context.to_app_context());
                match core::dispatch_envelope(
                    &app_context,
                    kafka_envelope,
                )
                .await
                {
                    Ok(()) => {
                        let ack = proto::MessageAck {
                            message_id,
                            message_number: 0,
                            server_timestamp: chrono::Utc::now().timestamp_millis(),
                            delivery_count: 1,
                        };

                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Ack(ack)),
                            response_id: Some(req.request_id.clone()),
                        };

                        tx.send(Ok(response)).await?;
                    }
                    Err(e) => {
                        use construct_server_shared::shared::proto::core::v1 as core;
                        let message_id_str = if let Some(id_type) = &envelope.message_id_type {
                            match id_type {
                                core::envelope::MessageIdType::MessageId(id) => id.clone(),
                                _ => String::new(),
                            }
                        } else {
                            String::new()
                        };

                        let error = proto::MessageError {
                            message_id: message_id_str,
                            error_code: proto::ErrorCode::Unspecified.into(),
                            error_message: e.to_string(),
                            retryable: false,
                        };

                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                        };

                        tx.send(Ok(response)).await?;
                    }
                }
            }
        }

        Some(StreamReq::Heartbeat(hb)) => {
            let ack = proto::HeartbeatAck {
                timestamp: hb.timestamp,
                server_timestamp: chrono::Utc::now().timestamp_millis(),
            };

            let response = proto::MessageStreamResponse {
                response: Some(proto::message_stream_response::Response::HeartbeatAck(ack)),
                response_id: Some(req.request_id),
            };

            tx.send(Ok(response)).await?;
        }

        // Subscribe/Unsubscribe: conversation_ids are intentionally not logged or stored
        // to avoid leaking the client's contact graph to the server.
        // All messages for this user are already routed to their Redis stream regardless.
        Some(StreamReq::Receipt(receipt)) => {
            if user_id.is_none() {
                tracing::warn!("Receipt received but user_id is unknown — receipt dropped (missing auth metadata)");
            } else if let Some(direct) = receipt.receipt_type.and_then(|r| {
                if let construct_server_shared::shared::proto::signaling::v1::delivery_receipt::ReceiptType::Direct(d) = r {
                    Some(d)
                } else {
                    None
                }
            }) && let Some(uid) = user_id {
                relay_delivery_receipt(context, direct, uid.to_string()).await?;
            }
        }
        Some(StreamReq::Typing(_))
        | Some(StreamReq::Subscribe(_))
        | Some(StreamReq::Unsubscribe(_)) => {
            // Not implemented yet
            tracing::debug!("Received unimplemented request type");
        }

        None => {
            tracing::warn!("Received empty stream request");
        }
    }

    Ok(())
}

/// Subscribe to `inbox:wakeup:{user_id}` via Redis pub/sub and forward signals
/// to `tx` so the stream loop can call `poll_messages` immediately on delivery.
///
/// Spawns a background task — exits automatically when the receiver is dropped
/// (i.e. the gRPC stream closes).
pub(crate) fn spawn_inbox_wakeup(redis_url: String, user_id: uuid::Uuid, tx: mpsc::Sender<()>) {
    tokio::spawn(async move {
        let channel = format!("inbox:wakeup:{}", user_id);
        let client = match redis::Client::open(redis_url.as_str()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "inbox_wakeup: failed to create Redis client");
                return;
            }
        };
        let mut pubsub = match client.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "inbox_wakeup: failed to open pub/sub connection");
                return;
            }
        };
        if let Err(e) = pubsub.subscribe(&channel).await {
            tracing::warn!(error = %e, "inbox_wakeup: failed to subscribe");
            return;
        }
        tracing::debug!(channel = %channel, "inbox_wakeup: subscribed");
        let mut stream = pubsub.into_on_message();
        while stream.next().await.is_some() {
            if tx.send(()).await.is_err() {
                break; // stream closed — receiver dropped
            }
        }
        tracing::debug!(channel = %channel, "inbox_wakeup: subscriber exited");
    });
}

/// Poll for new messages from Redis Streams
pub(crate) async fn poll_messages(
    context: &Arc<MessagingServiceContext>,
    user_id: uuid::Uuid,
    last_stream_id: &mut Option<String>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
) -> anyhow::Result<()> {
    let user_id_str = user_id.to_string();
    let limit = 50;

    let mut queue = context.queue.lock().await;
    let messages = queue
        .read_user_messages_from_stream(&user_id_str, None, last_stream_id.as_deref(), limit)
        .await?;

    drop(queue);

    for (stream_id, envelope) in messages {
        // Convert KafkaMessageEnvelope to the appropriate stream response
        let Some(envelope) = envelope else {
            *last_stream_id = Some(stream_id); // advance past corrupt/wrong-recipient entry
            continue;
        };

        let response = if matches!(
            envelope.message_type,
            construct_server_shared::kafka::types::MessageType::Receipt
        ) {
            // Parse receipt JSON and send as MessageStreamResponse::Receipt
            match build_receipt_response(&envelope) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to parse receipt envelope, skipping");
                    *last_stream_id = Some(stream_id);
                    continue;
                }
            }
        } else {
            let proto_envelope = convert_kafka_envelope_to_proto(envelope)?;
            proto::MessageStreamResponse {
                response: Some(proto::message_stream_response::Response::Message(
                    proto_envelope,
                )),
                response_id: None,
            }
        };

        tx.send(Ok(response)).await?;
        *last_stream_id = Some(stream_id);
    }

    Ok(())
}
