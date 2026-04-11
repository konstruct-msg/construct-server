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
    last_stream_id: &mut Option<String>,
) -> anyhow::Result<()> {
    use proto::message_stream_request::Request as StreamReq;

    match req.request {
        Some(StreamReq::Send(envelope)) => {
            let attempt_id = req.attempt_id.clone();

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
                            error_code: proto::ErrorCode::Internal.into(),
                            error_message: e.to_string(),
                            retryable: true,
                            retry_after_ms: None,
                        };
                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                            stream_cursor: None,
                            rate_limit_challenge: None,
                            attempt_id,
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
                    stream_cursor: None,
                    rate_limit_challenge: None,
                    attempt_id,
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

                // Prefer client-provided message_id for idempotency; generate only as fallback.
                use construct_server_shared::shared::proto::core::v1 as proto_core;
                let message_id = match &envelope.message_id_type {
                    Some(proto_core::envelope::MessageIdType::MessageId(id))
                        if !id.is_empty() =>
                    {
                        id.clone()
                    }
                    _ => uuid::Uuid::new_v4().to_string(),
                };

                // ── Sentinel check (ban/block/user-level rate limits) ───────
                // Must mirror the sentinel check in send_message gRPC so that limits
                // enforced on one transport are also enforced on the other.
                // Fails open — sentinel outage does not block message delivery.
                let sender_device_id = envelope
                    .sender_device
                    .as_ref()
                    .map(|d| d.device_id.as_str())
                    .unwrap_or("");
                let recipient_device_id = envelope
                    .recipient_device
                    .as_ref()
                    .map(|d| d.device_id.as_str())
                    .unwrap_or("");

                if let Some(ref sentinel) = context.sentinel_client
                    && !sender_device_id.is_empty()
                {
                    let target = if !recipient_device_id.is_empty() {
                        recipient_device_id
                    } else {
                        sender_device_id
                    };
                    let (allowed, reason, retry_after) = sentinel
                        .check_send_permission_with_user(
                            sender_device_id,
                            target,
                            &uid.to_string(),
                        )
                        .await;

                    if !allowed {
                        let (error_code, retryable, retry_after_ms) = if retry_after > 0 {
                            tracing::info!(sender = %uid, retry_after_secs = retry_after, reason = %reason, "Sentinel: stream send denied (rate limited)");
                            (proto::ErrorCode::RateLimit, true, Some((retry_after * 1000).into()))
                        } else {
                            tracing::info!(sender = %uid, reason = %reason, "Sentinel: stream send denied (banned or blocked)");
                            (proto::ErrorCode::Blocked, false, None)
                        };
                        let error = proto::MessageError {
                            message_id: message_id.clone(),
                            error_code: error_code.into(),
                            error_message: reason,
                            retryable,
                            retry_after_ms,
                        };
                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                            stream_cursor: None,
                            rate_limit_challenge: None,
                            attempt_id,
                        };
                        tx.send(Ok(response)).await?;
                        return Ok(());
                    }
                }

                // ── Rate limiting (same policy as send_message gRPC) ────────
                if let Ok(mut redis_conn) = context.redis_conn().await {
                    let trust =
                        crate::trust::get_trust_level(&mut redis_conn, &context.db_pool, *uid, &context.config.messaging)
                            .await;

                    if let Err(pow_level) =
                        crate::trust::check_hourly_rate(&mut redis_conn, &uid.to_string(), trust.hourly_limit(&context.config.messaging), &context.config.messaging)
                            .await
                    {
                        let (challenge, expires_at) = crate::trust::make_challenge(pow_level, &context.config.messaging);
                        tracing::info!(
                            sender = %uid,
                            pow_level,
                            "Rate limit exceeded — issuing PoW challenge (stream)"
                        );
                        let error = proto::MessageError {
                            message_id: message_id.clone(),
                            error_code: proto::ErrorCode::RateLimit.into(),
                            error_message: format!("Rate limit exceeded — solve PoW level {}", pow_level),
                            retryable: true,
                            retry_after_ms: None,
                        };
                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                            stream_cursor: None,
                            rate_limit_challenge: Some(proto::RateLimitChallenge {
                                challenge,
                                difficulty: pow_level,
                                expires_at,
                            }),
                            attempt_id,
                        };
                        tx.send(Ok(response)).await?;
                        return Ok(());
                    }

                    if let Some(fanout_limit) = trust.fanout_limit(&context.config.messaging)
                        && let Err(pow_level) =
                            crate::trust::check_fanout_rate(&mut redis_conn, &uid.to_string(), &recipient_id, fanout_limit, &context.config.messaging)
                                .await
                    {
                        let (challenge, expires_at) = crate::trust::make_challenge(pow_level, &context.config.messaging);
                        tracing::info!(
                            sender = %uid,
                            pow_level,
                            "Fanout limit exceeded — issuing PoW challenge (stream)"
                        );
                        let error = proto::MessageError {
                            message_id: message_id.clone(),
                            error_code: proto::ErrorCode::RateLimit.into(),
                            error_message: format!("Fanout limit exceeded — solve PoW level {}", pow_level),
                            retryable: true,
                            retry_after_ms: None,
                        };
                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                            stream_cursor: None,
                            rate_limit_challenge: Some(proto::RateLimitChallenge {
                                challenge,
                                difficulty: pow_level,
                                expires_at,
                            }),
                            attempt_id,
                        };
                        tx.send(Ok(response)).await?;
                        return Ok(());
                    }
                }

                use construct_server_shared::kafka::types::{
                    KafkaMessageEnvelope, ProtoEnvelopeContext,
                };
                let kafka_envelope =
                    KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
                        sender_id: uid.to_string(),
                        recipient_id,
                        message_id: message_id.clone(),
                        encrypted_payload: envelope.encrypted_payload.to_vec(),
                        content_type: envelope.content_type,
                        edits_message_id: envelope.edits_message_id.clone(),
                    });

                let app_context = Arc::new(context.to_app_context());
                match core::dispatch_envelope(
                    &app_context,
                    kafka_envelope,
                    context.notification_client.clone(),
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
                            stream_cursor: None,
                            rate_limit_challenge: None,
                            attempt_id,
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
                            error_code: proto::ErrorCode::Internal.into(),
                            error_message: e.to_string(),
                            retryable: true,
                            retry_after_ms: None,
                        };

                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                            stream_cursor: None,
                            rate_limit_challenge: None,
                            attempt_id,
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
                stream_cursor: None,
                rate_limit_challenge: None,
                attempt_id: req.attempt_id,
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
        Some(StreamReq::Subscribe(sub)) => {
            // conversation_ids are intentionally not logged or stored
            // to avoid leaking the client's contact graph to the server.
            // All messages for this user are already routed to their Redis stream regardless.
            //
            // If the subscribe carries a since_cursor, apply it as the resume position
            // so that reconnecting clients don't re-read the entire Redis stream.
            if let Some(cursor) = sub.since_cursor
                && !cursor.is_empty()
            {
                tracing::debug!(cursor = %cursor, "Resuming stream from client cursor");
                *last_stream_id = Some(cursor);
            }
        }
        Some(StreamReq::Unsubscribe(_)) => {
            // No-op: all messages are routed by user_id regardless of subscriptions
        }
        Some(StreamReq::Typing(_)) => {
            // Not implemented yet
            tracing::debug!("Received unimplemented request type (typing)");
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
/// (i.e. the gRPC stream closes). Automatically reconnects on Redis connection loss
/// so the fallback 5s poll is never triggered in normal operation.
///
/// **Race-condition protection**: sends a synthetic wakeup signal immediately after
/// each successful SUBSCRIBE. This triggers an extra `poll_messages` call that catches
/// any messages that were XADD'd to the stream between stream-open and subscribe
/// completion (~50 ms window), preventing up to 5 s delivery delay on reconnect.
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

        // Reconnect loop: on any connection/subscribe failure, wait briefly and retry.
        // Exits only when the gRPC stream closes (tx.send fails → receiver dropped).
        loop {
            let pubsub = match client.get_async_pubsub().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, channel = %channel, "inbox_wakeup: pub/sub connect failed, retrying in 2s");
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    continue;
                }
            };
            let mut pubsub = pubsub;
            if let Err(e) = pubsub.subscribe(&channel).await {
                tracing::warn!(error = %e, channel = %channel, "inbox_wakeup: subscribe failed, retrying in 2s");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }
            tracing::debug!(channel = %channel, "inbox_wakeup: subscribed");

            // Synthetic wakeup immediately after subscribe: polls for any messages
            // that were dispatched during the TCP-connect + SUBSCRIBE window (~50 ms).
            // Without this, those messages would wait for the next fallback poll (5s).
            if tx.send(()).await.is_err() {
                return; // stream closed
            }

            let mut stream = pubsub.into_on_message();
            loop {
                match stream.next().await {
                    Some(_) => {
                        if tx.send(()).await.is_err() {
                            // gRPC stream closed — receiver dropped, stop wakeup task
                            return;
                        }
                    }
                    None => {
                        // pub/sub connection dropped — break inner loop to reconnect
                        tracing::debug!(channel = %channel, "inbox_wakeup: connection lost, reconnecting");
                        break;
                    }
                }
            }
        }
    });
}

/// Poll for new messages from Redis Streams
///
/// Takes `queue` as a per-stream clone rather than locking the global
/// `context.queue` mutex. This allows concurrent XREAD calls from multiple
/// connected users without serializing on a single lock.
pub(crate) async fn poll_messages(
    queue: &mut construct_queue::MessageQueue,
    config: &construct_config::MessagingConfig,
    user_id: uuid::Uuid,
    last_stream_id: &mut Option<String>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
) -> anyhow::Result<()> {
    let user_id_str = user_id.to_string();
    let limit = 50;

    let t_xread = std::time::Instant::now();
    let messages = queue
        .read_user_messages_from_stream(&user_id_str, None, last_stream_id.as_deref(), limit)
        .await?;
    let xread_ms = t_xread.elapsed().as_millis();

    let msg_count = messages.len();
    if xread_ms > config.stream_xread_slow_ms {
        tracing::info!(xread_ms, msg_count, "poll_messages timing (slow)");
    }

    for (stream_id, envelope) in messages {
        // Convert KafkaMessageEnvelope to the appropriate stream response
        let Some(envelope) = envelope else {
            *last_stream_id = Some(stream_id); // advance past corrupt/wrong-recipient entry
            continue;
        };

        let mut response = if matches!(
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
                stream_cursor: None,
                rate_limit_challenge: None,
                attempt_id: None,
            }
        };

        // Attach the Redis stream position so the client can resume on the next
        // reconnect by passing stream_cursor as SubscribeRequest.since_cursor.
        response.stream_cursor = Some(stream_id.clone());

        tx.send(Ok(response)).await?;
        *last_stream_id = Some(stream_id);
    }

    Ok(())
}
