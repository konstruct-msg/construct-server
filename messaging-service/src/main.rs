mod handlers;
mod media_routes;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use construct_config::Config;
use construct_server_shared::apns::DeviceTokenEncryption;
use construct_server_shared::auth::AuthManager;
use construct_server_shared::db::DbPool;
use construct_server_shared::kafka::MessageProducer;
use construct_server_shared::messaging_service::MessagingServiceContext;
use construct_server_shared::queue::MessageQueue;
use futures_core::Stream;
use serde_json::json;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    messaging_service_server::{MessagingService, MessagingServiceServer},
};
use std::env;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct MessagingGrpcService {
    context: Arc<MessagingServiceContext>,
}

#[tonic::async_trait]
impl MessagingService for MessagingGrpcService {
    type MessageStreamStream =
        Pin<Box<dyn Stream<Item = Result<proto::MessageStreamResponse, Status>> + Send + 'static>>;

    async fn message_stream(
        &self,
        request: Request<tonic::Streaming<proto::MessageStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        // Extract authenticated user_id: first try x-user-id (set by gateway/proxy),
        // then fall back to Authorization Bearer JWT (set directly by the client).
        let auth_user_id: Option<uuid::Uuid> = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .or_else(|| {
                request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .and_then(|token| {
                        self.context
                            .auth_manager
                            .verify_token(token)
                            .ok()
                            .and_then(|claims| uuid::Uuid::parse_str(&claims.sub).ok())
                    })
            });

        let mut in_stream = request.into_inner();
        let context = self.context.clone();

        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            // Track last seen stream_id for pagination
            let mut last_stream_id: Option<String> = None;
            // Initialise from auth metadata; may also be set from first Send message
            let mut user_id: Option<uuid::Uuid> = auth_user_id;

            // Wakeup channel: Redis pub/sub listener signals us when a new message
            // arrives so we can deliver immediately without waiting for the next poll.
            let (wakeup_tx, mut wakeup_rx) = mpsc::channel::<()>(4);
            let mut wakeup_subscribed = false;

            // Fallback poll interval — reduced to 60 s now that pub/sub handles
            // real-time delivery; this only covers reconnects / missed events.
            let mut poll_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            // If user_id is already known from auth metadata, subscribe now and
            // flush any messages that arrived before the stream opened.
            if let Some(uid) = user_id {
                spawn_inbox_wakeup(context.config.redis_url.clone(), uid, wakeup_tx.clone());
                wakeup_subscribed = true;
                if let Err(e) = poll_messages(&context, uid, &mut last_stream_id, &tx).await {
                    tracing::warn!("Initial poll error: {}", e);
                }
            }

            loop {
                // Lazy subscribe: subscribe as soon as user_id becomes known
                // (e.g. from the first Send message if not in auth metadata).
                if !wakeup_subscribed {
                    if let Some(uid) = user_id {
                        spawn_inbox_wakeup(
                            context.config.redis_url.clone(),
                            uid,
                            wakeup_tx.clone(),
                        );
                        wakeup_subscribed = true;
                        if let Err(e) = poll_messages(&context, uid, &mut last_stream_id, &tx).await
                        {
                            tracing::warn!("Initial poll error: {}", e);
                        }
                    }
                }

                tokio::select! {
                    // Handle incoming requests from client
                    Some(result) = in_stream.next() => {
                        match result {
                            Ok(req) => {
                                if let Err(e) = handle_stream_request(
                                    req,
                                    &context,
                                    &tx,
                                    &mut user_id,
                                ).await {
                                    tracing::warn!("Error handling stream request: {}", e);
                                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                                    break;
                                }
                            }
                            Err(e) => {
                                // h2 protocol resets are normal client disconnects, not server errors
                                if e.message().contains("h2 protocol") {
                                    tracing::debug!("MessageStream closed by client: {}", e);
                                } else {
                                    tracing::warn!("Stream error: {}", e);
                                }
                                break;
                            }
                        }
                    }

                    // Push: new message arrived — deliver immediately
                    Some(()) = wakeup_rx.recv() => {
                        if let Some(uid) = user_id {
                            if let Err(e) = poll_messages(&context, uid, &mut last_stream_id, &tx).await {
                                tracing::warn!("Error polling messages after wakeup: {}", e);
                            }
                        }
                    }

                    // Fallback poll (covers missed pub/sub events and reconnects)
                    _ = poll_interval.tick() => {
                        if let Some(uid) = user_id && let Err(e) = poll_messages(
                                &context,
                                uid,
                                &mut last_stream_id,
                                &tx,
                            ).await {
                                tracing::warn!("Error polling messages: {}", e);
                            }
                        }

                    else => break,
                }
            }

            tracing::info!("MessageStream closed");
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::MessageStreamStream
        ))
    }

    async fn send_message(
        &self,
        request: Request<proto::SendMessageRequest>,
    ) -> Result<Response<proto::SendMessageResponse>, Status> {
        let req = request.into_inner();
        let envelope = req
            .message
            .ok_or_else(|| Status::invalid_argument("message is required"))?;

        // ── Sealed Sender path ──────────────────────────────────────────────
        if let Some(sealed) = &envelope.sealed_sender {
            let resp = dispatch_sealed_sender(&self.context, sealed)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            return Ok(Response::new(resp));
        }

        // ── Regular (local) message path ────────────────────────────────────
        let sender = envelope
            .sender
            .ok_or_else(|| Status::invalid_argument("sender is required"))?;
        let sender_id = uuid::Uuid::parse_str(&sender.user_id)
            .map_err(|_| Status::invalid_argument("invalid sender.user_id"))?;

        let recipient = envelope
            .recipient
            .ok_or_else(|| Status::invalid_argument("recipient is required"))?;

        if envelope.encrypted_payload.is_empty() {
            return Err(Status::invalid_argument("encrypted_payload is required"));
        }

        let message_id = uuid::Uuid::new_v4().to_string();

        use construct_server_shared::kafka::types::{KafkaMessageEnvelope, ProtoEnvelopeContext};
        let kafka_envelope = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: sender_id.to_string(),
            recipient_id: recipient.user_id.clone(),
            message_id: message_id.clone(),
            encrypted_payload: envelope.encrypted_payload.to_vec(),
        });

        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::messaging_service::core::dispatch_envelope(
            &app_context,
            kafka_envelope,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::SendMessageResponse {
            message_id,
            message_number: 0,
            server_timestamp: chrono::Utc::now().timestamp_millis(),
            success: true,
            error: None,
        }))
    }

    async fn edit_message(
        &self,
        _request: Request<proto::EditMessageRequest>,
    ) -> Result<Response<proto::EditMessageResponse>, Status> {
        Err(Status::unimplemented("edit_message is not implemented yet"))
    }

    // =========================================================================
    // Reactions RPCs (Stubs)
    // =========================================================================

    async fn add_reaction(
        &self,
        request: Request<proto::AddReactionRequest>,
    ) -> Result<Response<proto::AddReactionResponse>, Status> {
        let req = request.into_inner();

        if req.message_id.is_empty() {
            return Err(Status::invalid_argument("message_id is required"));
        }
        if req.encrypted_reaction.is_empty() {
            return Err(Status::invalid_argument("encrypted_reaction is required"));
        }

        // TODO: Implement add reaction
        // 1. Get authenticated user
        // 2. Validate message exists and user has access
        // 3. Store reaction (encrypted: sender + emoji)
        // 4. Notify message owner via streaming

        Err(Status::unimplemented("AddReaction not implemented yet"))
    }

    async fn remove_reaction(
        &self,
        request: Request<proto::RemoveReactionRequest>,
    ) -> Result<Response<proto::RemoveReactionResponse>, Status> {
        let req = request.into_inner();

        if req.message_id.is_empty() {
            return Err(Status::invalid_argument("message_id is required"));
        }
        if req.reaction_id.is_empty() {
            return Err(Status::invalid_argument("reaction_id is required"));
        }

        // TODO: Implement remove reaction
        // 1. Get authenticated user
        // 2. Validate user owns this reaction
        // 3. Remove reaction from storage
        // 4. Notify message owner via streaming

        Err(Status::unimplemented("RemoveReaction not implemented yet"))
    }

    async fn get_pending_messages(
        &self,
        request: Request<proto::GetPendingMessagesRequest>,
    ) -> Result<Response<proto::GetPendingMessagesResponse>, Status> {
        let user_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .and_then(|token| {
                        self.context
                            .auth_manager
                            .verify_token(token)
                            .ok()
                            .map(|claims| claims.sub)
                    })
            })
            .ok_or_else(|| Status::unauthenticated("Missing authentication"))?;

        let req = request.into_inner();
        let limit = req.limit.unwrap_or(50).min(100) as usize;
        let since = req.since_cursor.as_deref();

        let mut queue = self.context.queue.lock().await;
        let stream_messages = queue
            .read_user_messages_from_stream(&user_id, None, since, limit)
            .await
            .map_err(|e| Status::internal(format!("Failed to read messages: {}", e)))?;

        // encrypted_payload is opaque — server never reads crypto params from it.
        // Sort is by server timestamp (already chronological from Redis stream).
        let messages: Vec<proto::PendingMessage> = stream_messages
            .into_iter()
            .filter_map(|(_stream_id, env)| {
                let env = env?; // skip corrupt / wrong-recipient entries
                use base64::Engine;
                use construct_server_shared::kafka::types::MessageType;
                use construct_server_shared::shared::proto::core::v1 as core;

                // Receipts are ephemeral and must be delivered via active MessageStream only.
                // Returning stale receipts here would confuse clients (undecryptable payload).
                if matches!(env.message_type, MessageType::Receipt) {
                    return None;
                }

                let content_type = match env.message_type {
                    MessageType::ControlMessage => match env.encrypted_payload.as_str() {
                        "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
                        "KEY_SYNC" => core::ContentType::KeySync,
                        _ => core::ContentType::E2eeSignal,
                    },
                    _ => core::ContentType::E2eeSignal,
                };

                // For control messages (SESSION_RESET / END_SESSION / KEY_SYNC), the payload
                // is the ASCII control-type string — send empty bytes to the client so it
                // cannot mistake this for encrypted ciphertext it needs to decrypt.
                let payload_bytes = match content_type {
                    core::ContentType::SessionReset | core::ContentType::KeySync => vec![],
                    _ => base64::engine::general_purpose::STANDARD
                        .decode(&env.encrypted_payload)
                        .unwrap_or_else(|_| env.encrypted_payload.clone().into_bytes()),
                };

                Some(proto::PendingMessage {
                    message_id: env.message_id,
                    sender_id: env.sender_id,
                    encrypted_payload: payload_bytes,
                    timestamp: env.timestamp,
                    content_type: content_type.into(),
                })
            })
            .collect();

        let next_cursor = messages
            .last()
            .map(|m| format!("{}", m.timestamp))
            .unwrap_or_else(|| since.unwrap_or("0-0").to_string());

        let has_more = messages.len() == limit;

        Ok(Response::new(proto::GetPendingMessagesResponse {
            messages,
            next_cursor,
            has_more,
        }))
    }

    async fn request_key_sync(
        &self,
        request: Request<proto::RequestKeySyncRequest>,
    ) -> Result<Response<proto::RequestKeySyncResponse>, Status> {
        let sender_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .or_else(|| {
                request
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .and_then(|token| {
                        self.context
                            .auth_manager
                            .verify_token(token)
                            .ok()
                            .and_then(|claims| uuid::Uuid::parse_str(&claims.sub).ok())
                    })
            })
            .ok_or_else(|| Status::unauthenticated("Missing authentication"))?;

        let recipient_user_id = request.into_inner().recipient_user_id;
        if recipient_user_id.is_empty() {
            return Err(Status::invalid_argument("recipient_user_id is required"));
        }

        use construct_server_shared::kafka::types::KafkaMessageEnvelope;
        let envelope =
            KafkaMessageEnvelope::new_key_sync(sender_id.to_string(), recipient_user_id.clone());

        let mut queue = self.context.queue.lock().await;
        queue
            .write_message_to_user_stream(&recipient_user_id, &envelope)
            .await
            .map_err(|e| Status::internal(format!("Failed to queue KEY_SYNC: {e}")))?;

        tracing::info!(
            sender = %sender_id,
            recipient = %recipient_user_id,
            "KEY_SYNC queued"
        );

        Ok(Response::new(proto::RequestKeySyncResponse {}))
    }
}

/// Handle incoming MessageStreamRequest from client
async fn handle_stream_request(
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
                match construct_server_shared::messaging_service::core::dispatch_envelope(
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
fn spawn_inbox_wakeup(redis_url: String, user_id: uuid::Uuid, tx: mpsc::Sender<()>) {
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
async fn poll_messages(
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

/// Convert KafkaMessageEnvelope to proto Envelope
fn convert_kafka_envelope_to_proto(
    envelope: construct_server_shared::kafka::types::KafkaMessageEnvelope,
) -> anyhow::Result<construct_server_shared::shared::proto::core::v1::Envelope> {
    use base64::Engine;
    use construct_server_shared::kafka::types::MessageType;
    use construct_server_shared::shared::proto::core::v1 as core;

    // Sealed sender — reconstruct SealedSenderEnvelope, hide sender from proto.
    if envelope.is_sealed_sender {
        let sealed_inner_bytes = envelope
            .sealed_inner_b64
            .as_deref()
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .unwrap_or_default();

        return Ok(core::Envelope {
            sender: None, // anonymous — server does not know sender
            sender_device: None,
            recipient: Some(core::UserId {
                user_id: envelope.recipient_id,
                domain: None,
                display_name: None,
            }),
            recipient_device: None,
            content_type: core::ContentType::E2eeSignal.into(),
            message_id_type: Some(core::envelope::MessageIdType::MessageId(
                envelope.message_id,
            )),
            timestamp: envelope.timestamp,
            ttl: 0,
            priority: core::MessagePriority::Normal.into(),
            encrypted_payload: vec![],
            conversation_id: String::new(),
            server_metadata: None,
            client_metadata: None,
            forwarding_path: vec![],
            ephemeral_seconds: None,
            reply_to_message_id: None,
            edits_message_id: None,
            reactions: vec![],
            mentions: vec![],
            sealed_sender: Some(core::SealedSenderEnvelope {
                recipient_server: String::new(),
                sealed_inner: sealed_inner_bytes,
                forwarding_token: vec![],
                timestamp: 0,
            }),
        });
    }

    // Map Kafka MessageType → proto ContentType so clients can detect control messages
    // (SESSION_RESET, END_SESSION, KEY_SYNC) without trying to decrypt them.
    let content_type = match envelope.message_type {
        MessageType::ControlMessage => match envelope.encrypted_payload.as_str() {
            "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
            "KEY_SYNC" => core::ContentType::KeySync,
            _ => core::ContentType::E2eeSignal,
        },
        _ => core::ContentType::E2eeSignal,
    };

    // For control messages, send empty payload — the ASCII type string ("END_SESSION",
    // "SESSION_RESET") is NOT ciphertext and must not be passed to the decryption layer.
    let payload_bytes = match content_type {
        core::ContentType::SessionReset | core::ContentType::KeySync => vec![],
        _ => base64::engine::general_purpose::STANDARD
            .decode(&envelope.encrypted_payload)
            .unwrap_or_else(|_| envelope.encrypted_payload.into_bytes()),
    };

    Ok(core::Envelope {
        sender: Some(core::UserId {
            user_id: envelope.sender_id,
            domain: None,
            display_name: None,
        }),
        sender_device: None,
        recipient: Some(core::UserId {
            user_id: envelope.recipient_id,
            domain: None,
            display_name: None,
        }),
        recipient_device: None,
        content_type: content_type.into(),
        message_id_type: Some(core::envelope::MessageIdType::MessageId(
            envelope.message_id,
        )),
        timestamp: envelope.timestamp,
        ttl: 0,
        priority: core::MessagePriority::Normal.into(),
        encrypted_payload: payload_bytes,
        conversation_id: String::new(),
        server_metadata: None,
        client_metadata: None,
        forwarding_path: vec![],
        ephemeral_seconds: None,
        reply_to_message_id: None,
        edits_message_id: None,
        reactions: vec![],
        mentions: vec![],
        sealed_sender: None,
    })
}

/// Route a SealedSenderEnvelope:
///  - Cross-server (recipient_server ≠ ours): forward via FederationClient
///  - Local (same server or empty): parse SealedInner → deliver to recipient_user_id
async fn dispatch_sealed_sender(
    context: &Arc<MessagingServiceContext>,
    sealed: &construct_server_shared::shared::proto::core::v1::SealedSenderEnvelope,
) -> anyhow::Result<proto::SendMessageResponse> {
    use construct_server_shared::federation::FederationClient;
    use construct_server_shared::kafka::types::KafkaMessageEnvelope;
    use construct_server_shared::shared::proto::core::v1 as core;
    use prost::Message;

    let our_domain = &context.config.federation.instance_domain;
    let message_id = uuid::Uuid::new_v4().to_string();

    // Cross-server: forward sealed_inner opaquely to recipient server
    if !sealed.recipient_server.is_empty() && sealed.recipient_server != *our_domain {
        let target = &sealed.recipient_server;
        let client = match &context.server_signer {
            Some(signer) => FederationClient::new_with_signer(signer.clone(), our_domain.clone()),
            None => FederationClient::new(),
        };

        client
            .send_sealed_message(target, &message_id, &sealed.sealed_inner, sealed.timestamp)
            .await
            .map_err(|e| anyhow::anyhow!("Sealed sender federation failed to {}: {}", target, e))?;

        return Ok(proto::SendMessageResponse {
            message_id,
            message_number: 0,
            server_timestamp: chrono::Utc::now().timestamp_millis(),
            success: true,
            error: None,
        });
    }

    // Local delivery: decode SealedInner to get recipient_user_id
    let sealed_inner = core::SealedInner::decode(sealed.sealed_inner.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decode SealedInner: {}", e))?;

    let recipient_id = sealed_inner.recipient_user_id.clone();
    if recipient_id.is_empty() {
        anyhow::bail!("SealedInner.recipient_user_id is required");
    }

    let kafka_envelope = KafkaMessageEnvelope::from_sealed_sender(
        message_id.clone(),
        recipient_id,
        sealed.sealed_inner.to_vec(),
    );

    let app_context = Arc::new(context.to_app_context());
    construct_server_shared::messaging_service::core::dispatch_envelope(
        &app_context,
        kafka_envelope,
    )
    .await?;

    Ok(proto::SendMessageResponse {
        message_id,
        message_number: 0,
        server_timestamp: chrono::Utc::now().timestamp_millis(),
        success: true,
        error: None,
    })
}

/// Relay a DeliveryReceipt from the recipient to the original sender's stream.
///
/// Looks up the original sender via the Redis `receipt:sender:{message_id}` mapping
/// stored by `dispatch_envelope()`. Writes a Receipt-type envelope to the sender's
/// offline delivery stream so they pick it up on the next poll.
async fn relay_delivery_receipt(
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
    // Primary lookup: Redis (fast). Fallback: delivery_pending DB table (survives Redis restarts).
    let mut sender_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for message_id in &direct.message_ids {
        // Try Redis first
        let redis_result = {
            let mut queue = context.queue.lock().await;
            queue.get_message_sender(message_id).await
        };

        let sender_id = match redis_result {
            Ok(Some(id)) => Some(id),
            Ok(None) => {
                // Redis miss — fall back to DB
                let hash_salt = &context.config.logging.hash_salt;
                let message_hash =
                    construct_server_shared::messaging_service::core::receipt_routing_hash(
                        message_id, hash_salt,
                    );
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
            tracing::debug!(sender_id = %sender_id, status, "Relayed delivery receipt to sender stream");
        }
    }

    Ok(())
}

/// Build a MessageStreamResponse::Receipt from a Receipt-type KafkaMessageEnvelope.
fn build_receipt_response(
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
        _ => 1i32, // delivered
    };

    let direct = signaling::DirectReceipt {
        message_ids: payload.message_ids,
        status,
        timestamp: payload.timestamp,
        sender_device_id: String::new(),
    };

    let receipt = signaling::DeliveryReceipt {
        receipt_type: Some(signaling::delivery_receipt::ReceiptType::Direct(direct)),
    };

    Ok(proto::MessageStreamResponse {
        response: Some(proto::message_stream_response::Response::Receipt(receipt)),
        response_id: None,
    })
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== Messaging Service Starting ===");
    info!("Port: {}", config.port);

    // Initialize database
    info!("Connecting to database...");
    let db_pool = Arc::new(
        DbPool::connect(&config.database_url)
            .await
            .context("Failed to connect to database")?,
    );
    info!("Connected to database");

    // Apply database migrations
    info!("Applying database migrations...");
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await
        .context("Failed to apply database migrations")?;
    info!("Database migrations applied successfully");

    // Initialize Redis
    info!("Connecting to Redis...");
    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .context("Failed to create message queue")?,
    ));
    info!("Connected to Redis");

    // Initialize Kafka Producer
    info!("Connecting to Kafka...");
    let kafka_producer =
        Arc::new(MessageProducer::new(&config.kafka).context("Failed to create Kafka producer")?);
    info!("Connected to Kafka");

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // ✅ NEW: Initialize APNs Client for push notifications
    info!("Initializing APNs client...");
    let apns_client = Arc::new(
        construct_server_shared::apns::ApnsClient::new(config.apns.clone())
            .context("Failed to initialize APNs client")?,
    );
    if let Err(e) = apns_client.initialize().await {
        if config.apns.enabled {
            tracing::error!(
                error = %e,
                key_path = %config.apns.key_path,
                "APNs initialization failed — push notifications DISABLED until key is deployed"
            );
        }
    } else if config.apns.enabled {
        info!("APNs client initialized and ENABLED");
    } else {
        info!("APNs client initialized but DISABLED (APNS_ENABLED=false)");
    }
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .context("Failed to initialize device token encryption")?,
    );

    // Initialize Key Management System (optional, requires VAULT_ADDR)
    let key_management =
        match construct_server_shared::key_management::KeyManagementConfig::from_env() {
            Ok(kms_config) => {
                info!("Initializing Key Management System...");
                match construct_server_shared::key_management::KeyManagementSystem::new(
                    db_pool.clone(),
                    kms_config,
                )
                .await
                {
                    Ok(kms) => {
                        // Start background tasks (key refresh, rotation)
                        if let Err(e) = kms.start().await {
                            tracing::error!(error = %e, "Failed to start key management background tasks");
                            return Err(e).context("Failed to start key management system");
                        }
                        info!("Key Management System initialized and started");
                        Some(Arc::new(kms))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to initialize Key Management System - continuing without automatic key rotation"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "Key Management System disabled (VAULT_ADDR not configured or invalid config)"
                );
                None
            }
        };

    // Initialize server signer for federation (sealed sender cross-server forwarding)
    let server_signer =
        construct_server_shared::context::AppContext::init_server_signer_pub(&config);

    // Create service context
    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management,
        server_signer,
    });

    // handlers module is local (messaging-service/src/handlers.rs)

    // Start gRPC MessagingService (SVC-3 scaffold)
    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("MESSAGING_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50053".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Invalid MESSAGING_GRPC_BIND_ADDRESS")?;
    // Replace bare .serve() with graceful shutdown for gRPC
    tokio::spawn(async move {
        let service = MessagingGrpcService {
            context: grpc_context,
        };
        if let Err(e) = construct_server_shared::grpc_server()
            .add_service(MessagingServiceServer::new(service))
            .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal())
            .await
        {
            tracing::error!(error = %e, "Messaging gRPC server failed");
        }
    });
    info!("Messaging gRPC listening on {}", grpc_bind_address);

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        )
        // Phase 4.5: Control messages endpoint
        .route("/api/v1/control", post(handlers::send_control_message))
        // Media upload token endpoint
        .route(
            "/api/v1/media/token",
            post(media_routes::generate_media_token),
        )
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("Messaging Service listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start server")?;

    Ok(())
}
