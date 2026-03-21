use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::context::MessagingServiceContext;
use crate::core;
use crate::envelope::dispatch_sealed_sender;
use crate::stream::{handle_stream_request, poll_messages, spawn_inbox_wakeup};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, messaging_service_server::MessagingService,
};

#[derive(Clone)]
pub(crate) struct MessagingGrpcService {
    pub(crate) context: Arc<MessagingServiceContext>,
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

            // Fallback poll interval — 30 s safety net for any missed pub/sub wakeup.
            // Real-time delivery is handled by spawn_inbox_wakeup (Redis pub/sub with
            // auto-reconnect). This fallback ensures at most 30s lag if wakeup is lost,
            // without flooding the shared queue Mutex with frequent polls.
            let mut poll_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

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
                if !wakeup_subscribed && let Some(uid) = user_id {
                    spawn_inbox_wakeup(context.config.redis_url.clone(), uid, wakeup_tx.clone());
                    wakeup_subscribed = true;
                    if let Err(e) = poll_messages(&context, uid, &mut last_stream_id, &tx).await {
                        tracing::warn!("Initial poll error: {}", e);
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
                        if let Some(uid) = user_id
                            && let Err(e) = poll_messages(&context, uid, &mut last_stream_id, &tx).await {
                                tracing::warn!("Error polling messages after wakeup: {}", e);
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

        // Reject oversized payloads before any DB work.
        // 64 KB matches client-side WirePayload limit (~6 KB typical + 100× headroom).
        const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
        if envelope.encrypted_payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Status::invalid_argument(format!(
                "encrypted_payload exceeds maximum size ({} > {} bytes)",
                envelope.encrypted_payload.len(),
                MAX_PAYLOAD_BYTES
            )));
        }

        // Use client-provided message_id (echo back per proto contract).
        // Priority: envelope.message_id → idempotency_key → generated UUID.
        let message_id = {
            use construct_server_shared::shared::proto::core::v1 as core;
            match &envelope.message_id_type {
                Some(core::envelope::MessageIdType::MessageId(id)) if !id.is_empty() => id.clone(),
                _ => req
                    .idempotency_key
                    .as_deref()
                    .filter(|k| !k.is_empty())
                    .map(|k| k.to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            }
        };

        use construct_server_shared::kafka::types::{KafkaMessageEnvelope, ProtoEnvelopeContext};

        // Block check: if recipient has blocked sender → return BLOCKED (not an error status).
        let recipient_id_uuid = uuid::Uuid::parse_str(&recipient.user_id)
            .map_err(|_| Status::invalid_argument("invalid recipient.user_id"))?;
        let blocked = construct_server_shared::db::is_blocked_by(
            &self.context.db_pool,
            &recipient_id_uuid,
            &sender_id,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        if blocked {
            return Ok(Response::new(proto::SendMessageResponse {
                message_id: message_id.clone(),
                message_number: 0,
                server_timestamp: chrono::Utc::now().timestamp_millis(),
                success: false,
                error: Some(proto::MessageError {
                    message_id,
                    error_code: proto::ErrorCode::Blocked.into(),
                    error_message: "Recipient has blocked you".to_string(),
                    retryable: false,
                }),
            }));
        }

        let kafka_envelope = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: sender_id.to_string(),
            recipient_id: recipient.user_id.clone(),
            message_id: message_id.clone(),
            encrypted_payload: envelope.encrypted_payload.to_vec(),
            content_type: envelope.content_type,
            edits_message_id: envelope.edits_message_id.clone(),
        });

        let app_context = Arc::new(self.context.to_app_context());
        core::dispatch_envelope(&app_context, kafka_envelope)
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
        request: Request<proto::EditMessageRequest>,
    ) -> Result<Response<proto::EditMessageResponse>, Status> {
        // Extract authenticated sender_id from x-user-id header or Bearer JWT
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

        let req = request.into_inner();
        if req.message_id.is_empty() {
            return Err(Status::invalid_argument("message_id is required"));
        }
        if req.recipient_user_id.is_empty() {
            return Err(Status::invalid_argument("recipient_user_id is required"));
        }
        if req.new_encrypted_content.is_empty() {
            return Err(Status::invalid_argument(
                "new_encrypted_content is required",
            ));
        }

        // Increment edit count in Redis. Key: edits:{message_id}, TTL 7 days.
        // This lets the client display "edited N times" and lets the server
        // enforce a hard cap to prevent edit-spam.
        const MAX_EDITS: u32 = 20;
        const EDIT_TTL_SECS: u64 = 7 * 24 * 3600;
        let edit_count = {
            let mut queue = self.context.queue.lock().await;
            queue
                .increment_edit_count(&req.message_id, EDIT_TTL_SECS)
                .await
                .map_err(|e| Status::internal(format!("Redis error: {e}")))?
        };
        if edit_count > MAX_EDITS {
            return Err(Status::resource_exhausted(format!(
                "edit limit of {MAX_EDITS} exceeded"
            )));
        }

        let edited_at = chrono::Utc::now().timestamp_millis();
        let new_message_id = uuid::Uuid::new_v4().to_string();

        use construct_server_shared::kafka::types::KafkaMessageEnvelope;
        let envelope = KafkaMessageEnvelope::from_edit(
            new_message_id,
            sender_id.to_string(),
            req.recipient_user_id.clone(),
            req.message_id.clone(),
            req.new_encrypted_content.to_vec(),
        );

        let mut queue = self.context.queue.lock().await;
        queue
            .write_message_to_user_stream(&req.recipient_user_id, &envelope)
            .await
            .map_err(|e| Status::internal(format!("Failed to queue edit: {e}")))?;

        tracing::info!(
            sender = %sender_id,
            recipient = %req.recipient_user_id,
            original_message_id = %req.message_id,
            edit_count = edit_count,
            "Message edit queued"
        );

        Ok(Response::new(proto::EditMessageResponse {
            success: true,
            edited_at,
            edit_count,
        }))
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

        // Hold the lock only for the XREAD operation — release immediately after so other
        // handlers (other getPendingMessages calls, send_message) are not blocked during
        // the message-building loop below.
        let stream_messages = {
            let mut queue = self.context.queue.lock().await;
            queue
                .read_user_messages_from_stream(&user_id, None, since, limit)
                .await
                .map_err(|e| Status::internal(format!("Failed to read messages: {}", e)))?
        };

        // encrypted_payload is opaque — server never reads crypto params from it.
        // Sort is by server timestamp (already chronological from Redis stream).
        // Track the last Redis stream ID so the cursor advances correctly.
        // NOTE: we must use the Redis stream ID (millisecond timestamp) as cursor,
        // not env.timestamp (Unix seconds) — using seconds caused all messages to
        // be re-delivered on every GetPendingMessages call.
        let mut last_stream_id: Option<String> = None;
        let messages: Vec<proto::PendingMessage> = stream_messages
            .into_iter()
            .filter_map(|(stream_id, env)| {
                // Always advance the cursor past this entry, even if we skip it.
                last_stream_id = Some(stream_id);

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

        let next_cursor = last_stream_id.unwrap_or_else(|| since.unwrap_or("0-0").to_string());

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
