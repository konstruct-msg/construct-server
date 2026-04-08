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
        let auth_user_id: Option<uuid::Uuid> =
            extract_authed_user_id(request.metadata(), &self.context).await;

        let mut in_stream = request.into_inner();
        let context = self.context.clone();

        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            // Per-stream queue clone — avoids contention on the global context.queue mutex.
            // ConnectionManager is Clone and pipelines commands internally, so concurrent
            // XREAD calls from different stream tasks can proceed in parallel.
            let mut stream_queue = context.queue.lock().await.clone();

            // Track last seen stream_id for pagination
            let mut last_stream_id: Option<String> = None;
            // Initialise from auth metadata; may also be set from first Send message
            let mut user_id: Option<uuid::Uuid> = auth_user_id;

            // Unique ID for this stream connection — used to correlate open/close log lines
            let stream_conn_id = uuid::Uuid::new_v4();
            let stream_opened_at = std::time::Instant::now();
            tracing::info!(
                stream_conn_id = %stream_conn_id,
                user_id = user_id.map(|u| u.to_string()).unwrap_or_default(),
                "MessageStream opened"
            );

            // Wakeup channel: Redis pub/sub listener signals us when a new message
            // arrives so we can deliver immediately without waiting for the next poll.
            let (wakeup_tx, mut wakeup_rx) = mpsc::channel::<()>(4);
            let mut wakeup_subscribed = false;

            // Fallback poll interval — safety net for any missed pub/sub wakeup.
            // Real-time delivery is handled by spawn_inbox_wakeup (Redis pub/sub with
            // auto-reconnect). This fallback caps worst-case delay if a wakeup signal
            // is missed during the pub/sub subscribe race window (~50ms at stream open).
            let mut poll_interval = tokio::time::interval(tokio::time::Duration::from_secs(
                context.config.messaging.stream_poll_fallback_secs,
            ));

            // Server-initiated keepalive: send a HeartbeatAck to the client every 30 s
            // when the stream is otherwise idle. This keeps the H2 stream active so that
            // the HTTP/2 PING frames fire and NAT/firewalls/ICE proxies do not silently
            // drop the connection. tonic 0.14 does not expose keepalive_while_idle, so
            // application-level traffic is the only way to maintain idle streams.
            let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(
                context.config.messaging.stream_heartbeat_interval_secs,
            ));

            // If user_id is already known from auth metadata, subscribe now and
            // flush any messages that arrived before the stream opened.
            if let Some(uid) = user_id {
                spawn_inbox_wakeup(context.config.redis_url.clone(), uid, wakeup_tx.clone());
                wakeup_subscribed = true;
                if let Err(e) = stream_queue
                    .track_user_online(&uid.to_string(), &context.server_instance_id)
                    .await
                {
                    tracing::warn!(user_id = %uid, "track_user_online failed: {}", e);
                }
                if let Err(e) = poll_messages(
                    &mut stream_queue,
                    &context.config.messaging,
                    uid,
                    &mut last_stream_id,
                    &tx,
                )
                .await
                {
                    tracing::warn!("Initial poll error: {}", e);
                }
            }

            let close_reason = 'stream: loop {
                // Lazy subscribe: subscribe as soon as user_id becomes known
                // (e.g. from the first Send message if not in auth metadata).
                if !wakeup_subscribed && let Some(uid) = user_id {
                    spawn_inbox_wakeup(context.config.redis_url.clone(), uid, wakeup_tx.clone());
                    wakeup_subscribed = true;
                    if let Err(e) = stream_queue
                        .track_user_online(&uid.to_string(), &context.server_instance_id)
                        .await
                    {
                        tracing::warn!(user_id = %uid, "track_user_online failed: {}", e);
                    }
                    if let Err(e) = poll_messages(
                        &mut stream_queue,
                        &context.config.messaging,
                        uid,
                        &mut last_stream_id,
                        &tx,
                    )
                    .await
                    {
                        tracing::warn!("Initial poll error: {}", e);
                    }
                }

                tokio::select! {
                    // Handle incoming requests from client — also catches None (graceful close)
                    result = in_stream.next() => {
                        match result {
                            Some(Ok(req)) => {
                                if let Err(e) = handle_stream_request(
                                    req,
                                    &context,
                                    &tx,
                                    &mut user_id,
                                    &mut last_stream_id,
                                ).await {
                                    tracing::warn!(error = %e, "Error handling stream request");
                                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                                    break 'stream "handler_error";
                                }
                            }
                            Some(Err(e)) => {
                                // Classify the disconnect so we know what's normal vs unexpected
                                let msg = e.message();
                                if msg.contains("h2 protocol")
                                    || msg.contains("connection closed")
                                    || msg.contains("broken pipe")
                                    || msg.contains("reset by peer")
                                    || e.code() == tonic::Code::Cancelled
                                {
                                    // Normal: iOS backgrounding / keepalive timeout / client restart
                                    tracing::info!(
                                        code = ?e.code(),
                                        message = %msg,
                                        "MessageStream: client disconnected (normal)"
                                    );
                                    break 'stream "client_disconnect";
                                } else {
                                    tracing::warn!(
                                        code = ?e.code(),
                                        error = %e,
                                        "MessageStream: unexpected stream error"
                                    );
                                    break 'stream "stream_error";
                                }
                            }
                            None => {
                                // Client closed the request side of the stream gracefully
                                tracing::info!("MessageStream: client closed input stream (graceful)");
                                break 'stream "client_eof";
                            }
                        }
                    }

                    // Push: new message arrived — deliver immediately
                    Some(()) = wakeup_rx.recv() => {
                        if let Some(uid) = user_id
                            && let Err(e) = poll_messages(&mut stream_queue, &context.config.messaging, uid, &mut last_stream_id, &tx).await {
                                tracing::warn!("Error polling messages after wakeup: {}", e);
                            }
                    }

                    // Fallback poll (covers missed pub/sub events and reconnects)
                    _ = poll_interval.tick() => {
                        if let Some(uid) = user_id && let Err(e) = poll_messages(
                                &mut stream_queue,
                                &context.config.messaging,
                                uid,
                                &mut last_stream_id,
                                &tx,
                            ).await {
                                tracing::warn!("Error polling messages: {}", e);
                            }
                        }

                    // Server-initiated keepalive: send a HeartbeatAck so the H2 stream
                    // stays active and tonic's keepalive PINGs are triggered even during
                    // periods with no user messages (idle chats, background app state).
                    _ = heartbeat_interval.tick() => {
                        let ack = proto::HeartbeatAck {
                            timestamp: 0, // server-initiated; no prior client ping to echo
                            server_timestamp: chrono::Utc::now().timestamp_millis(),
                        };
                        if tx.send(Ok(proto::MessageStreamResponse {
                            response_id: None,
                            stream_cursor: None,
                            rate_limit_challenge: None,
                            attempt_id: None,
                            response: Some(
                                proto::message_stream_response::Response::HeartbeatAck(ack),
                            ),
                        })).await.is_err() {
                            break 'stream "heartbeat_tx_closed";
                        }
                    }

                    else => break 'stream "all_channels_closed",
                }
            };

            let lifetime_secs = stream_opened_at.elapsed().as_secs();
            tracing::info!(
                stream_conn_id = %stream_conn_id,
                user_id = user_id.map(|u| u.to_string()).unwrap_or_default(),
                reason = close_reason,
                lifetime_secs,
                "MessageStream closed"
            );

            if let Some(uid) = user_id
                && let Err(e) = stream_queue.untrack_user_online(&uid.to_string()).await
            {
                tracing::warn!(user_id = %uid, "untrack_user_online failed: {}", e);
            }
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
        let attempt_id = req.attempt_id.clone();
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

        validate_payload(&envelope.encrypted_payload).map_err(Status::invalid_argument)?;

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

        // ── Early idempotency fast-path ─────────────────────────────────────────
        // Check if this message_id was already dispatched BEFORE touching rate
        // counters.  Client retries after a disconnect share the same message_id,
        // so without this check every retry inflates the hourly rate counter.
        {
            let mut queue = self.context.queue.lock().await;
            match queue.is_message_duplicate(&message_id).await {
                Ok(true) => {
                    tracing::debug!(
                        message_id = %message_id,
                        "send_message: duplicate retry — returning cached success"
                    );
                    return Ok(Response::new(proto::SendMessageResponse {
                        message_id,
                        message_number: 0,
                        server_timestamp: chrono::Utc::now().timestamp_millis(),
                        success: true,
                        error: None,
                        rate_limit_challenge: None,
                        attempt_id: attempt_id.clone(),
                    }));
                }
                Ok(false) => {} // first time — proceed to rate check
                Err(_) => {}    // fail-open: Redis unavailable, proceed normally
            }
        }

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
                    retry_after_ms: None,
                }),
                rate_limit_challenge: None,
                attempt_id: attempt_id.clone(),
            }));
        }

        // Sentinel check: rate limits and spam/ban enforcement.
        // Fails open — a sentinel outage or missing device_id does not block messaging.
        // Uses device_id (not user_id): sentinel keys are SHA256(pubkey)[0..16].
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

        if let Some(ref sentinel) = self.context.sentinel_client
            && !sender_device_id.is_empty()
        {
            let target = if !recipient_device_id.is_empty() {
                recipient_device_id
            } else {
                // Recipient device unknown: skip block check, only enforce sender limits.
                sender_device_id
            };
            let (allowed, reason, retry_after) = sentinel
                .check_send_permission(sender_device_id, target)
                .await;

            if !allowed {
                if retry_after > 0 {
                    tracing::info!(
                        sender = %sender_id,
                        retry_after_secs = retry_after,
                        reason = %reason,
                        "Sentinel: send denied (rate limited)"
                    );
                    return Ok(Response::new(proto::SendMessageResponse {
                        message_id: message_id.clone(),
                        message_number: 0,
                        server_timestamp: chrono::Utc::now().timestamp_millis(),
                        success: false,
                        error: Some(proto::MessageError {
                            message_id,
                            error_code: proto::ErrorCode::RateLimit.into(),
                            error_message: reason,
                            retryable: true,
                            retry_after_ms: Some((retry_after * 1000).into()),
                        }),
                        rate_limit_challenge: None,
                        attempt_id: attempt_id.clone(),
                    }));
                } else {
                    tracing::info!(
                        sender = %sender_id,
                        reason = %reason,
                        "Sentinel: send denied (banned or blocked)"
                    );
                    return Ok(Response::new(proto::SendMessageResponse {
                        message_id: message_id.clone(),
                        message_number: 0,
                        server_timestamp: chrono::Utc::now().timestamp_millis(),
                        success: false,
                        error: Some(proto::MessageError {
                            message_id,
                            error_code: proto::ErrorCode::Blocked.into(),
                            error_message: reason,
                            retryable: false,
                            retry_after_ms: None,
                        }),
                        rate_limit_challenge: None,
                        attempt_id: attempt_id.clone(),
                    }));
                }
            }
        }

        // ── TrustLevel + rate limiting ─────────────────────────────────────────
        // Fail-open: if Redis is unavailable we skip rate checks and default to
        // TrustLevel::Trusted so no messages are lost due to a Redis hiccup.
        let t_rate = std::time::Instant::now();
        let mut trust_level = crate::trust::TrustLevel::Trusted;
        if let Ok(mut redis_conn) = self.context.redis_conn().await {
            let trust = crate::trust::get_trust_level(
                &mut redis_conn,
                &self.context.db_pool,
                sender_id,
                &self.context.config.messaging,
            )
            .await;
            trust_level = trust;

            // Hourly message rate check
            let hourly_result = crate::trust::check_hourly_rate(
                &mut redis_conn,
                &sender_id.to_string(),
                trust.hourly_limit(&self.context.config.messaging),
                &self.context.config.messaging,
            )
            .await;

            if let Err(pow_level) = hourly_result {
                let (challenge, expires_at) =
                    crate::trust::make_challenge(pow_level, &self.context.config.messaging);
                tracing::info!(
                    sender = %sender_id,
                    pow_level,
                    "Rate limit exceeded — issuing PoW challenge"
                );
                return Ok(Response::new(proto::SendMessageResponse {
                    message_id: message_id.clone(),
                    message_number: 0,
                    server_timestamp: chrono::Utc::now().timestamp_millis(),
                    success: false,
                    error: Some(proto::MessageError {
                        message_id: message_id.clone(),
                        error_code: proto::ErrorCode::RateLimit.into(),
                        error_message: format!(
                            "Rate limit exceeded — solve PoW level {}",
                            pow_level
                        ),
                        retryable: true,
                        retry_after_ms: None,
                    }),
                    rate_limit_challenge: Some(proto::RateLimitChallenge {
                        challenge,
                        difficulty: pow_level,
                        expires_at,
                    }),
                    attempt_id: attempt_id.clone(),
                }));
            }

            // Daily fanout limit check
            if let Some(fanout_limit) = trust.fanout_limit(&self.context.config.messaging) {
                let fanout_result = crate::trust::check_fanout_rate(
                    &mut redis_conn,
                    &sender_id.to_string(),
                    &recipient.user_id,
                    fanout_limit,
                    &self.context.config.messaging,
                )
                .await;

                if let Err(pow_level) = fanout_result {
                    let (challenge, expires_at) =
                        crate::trust::make_challenge(pow_level, &self.context.config.messaging);
                    tracing::info!(
                        sender = %sender_id,
                        pow_level,
                        "Fanout limit exceeded — issuing PoW challenge"
                    );
                    return Ok(Response::new(proto::SendMessageResponse {
                        message_id: message_id.clone(),
                        message_number: 0,
                        server_timestamp: chrono::Utc::now().timestamp_millis(),
                        success: false,
                        error: Some(proto::MessageError {
                            message_id: message_id.clone(),
                            error_code: proto::ErrorCode::RateLimit.into(),
                            error_message: format!(
                                "Fanout limit exceeded — solve PoW level {}",
                                pow_level
                            ),
                            retryable: true,
                            retry_after_ms: None,
                        }),
                        rate_limit_challenge: Some(proto::RateLimitChallenge {
                            challenge,
                            difficulty: pow_level,
                            expires_at,
                        }),
                        attempt_id: attempt_id.clone(),
                    }));
                }
            }
        }

        let t_dispatch = std::time::Instant::now();
        let rate_ms = t_dispatch.duration_since(t_rate).as_millis();
        let mut kafka_envelope = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: sender_id.to_string(),
            recipient_id: recipient.user_id.clone(),
            message_id: message_id.clone(),
            encrypted_payload: envelope.encrypted_payload.to_vec(),
            content_type: envelope.content_type,
            edits_message_id: envelope.edits_message_id.clone(),
        });
        kafka_envelope.max_queue_len =
            Some(trust_level.queue_maxlen(&self.context.config.messaging));

        let app_context = Arc::new(self.context.to_app_context());
        core::dispatch_envelope(
            &app_context,
            kafka_envelope,
            self.context.notification_client.clone(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        let dispatch_inner_ms = t_dispatch.elapsed().as_millis();
        tracing::info!(
            rate_ms,
            dispatch_ms = dispatch_inner_ms,
            total_ms = t_rate.elapsed().as_millis(),
            message_id = %message_id,
            "send_message dispatch complete"
        );

        Ok(Response::new(proto::SendMessageResponse {
            message_id,
            message_number: 0,
            server_timestamp: chrono::Utc::now().timestamp_millis(),
            success: true,
            error: None,
            rate_limit_challenge: None,
            attempt_id,
        }))
    }

    async fn edit_message(
        &self,
        request: Request<proto::EditMessageRequest>,
    ) -> Result<Response<proto::EditMessageResponse>, Status> {
        // Extract authenticated sender_id from x-user-id header or Bearer JWT (+ blocklist check)
        let sender_id = extract_authed_user_id(request.metadata(), &self.context)
            .await
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authentication"))?;

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
        let user_id = extract_authed_user_id(request.metadata(), &self.context)
            .await
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authentication"))?
            .to_string();

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

                let content_type = if let Some(ct) = env.proto_content_type {
                    core::ContentType::try_from(ct).unwrap_or(core::ContentType::E2eeSignal)
                } else {
                    match env.message_type {
                        MessageType::ControlMessage => match env.encrypted_payload.as_str() {
                            "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
                            "KEY_SYNC" => core::ContentType::KeySync,
                            _ => core::ContentType::E2eeSignal,
                        },
                        _ => core::ContentType::E2eeSignal,
                    }
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
        let sender_id = extract_authed_user_id(request.metadata(), &self.context)
            .await
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authentication"))?;

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

// ============================================================================
// Pure helpers
// ============================================================================

/// Validates that `payload` is non-empty and within the 64 KiB size limit.
pub(crate) fn validate_payload(payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("encrypted_payload is required".to_string());
    }
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "encrypted_payload exceeds maximum size ({} > {} bytes)",
            payload.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    Ok(())
}

// ============================================================================
// Auth Helpers
// ============================================================================

/// Extract the authenticated user UUID from gRPC request metadata.
///
/// Resolution order:
/// 1. `x-user-id` header — injected by the gateway after it has already
///    validated the JWT. Trusted; no further checks needed.
/// 2. `Authorization: Bearer <jwt>` — used for direct (non-gateway) gRPC
///    connections. Requires both cryptographic verification **and** a Redis
///    blocklist check (fail-closed: rejects on Redis error).
///
/// Returns `None` when no auth header is present or when the JWT is
/// invalid / revoked.
async fn extract_authed_user_id(
    metadata: &tonic::metadata::MetadataMap,
    context: &MessagingServiceContext,
) -> Option<uuid::Uuid> {
    if let Some(uid) = metadata
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        return Some(uid);
    }

    let token = metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_owned())?;

    let claims = context.auth_manager.verify_token(&token).ok()?;
    let user_id = uuid::Uuid::parse_str(&claims.sub).ok()?;

    // Fail-closed: reject the request if Redis is unavailable or the token
    // has been explicitly revoked (e.g. via logout or device removal).
    let mut redis = match context.redis_conn().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Redis unavailable for blocklist check — rejecting JWT");
            return None;
        }
    };

    let key = format!("invalidated_token:{}", claims.jti);
    match redis::cmd("EXISTS")
        .arg(&key)
        .query_async::<bool>(&mut redis)
        .await
    {
        Ok(false) => Some(user_id),
        Ok(true) => {
            tracing::warn!(jti = %claims.jti, "Rejected revoked access token in gRPC auth");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "Blocklist EXISTS check failed — rejecting JWT");
            None
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_size_empty_rejected() {
        assert!(validate_payload(&[]).is_err());
    }

    #[test]
    fn test_payload_size_64kb_accepted() {
        let payload = vec![0u8; 65535];
        assert!(validate_payload(&payload).is_ok());
    }

    #[test]
    fn test_payload_size_over_64kb_rejected() {
        let payload = vec![0u8; 65537];
        assert!(validate_payload(&payload).is_err());
    }
}
