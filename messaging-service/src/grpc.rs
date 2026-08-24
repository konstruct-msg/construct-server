use std::pin::Pin;
use std::sync::Arc;

use futures_core::Stream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::context::MessagingServiceContext;
use crate::core;
use crate::envelope::{TokenRejected, dispatch_sealed_sender};
use crate::stream::{
    SUBSCRIBE_CATCHUP_GRACE, StreamCatchupState, handle_stream_request,
    is_valid_redis_stream_cursor, poll_messages, spawn_inbox_wakeup,
};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, messaging_service_server::MessagingService,
};

#[derive(Clone)]
pub(crate) struct MessagingGrpcService {
    pub(crate) context: Arc<MessagingServiceContext>,
}

/// Map a `dispatch_sealed_sender` failure to a gRPC status. Privacy Pass rejection
/// under enforce becomes FAILED_PRECONDITION "privacy_pass:{label}" (a stable,
/// client-parseable contract — the client replenishes and retries sealed once);
/// everything else stays a generic internal error.
fn map_sealed_dispatch_error(e: anyhow::Error) -> Status {
    if let Some(rejected) = e.downcast_ref::<TokenRejected>() {
        Status::failed_precondition(rejected.to_string())
    } else {
        Status::internal(e.to_string())
    }
}

fn heartbeat_ack_response() -> proto::MessageStreamResponse {
    proto::MessageStreamResponse {
        response_id: None,
        stream_cursor: None,
        rate_limit_challenge: None,
        attempt_id: None,
        response: Some(proto::message_stream_response::Response::HeartbeatAck(
            proto::HeartbeatAck {
                timestamp: 0, // server-initiated; no prior client ping to echo
                server_timestamp: chrono::Utc::now().timestamp_millis(),
            },
        )),
    }
}

async fn send_initial_heartbeat_ack(
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    stream_conn_id: uuid::Uuid,
) -> bool {
    let initial_ack_sent = tx.send(Ok(heartbeat_ack_response())).await.is_ok();
    tracing::info!(
        stream_conn_id = %stream_conn_id,
        initial_ack_sent,
        "initial HeartbeatAck dispatched"
    );
    initial_ack_sent
}

#[tonic::async_trait]
impl MessagingService for MessagingGrpcService {
    type MessageStreamStream =
        Pin<Box<dyn Stream<Item = Result<proto::MessageStreamResponse, Status>> + Send + 'static>>;

    async fn message_stream(
        &self,
        request: Request<tonic::Streaming<proto::MessageStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        let (auth_user_id, auth_device_id) =
            match extract_authed_identity(request.metadata(), &self.context).await {
                Some((uid, did)) => (Some(uid), did),
                None => (None, None),
            };

        let mut in_stream = request.into_inner();
        let context = self.context.clone();

        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            // Per-stream queue clone — avoids contention on the global context.queue mutex.
            // ConnectionManager is Clone and pipelines commands internally, so concurrent
            // XREAD calls from different stream tasks can proceed in parallel.
            let mut stream_queue = context.queue.lock().await.clone();

            // Initialise from auth metadata (Bearer); envelope.sender is never trusted.
            let mut user_id: Option<uuid::Uuid> = auth_user_id;
            // Token device_id selects the per-device mailbox (dual-read with user stream
            // during minimal-server-delivery step 3). None → legacy user-stream only.
            let device_id: Option<String> = auth_device_id;
            // last_stream_id stays None until Subscribe applies since_cursor (or
            // subscribe-grace expires) so the first XREAD does not replay the
            // whole offline retention window. Wakeup/interval polls stay gated
            // until initial_catchup_done.
            let mut catchup = StreamCatchupState::default();

            // Unique ID for this stream connection — used to correlate open/close log lines
            let stream_conn_id = uuid::Uuid::new_v4();
            let stream_opened_at = std::time::Instant::now();
            tracing::info!(
                stream_conn_id = %stream_conn_id,
                user_id = user_id.map(|u| u.to_string()).unwrap_or_default(),
                "MessageStream opened"
            );

            // Immediately emit the first stream item so tonic/h2 sends initial
            // response HEADERS at accept time. For server-streaming/bidi RPCs,
            // tonic may otherwise defer HEADERS until the first DATA frame; when
            // the inbox is empty that can be as late as the heartbeat interval.
            if !send_initial_heartbeat_ack(&tx, stream_conn_id).await {
                return;
            }

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
            // the HTTP/2 PING frames fire and NAT/firewalls/VEIL proxies do not silently
            // drop the connection. tonic 0.14 does not expose keepalive_while_idle, so
            // application-level traffic is the only way to maintain idle streams.
            let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(
                context.config.messaging.stream_heartbeat_interval_secs,
            ));

            // Wait for Subscribe (with optional since_cursor) before the first
            // offline XREAD. iOS sends Subscribe immediately after open; grace
            // covers clients that never Subscribe (poll from stream start).
            let subscribe_grace = tokio::time::sleep(SUBSCRIBE_CATCHUP_GRACE);
            tokio::pin!(subscribe_grace);

            // If user_id is already known from auth metadata, arm inbox wakeup and
            // mark online — but do NOT poll yet (wait for Subscribe or grace).
            if let Some(uid) = user_id {
                spawn_inbox_wakeup(context.config.redis_url.clone(), uid, wakeup_tx.clone());
                wakeup_subscribed = true;
                if let Err(e) = stream_queue
                    .track_user_online(&uid.to_string(), &context.server_instance_id)
                    .await
                {
                    tracing::warn!(user_id = %uid, "track_user_online failed: {}", e);
                }
            }

            // Open/close are counted around the loop, not at the RPC entry, so the
            // gauge tracks streams that are actually running rather than requests
            // that arrived. Every exit from the loop below falls through to the
            // decrement — there is no early return between here and there.
            construct_metrics::GRPC_STREAMS_ACTIVE.inc();
            construct_metrics::GRPC_STREAMS_OPENED_TOTAL.inc();

            let close_reason = 'stream: loop {
                // Lazy inbox wakeup: arm as soon as user_id becomes known.
                // Catch-up poll still waits for Subscribe or grace (not here).
                if !wakeup_subscribed && let Some(uid) = user_id {
                    spawn_inbox_wakeup(context.config.redis_url.clone(), uid, wakeup_tx.clone());
                    wakeup_subscribed = true;
                    if let Err(e) = stream_queue
                        .track_user_online(&uid.to_string(), &context.server_instance_id)
                        .await
                    {
                        tracing::warn!(user_id = %uid, "track_user_online failed: {}", e);
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
                                    device_id.as_deref(),
                                    &mut stream_queue,
                                    &mut catchup,
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

                    // Subscribe never arrived: catch up from current cursor (usually None
                    // → stream start). Only clients that skip Subscribe take this path.
                    _ = &mut subscribe_grace, if !catchup.initial_catchup_done && user_id.is_some() => {
                        if let Some(uid) = user_id {
                            tracing::debug!(
                                user_id = %uid,
                                last_stream_id = ?catchup.last_stream_id,
                                "Subscribe grace elapsed without Subscribe — offline catch-up"
                            );
                            if let Err(e) = poll_messages(
                                &mut stream_queue,
                                &context.config.messaging,
                                uid,
                                device_id.as_deref(),
                                &mut catchup.last_stream_id,
                                &tx,
                                catchup.subscribe_with_cursor_seen,
                            )
                            .await
                            {
                                tracing::warn!("Grace catch-up poll error: {}", e);
                            }
                        }
                        catchup.initial_catchup_done = true;
                    }

                    // Push: new message arrived — deliver immediately (after initial catch-up)
                    Some(()) = wakeup_rx.recv(), if catchup.initial_catchup_done => {
                        if let Some(uid) = user_id
                            && let Err(e) = poll_messages(
                                &mut stream_queue,
                                &context.config.messaging,
                                uid,
                                device_id.as_deref(),
                                &mut catchup.last_stream_id,
                                &tx,
                                false, // routine wakeup, not a resume catch-up
                            )
                            .await
                        {
                            tracing::warn!("Error polling messages after wakeup: {}", e);
                        }
                    }

                    // Fallback poll (covers missed pub/sub events and reconnects)
                    _ = poll_interval.tick(), if catchup.initial_catchup_done => {
                        if let Some(uid) = user_id && let Err(e) = poll_messages(
                                &mut stream_queue,
                                &context.config.messaging,
                                uid,
                                device_id.as_deref(),
                                &mut catchup.last_stream_id,
                                &tx,
                                false, // fallback tick, not a resume catch-up
                            ).await {
                                tracing::warn!("Error polling messages: {}", e);
                            }
                        }

                    // Server-initiated keepalive: send a HeartbeatAck so the H2 stream
                    // stays active and tonic's keepalive PINGs are triggered even during
                    // periods with no user messages (idle chats, background app state).
                    _ = heartbeat_interval.tick() => {
                        if tx.send(Ok(heartbeat_ack_response())).await.is_err() {
                            break 'stream "heartbeat_tx_closed";
                        }
                    }

                    else => break 'stream "all_channels_closed",
                }
            };

            construct_metrics::GRPC_STREAMS_ACTIVE.dec();
            construct_metrics::GRPC_STREAMS_CLOSED_TOTAL
                .with_label_values(&[close_reason])
                .inc();

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
        // Authenticate the caller before consuming the request body.
        // Legacy sealed sender over SendMessage stays auth-gated until the old
        // transport is fully sunset. The dedicated SendSealedMessage RPC is the
        // only intentional unauthenticated ingress for sealed traffic.
        let authed_user_id = extract_authed_user_id(request.metadata(), &self.context).await;

        let req = request.into_inner();
        let attempt_id = req.attempt_id.clone();
        let envelope = req
            .message
            .ok_or_else(|| Status::invalid_argument("message is required"))?;

        // ── Sealed Sender path ──────────────────────────────────────────────
        if let Some(sealed) = &envelope.sealed_sender {
            require_legacy_sealed_sender_auth(authed_user_id)?;
            // The cutover gate (55.1a). Both doors lead to `dispatch_sealed_sender`, so the
            // distinction exists only here — counting inside the dispatch would answer a
            // different question than the one the flip turns on.
            construct_metrics::MSG_SEALED_INGRESS_TOTAL
                .with_label_values(&["legacy_send_message"])
                .inc();
            let resp = dispatch_sealed_sender(&self.context, sealed)
                .await
                .map_err(map_sealed_dispatch_error)?;
            return Ok(Response::new(resp));
        }

        // ── Regular (local) message path ────────────────────────────────────
        let sender = envelope
            .sender
            .ok_or_else(|| Status::invalid_argument("sender is required"))?;
        let sender_id = uuid::Uuid::parse_str(&sender.user_id)
            .map_err(|_| Status::invalid_argument("invalid sender.user_id"))?;

        // Verify that the sender in the envelope matches the authenticated user.
        // Prevents a device from spoofing another user's identity in the message body.
        let authed_id = authed_user_id
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authentication"))?;
        if authed_id != sender_id {
            return Err(Status::permission_denied(
                "sender.user_id does not match authenticated user",
            ));
        }

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

        use construct_server_shared::message::types::{MessageEnvelope, ProtoEnvelopeContext};

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
                Err(_) => {
                    // Fail-open: Redis unavailable — proceed (may double-count rate).
                    construct_metrics::record_abuse_fail_open("send_dedup");
                }
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

        if let Some(ref sentinel) = self.context.sentinel
            && !sender_device_id.is_empty()
        {
            let target = if !recipient_device_id.is_empty() {
                recipient_device_id
            } else {
                // Recipient device unknown: skip block check, only enforce sender limits.
                sender_device_id
            };
            // In-process call to SentinelCore — no gRPC hop.
            //
            // This fail-open branch is narrower than it looks: SentinelCore turns a Redis
            // failure in the quota path into `Ok(allowed: false)` on purpose, so it never
            // surfaces here as `Err`. Only errors before that point (trust lookup, block
            // lookup) reach this arm. Rate limiting itself is fail-CLOSED — a Redis outage
            // denies every send with retry_after=30.
            let (allowed, reason, retry_after) = match sentinel
                .check_send_permission(sender_device_id, target, Some(&sender_id.to_string()))
                .await
            {
                Ok(perm) => (perm.allowed, perm.denial_reason, perm.retry_after_seconds),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "SentinelCore::check_send_permission failed — failing open"
                    );
                    construct_metrics::record_abuse_fail_open("sentinel");
                    (true, String::new(), 0)
                }
            };

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
        } else {
            // Redis connect failed — trust defaults to Trusted, limits skipped.
            construct_metrics::record_abuse_fail_open("rate_trust");
            tracing::warn!("Redis unavailable for trust/rate checks — failing open (Trusted)");
        }

        let t_dispatch = std::time::Instant::now();
        let rate_ms = t_dispatch.duration_since(t_rate).as_millis();
        let mut msg_envelope = MessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: sender_id.to_string(),
            recipient_id: recipient.user_id.clone(),
            message_id: message_id.clone(),
            encrypted_payload: envelope.encrypted_payload.to_vec(),
            content_type: envelope.content_type,
        });
        msg_envelope.max_queue_len = Some(trust_level.queue_maxlen(&self.context.config.messaging));

        let app_context = Arc::new(self.context.to_app_context());
        core::dispatch_envelope(
            &app_context,
            msg_envelope,
            self.context.notification_context.clone(),
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

    /// SendSealedMessage — stealth-sealed-sender-v2 Phase 2: unauthenticated sealed
    /// send. Deliberately does NOT call `extract_authed_user_id` — anti-abuse is
    /// per-IP rate limiting here plus Privacy Pass token redemption + delivery-tag
    /// replay checking inside `dispatch_sealed_sender` (Phase 1, unchanged).
    async fn send_sealed_message(
        &self,
        request: Request<proto::SendSealedMessageRequest>,
    ) -> Result<Response<proto::SendMessageResponse>, Status> {
        let client_ip = extract_client_ip(request.metadata());
        let mut conn = self.context.redis_conn.clone();
        match construct_rate_limit::sliding_window_check_and_record(
            &mut conn,
            &format!("sealed_ip:{client_ip}"),
            self.context.config.messaging.sealed_ip_rate_limit_per_min,
            60,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(Status::resource_exhausted(
                    "sealed-sender rate limit exceeded for this IP",
                ));
            }
            Err(e) => {
                // Fail-open: Redis unavailable shouldn't block delivery — consistent
                // with this service's other Redis fail-open paths (delivery-tag cache).
                tracing::error!(error = %e, "sealed_ip rate limit check unavailable — proceeding");
                construct_metrics::record_abuse_fail_open("sealed_ip");
            }
        }

        let req = request.into_inner();
        let attempt_id = req.attempt_id.clone();
        let sealed = req
            .sealed_sender
            .ok_or_else(|| Status::invalid_argument("sealed_sender is required"))?;

        // Counted at the same point as the legacy door above — payload in hand, before
        // dispatch — so the two labels are comparable. A request refused by the per-IP limit
        // above never reaches here, and it is not a sealed send that arrived.
        construct_metrics::MSG_SEALED_INGRESS_TOTAL
            .with_label_values(&["sealed_rpc"])
            .inc();

        let mut resp = dispatch_sealed_sender(&self.context, &sealed)
            .await
            .map_err(map_sealed_dispatch_error)?;
        resp.attempt_id = attempt_id;
        Ok(Response::new(resp))
    }

    async fn edit_message(
        &self,
        request: Request<proto::EditMessageRequest>,
    ) -> Result<Response<proto::EditMessageResponse>, Status> {
        // Extract authenticated sender_id from x-user-id header or Bearer JWT (+ blocklist check)
        let sender_id = extract_authed_user_id(request.metadata(), &self.context)
            .await
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authentication"))?;

        let _req = request.into_inner();

        // Telemetry: detect usage of the deprecated EditMessage RPC before removal.
        construct_metrics::LEGACY_EDIT_USAGE_TOTAL
            .with_label_values(&["edit_message_rpc"])
            .inc();
        tracing::warn!(
            sender = %sender_id,
            "Deprecated EditMessage RPC called; edits should be sent as encrypted MessageContent.edit"
        );

        Err(Status::unimplemented(
            "EditMessage is deprecated: embed the edit reference inside the encrypted MessageContent.edit payload",
        ))
    }

    // =========================================================================
    // Reactions RPCs (Stubs)
    // =========================================================================

    async fn add_reaction(
        &self,
        _request: Request<proto::AddReactionRequest>,
    ) -> Result<Response<proto::AddReactionResponse>, Status> {
        Err(Status::unimplemented(
            "AddReaction is deprecated: send reactions as encrypted MessageContent.reaction messages",
        ))
    }

    async fn remove_reaction(
        &self,
        _request: Request<proto::RemoveReactionRequest>,
    ) -> Result<Response<proto::RemoveReactionResponse>, Status> {
        Err(Status::unimplemented(
            "RemoveReaction is deprecated: send reactions as encrypted MessageContent.reaction messages",
        ))
    }

    async fn get_pending_messages(
        &self,
        request: Request<proto::GetPendingMessagesRequest>,
    ) -> Result<Response<proto::GetPendingMessagesResponse>, Status> {
        let (user_uuid, device_id) = extract_authed_identity(request.metadata(), &self.context)
            .await
            .ok_or_else(|| Status::unauthenticated("Missing or invalid authentication"))?;
        let user_id = user_uuid.to_string();

        let req = request.into_inner();
        let limit = req.limit.unwrap_or(50).min(100) as usize;
        let since = req.since_cursor.as_deref();

        // Hold the lock only for XREAD — release immediately after so other handlers
        // are not blocked during the message-building loop below.
        //
        // since_cursor is a *read offset only* (no XTRIM). With device_id, dual-read
        // merges device + user streams (minimal-server-delivery step 3).
        if let Some(cursor) = since
            && !cursor.is_empty()
            && !is_valid_redis_stream_cursor(cursor)
        {
            tracing::warn!(
                cursor = %cursor,
                "Ignoring invalid since_cursor on GetPendingMessages (expected Redis stream ID)"
            );
        }
        let since = since.filter(|c| !c.is_empty() && is_valid_redis_stream_cursor(c));

        let mode = if device_id.as_deref().filter(|d| !d.is_empty()).is_some() {
            "device_merge"
        } else {
            "user_only"
        };
        let page = {
            let mut queue = self.context.queue.lock().await;
            queue
                .read_mailbox_messages(&user_id, device_id.as_deref(), since, limit)
                .await
                .map_err(|e| Status::internal(format!("Failed to read messages: {}", e)))?
        };
        let stream_messages = page.entries;
        construct_metrics::MSG_MAILBOX_READ_TOTAL
            .with_label_values(&["pending", mode])
            .inc();
        if page.user_only > 0 {
            construct_metrics::MSG_MAILBOX_USER_ONLY_ENTRIES_TOTAL
                .with_label_values(&["pending"])
                .inc_by(page.user_only as u64);
        }

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
                use construct_server_shared::message::types::MessageType;
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
                        MessageType::ControlMessage => {
                            match std::str::from_utf8(&env.encrypted_payload).unwrap_or("") {
                                "SESSION_RESET" | "END_SESSION" => core::ContentType::SessionReset,
                                "KEY_SYNC" => core::ContentType::KeySync,
                                _ => core::ContentType::E2eeSignal,
                            }
                        }
                        _ => core::ContentType::E2eeSignal,
                    }
                };

                // Control labels are not ciphertext — send empty bytes to the client.
                // E2EE path: encrypted_payload is already raw bytes after dual-deser.
                let payload_bytes = match content_type {
                    core::ContentType::SessionReset | core::ContentType::KeySync => vec![],
                    _ => env.encrypted_payload,
                };

                Some(proto::PendingMessage {
                    message_id: env.message_id,
                    sender_id: if env.is_sealed_sender {
                        String::new()
                    } else {
                        env.sender_id
                    },
                    encrypted_payload: if env.is_sealed_sender {
                        vec![]
                    } else {
                        payload_bytes
                    },
                    timestamp: env.timestamp,
                    content_type: content_type.into(),
                    sealed_inner_data: if env.is_sealed_sender {
                        env.sealed_inner.unwrap_or_default()
                    } else {
                        vec![]
                    },
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

        use construct_server_shared::message::types::MessageEnvelope;
        let envelope =
            MessageEnvelope::new_key_sync(sender_id.to_string(), recipient_user_id.clone());

        // Fan out like every other delivery. Writing the user stream directly was the last
        // path that bypassed the mailbox: it survives today only because dual-read still
        // reads that stream, and `MSG_MAILBOX_USER_WRITE=0` would make KEY_SYNC undeliverable
        // without a single error — the flag exists to be flipped by ops, so this cannot
        // depend on it staying on.
        let device_ids =
            core::fetch_recipient_device_ids_for_user(&self.context.db_pool, &recipient_user_id)
                .await;
        let mut queue = self.context.queue.lock().await;
        queue
            .write_message_to_device_streams(&recipient_user_id, &device_ids, &envelope)
            .await
            .map_err(|e| Status::internal(format!("Failed to queue KEY_SYNC: {e}")))?;

        tracing::info!(
            sender = %sender_id,
            recipient = %recipient_user_id,
            devices = device_ids.len(),
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

/// Extract client IP from `x-forwarded-for` / `x-real-ip` gRPC metadata (set by
/// Caddy's `reverse_proxy`). Used only for the unauthenticated `SendSealedMessage`
/// rate limit.
///
/// SECURITY: take the **rightmost** `X-Forwarded-For` entry, not the leftmost.
/// Caddy *appends* the real connecting peer after any client-supplied values, so
/// the leftmost hop is attacker-controlled and can rotate to dodge rate limits.
/// Matches `key-service` bundle rate-limit IP extraction.
fn extract_client_ip(metadata: &tonic::metadata::MetadataMap) -> String {
    if let Some(forwarded) = metadata
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let ip = forwarded.split(',').next_back().unwrap_or("").trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    if let Some(real_ip) = metadata.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return real_ip.trim().to_string();
    }
    "unknown".to_string()
}

fn require_legacy_sealed_sender_auth(authed_user_id: Option<uuid::Uuid>) -> Result<(), Status> {
    if authed_user_id.is_some() {
        Ok(())
    } else {
        Err(Status::unauthenticated(
            "legacy sealed sender over SendMessage requires authentication; use SendSealedMessage for unauthenticated sealed transport",
        ))
    }
}

/// Extract the authenticated user UUID from gRPC request metadata.
///
/// Requires a cryptographically verified Bearer access token (PASETO/JWT).
/// Optional `x-user-id` must match `claims.sub` when present (spoof guard).
/// Always checks the Redis revocation blocklist (fail-closed on Redis error).
///
/// Returns `(user_id, device_id_from_claims)` or `None` when auth is missing,
/// invalid, revoked, or Redis is down. `device_id` selects the per-device mailbox.
///
/// **Not trusted:** client-supplied `x-user-id` alone (Caddy does not inject
/// or strip this header — treating it as identity was an auth bypass).
async fn extract_authed_identity(
    metadata: &tonic::metadata::MetadataMap,
    context: &MessagingServiceContext,
) -> Option<(uuid::Uuid, Option<String>)> {
    let claims =
        construct_server_shared::auth_utils::verify_access_token(&context.auth_manager, metadata)
            .ok()?;
    let user_id = uuid::Uuid::parse_str(&claims.sub).ok()?;

    // Fail-closed: reject if Redis is unavailable, JTI is blocklisted, or the
    // device was revoked (covers all outstanding tokens for that device_id).
    let mut queue = context.queue.lock().await;

    match queue.is_token_invalidated(&claims.jti).await {
        Ok(true) => {
            tracing::warn!(jti = %claims.jti, "Rejected revoked access token in gRPC auth");
            return None;
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(error = %e, "Blocklist check failed — rejecting JWT");
            return None;
        }
    }

    if let Some(device_id) = claims.device_id.as_deref() {
        match queue.is_device_revoked(device_id).await {
            Ok(true) => {
                tracing::warn!(
                    device_id = %device_id,
                    "Rejected access token for revoked device"
                );
                return None;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Device-revoked check failed — rejecting JWT");
                return None;
            }
        }
    }

    Some((user_id, claims.device_id.clone()))
}

async fn extract_authed_user_id(
    metadata: &tonic::metadata::MetadataMap,
    context: &MessagingServiceContext,
) -> Option<uuid::Uuid> {
    extract_authed_identity(metadata, context)
        .await
        .map(|(uid, _)| uid)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_initial_heartbeat_ack_dispatches_immediately() {
        let (tx, mut rx) = mpsc::channel(1);
        let stream_conn_id = uuid::Uuid::new_v4();

        assert!(send_initial_heartbeat_ack(&tx, stream_conn_id).await);

        let item = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
            .await
            .expect("initial HeartbeatAck must be queued without waiting for heartbeat interval")
            .expect("channel must contain one item")
            .expect("initial HeartbeatAck must be Ok");

        match item.response {
            Some(proto::message_stream_response::Response::HeartbeatAck(ack)) => {
                assert_eq!(ack.timestamp, 0);
                assert!(ack.server_timestamp > 0);
            }
            other => panic!("expected initial HeartbeatAck, got {other:?}"),
        }
    }

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

    #[test]
    fn test_legacy_sealed_sender_requires_auth() {
        let err = require_legacy_sealed_sender_auth(None).expect_err("auth must be required");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_legacy_sealed_sender_accepts_authenticated_user() {
        require_legacy_sealed_sender_auth(Some(uuid::Uuid::new_v4()))
            .expect("authenticated legacy sealed sender must be allowed");
    }
}

#[cfg(test)]
mod sealed_dispatch_error_tests {
    use super::*;

    #[test]
    fn token_rejected_maps_to_failed_precondition_with_prefix() {
        let err = anyhow::Error::new(TokenRejected {
            label: "missing_token",
        });
        let status = map_sealed_dispatch_error(err);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "privacy_pass:missing_token");
    }

    /// U3 — every redeem label must surface as a stable `privacy_pass:{label}` status.
    #[test]
    fn all_token_rejected_labels_map_to_failed_precondition() {
        for label in [
            "missing_token",
            "invalid_token",
            "double_spent",
            "decrypt_failed",
            "redis_error",
            "not_configured",
            "unit_exhausted",
        ] {
            let status = map_sealed_dispatch_error(anyhow::Error::new(TokenRejected { label }));
            assert_eq!(
                status.code(),
                tonic::Code::FailedPrecondition,
                "label {label}"
            );
            assert_eq!(
                status.message(),
                format!("privacy_pass:{label}"),
                "label {label}"
            );
        }
    }

    #[test]
    fn other_errors_stay_internal() {
        let status = map_sealed_dispatch_error(anyhow::anyhow!("redis down"));
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), "redis down");
    }

    #[test]
    fn token_rejected_display_prefix_survives_anyhow_to_string() {
        // The stream path sends `e.to_string()` in MessageError.error_message —
        // the client parses the "privacy_pass:" prefix there.
        let err = anyhow::Error::new(TokenRejected {
            label: "double_spent",
        });
        assert_eq!(err.to_string(), "privacy_pass:double_spent");
    }
}
