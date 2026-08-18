use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::context::MessagingServiceContext;
use crate::core;
use crate::envelope::{convert_envelope_to_proto, dispatch_sealed_sender};
use crate::receipts::{build_receipt_response, relay_delivery_receipt};
use construct_server_shared::shared::proto::services::v1 as proto;

/// How long to wait for the client's first `Subscribe` (with optional
/// `since_cursor`) before doing an offline catch-up poll from the start of the
/// stream. iOS sends Subscribe immediately after open; this grace only covers
/// clients that never Subscribe (or lose the first frame).
pub(crate) const SUBSCRIBE_CATCHUP_GRACE: std::time::Duration =
    std::time::Duration::from_millis(1500);

/// Per-connection offline catch-up state for MessageStream.
///
/// Catch-up must run only after Subscribe applies `since_cursor` (or after
/// [`SUBSCRIBE_CATCHUP_GRACE`]), never at stream open.
#[derive(Debug, Default)]
pub(crate) struct StreamCatchupState {
    /// Last Redis stream id used as exclusive XREAD start (resume position).
    pub last_stream_id: Option<String>,
    /// Subscribe on this connection carried a valid `since_cursor` (S2 canary).
    pub subscribe_with_cursor_seen: bool,
    /// First offline catch-up completed (Subscribe handler or grace timer).
    pub initial_catchup_done: bool,
}

/// Handle incoming MessageStreamRequest from client.
///
/// On `Subscribe`, applies `since_cursor` (trim + resume position) and then runs
/// the offline catch-up poll. The open path must **not** poll before that —
/// doing so re-delivers the entire offline stream and races the cursor.
pub(crate) async fn handle_stream_request(
    req: proto::MessageStreamRequest,
    context: &Arc<MessagingServiceContext>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    user_id: &mut Option<uuid::Uuid>,
    stream_queue: &mut construct_queue::MessageQueue,
    catchup: &mut StreamCatchupState,
) -> anyhow::Result<()> {
    use proto::message_stream_request::Request as StreamReq;

    match req.request {
        Some(StreamReq::Send(envelope)) => {
            let attempt_id = req.attempt_id.clone();

            // Stream identity is bound only from verified auth metadata at open
            // (or re-checked on unary RPCs). Never trust envelope.sender.user_id
            // for inbox subscription — that was an unauthenticated spoof path.
            if user_id.is_none() && envelope.sealed_sender.is_none() {
                return Err(anyhow::anyhow!(
                    "unauthenticated: MessageStream requires Authorization Bearer token"
                ));
            }
            if let (Some(uid), Some(sender)) = (*user_id, envelope.sender.as_ref())
                && let Ok(claimed) = uuid::Uuid::parse_str(&sender.user_id)
                && claimed != uid
            {
                return Err(anyhow::anyhow!(
                    "sender.user_id does not match authenticated user"
                ));
            }

            // ── Sealed Sender path ──────────────────────────────────────────
            if let Some(sealed) = &envelope.sealed_sender {
                let message_id = match dispatch_sealed_sender(context, sealed).await {
                    Ok(resp) => resp.message_id,
                    Err(e) => {
                        // Privacy Pass rejection (enforce) surfaces here as
                        // error_message "privacy_pass:{label}" via TokenRejected's
                        // Display — the client parses that prefix on the stream path
                        // the same way it parses FAILED_PRECONDITION on the unary path.
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

                if let Some(ref sentinel) = context.sentinel
                    && !sender_device_id.is_empty()
                {
                    let target = if !recipient_device_id.is_empty() {
                        recipient_device_id
                    } else {
                        sender_device_id
                    };
                    // In-process call to SentinelCore — no gRPC hop.
                    // Fails open: on Redis/internal error we allow the send
                    // through (mirrors the previous gRPC-client fail-open
                    // behaviour when sentinel-service was unreachable).
                    let (allowed, reason, retry_after) = match sentinel
                        .check_send_permission(
                            sender_device_id,
                            target,
                            Some(&uid.to_string()),
                        )
                        .await
                    {
                        Ok(perm) => {
                            (perm.allowed, perm.denial_reason, perm.retry_after_seconds)
                        }
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

                use construct_server_shared::message::types::{
                    MessageEnvelope, ProtoEnvelopeContext,
                };
                let msg_envelope =
                    MessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
                        sender_id: uid.to_string(),
                        recipient_id,
                        message_id: message_id.clone(),
                        encrypted_payload: envelope.encrypted_payload.to_vec(),
                        content_type: envelope.content_type,
                    });

                let app_context = Arc::new(context.to_app_context());
                match core::dispatch_envelope(
                    &app_context,
                    msg_envelope,
                    context.notification_context.clone(),
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
            // Apply since_cursor *before* the offline catch-up poll. Catch-up used to
            // run at stream open (before this Subscribe was read), which re-delivered
            // the entire offline retention window and made the advance-only guard paper
            // over a race instead of preventing it.
            //
            // Guard: only advance the cursor — never rewind it. This is a safety net
            // for a later Subscribe with a stale bookmark (or a client that reconnects
            // with an older cursor), not a compensation for open-time catch-up.
            if let Some(cursor) = sub.since_cursor.as_deref()
                && !cursor.is_empty()
            {
                // Clients must pass a Redis stream ID (e.g. "1782556480695-0"), NOT a
                // message UUID.  An invalid cursor used as XREAD start ID is reset to "0"
                // (re-deliver everything) while a valid-but-stale cursor can skip messages.
                if !is_valid_redis_stream_cursor(cursor) {
                    tracing::warn!(
                        cursor = %cursor,
                        "Ignoring invalid since_cursor on Subscribe (expected Redis stream ID, not message UUID)"
                    );
                } else {
                    catchup.subscribe_with_cursor_seen = true;

                    // since_cursor is a read offset only. Do NOT trim here.
                    // Client-asserted XTRIM on the shared user mailbox created a silent-loss
                    // class (paging/cancel races; multi-device fastest-cursor wins). Retention
                    // is MAXLEN + age sweep. See construct-docs
                    // decisions/minimal-server-delivery.md (Accepted — step 2).
                    apply_since_cursor(cursor, &mut catchup.last_stream_id);
                }
            }

            // Offline catch-up after cursor application (or Subscribe without cursor).
            // Grace-timer path in grpc.rs covers clients that never Subscribe.
            if !catchup.initial_catchup_done
                && let Some(uid) = *user_id
            {
                if let Err(e) = poll_messages(
                    stream_queue,
                    &context.config.messaging,
                    uid,
                    &mut catchup.last_stream_id,
                    tx,
                    catchup.subscribe_with_cursor_seen,
                )
                .await
                {
                    tracing::warn!(error = %e, "Subscribe catch-up poll error");
                }
                catchup.initial_catchup_done = true;
            }
        }
        Some(StreamReq::Unsubscribe(_)) => {
            // No-op: all messages are routed by user_id regardless of subscriptions
        }
        Some(StreamReq::Typing(_)) => {
            // Not implemented yet
            tracing::debug!("Received unimplemented request type (typing)");
        }
        Some(StreamReq::P2pHandoffAck(_)) => {
            // Reserved for MASQUE/P2P direct transport integration.
            // Currently accepted as a no-op to keep stream protocol forward-compatible.
            tracing::debug!("Received unimplemented request type (p2p_handoff_ack)");
        }
        Some(StreamReq::P2pDisconnect(_)) => {
            // Reserved for MASQUE/P2P direct transport integration.
            // Currently accepted as a no-op to keep stream protocol forward-compatible.
            tracing::debug!("Received unimplemented request type (p2p_disconnect)");
        }

        None => {
            tracing::warn!("Received empty stream request");
        }
    }

    Ok(())
}

/// Returns true when `cursor` is a valid Redis stream resume position.
/// Shared by MessageStream Subscribe and GetPendingMessages (read offset only).
pub(crate) fn is_valid_redis_stream_cursor(cursor: &str) -> bool {
    if cursor == "0" || cursor == "$" {
        return true;
    }
    if let Some((ts, seq)) = cursor.split_once('-') {
        return ts.parse::<u64>().is_ok() && seq.parse::<u64>().is_ok();
    }
    cursor.parse::<u64>().is_ok()
}

/// Apply a client `since_cursor` as the resume position: only advance, never rewind.
/// Returns whether the cursor was applied (advanced or equal — position is at least
/// the client bookmark).
/// Whether an empty poll is worth a line in the log.
///
/// `poll_messages` reported only what it found, so a poll that returned nothing left no trace at
/// all. That is fine for the idle case — a wakeup tick on a user with an empty stream is noise.
/// It is not fine after the client resumed from a cursor: there the client has explicitly said
/// "I am missing everything after this point", and zero is the answer, not the absence of one.
///
/// The distinction cost a working day on 2026-08-18. Two messages were dispatched to an offline
/// recipient at 14:28:16 and 14:28:43; the client reconnected at 14:28:27 and 14:28:53 carrying a
/// cursor below both, and the log showed `Resuming stream from client since_cursor` with nothing
/// after it. That read as "catch-up never ran", and hours went into the branch that decides
/// whether it runs — when in fact it ran twice and found an empty stream, which points somewhere
/// else entirely.
///
/// A log line that appears only on success cannot distinguish "did not happen" from "happened and
/// found nothing", and those have different causes.
fn empty_poll_is_a_finding(msg_count: usize, is_resume_catchup: bool) -> bool {
    msg_count == 0 && is_resume_catchup
}

fn apply_since_cursor(cursor: &str, last_stream_id: &mut Option<String>) -> bool {
    let advance = match last_stream_id {
        None => true,
        Some(current) => compare_stream_ids(cursor, current) == std::cmp::Ordering::Greater,
    };
    if advance {
        tracing::info!(cursor = %cursor, "Resuming stream from client since_cursor");
        *last_stream_id = Some(cursor.to_string());
    }
    advance
}

/// Compare two Redis stream IDs lexicographically by (timestamp, sequence).
/// Returns `Ordering::Greater` if `a` is strictly newer than `b`.
/// IDs with unexpected formats are treated as "not greater" (safe fallback).
fn compare_stream_ids(a: &str, b: &str) -> std::cmp::Ordering {
    fn parse(id: &str) -> Option<(u64, u64)> {
        if let Some((ts, seq)) = id.split_once('-') {
            Some((ts.parse().ok()?, seq.parse().ok()?))
        } else {
            id.parse::<u64>().ok().map(|ts| (ts, 0))
        }
    }
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => std::cmp::Ordering::Less, // treat unparseable as "not newer"
    }
}

/// Spawns a background task — exits automatically when the receiver is dropped
/// (i.e. the gRPC stream closes). Automatically reconnects on Redis connection loss
/// so the fallback 5s poll is never triggered in normal operation.
///
/// **Race-condition protection**: sends a synthetic wakeup signal immediately after
/// each successful SUBSCRIBE. This triggers an extra `poll_messages` call that catches
/// any messages that were XADD'd to the stream between stream-open and subscribe
/// completion (~50 ms window), preventing up to 5 s delivery delay on reconnect.
///
/// Callers must gate wakeup-driven polls until initial catch-up has applied
/// `since_cursor` (or subscribe grace has elapsed); otherwise a synthetic wakeup
/// would XREAD from `"0"` and re-deliver the offline window.
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
///
/// `subscribe_with_cursor_seen`: true if this connection already processed a
/// Subscribe that carried a valid `since_cursor`. Polling with `last_stream_id
/// == None` in that state is a regression canary (S2).
pub(crate) async fn poll_messages(
    queue: &mut construct_queue::MessageQueue,
    config: &construct_config::MessagingConfig,
    user_id: uuid::Uuid,
    last_stream_id: &mut Option<String>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    // True only for the catch-up poll that follows a resume. The wakeup and fallback-tick
    // callers pass false: an empty read there is the normal idle case, and reporting it turned
    // the log into one line per second per connected user.
    is_resume_catchup: bool,
) -> anyhow::Result<()> {
    let user_id_str = user_id.to_string();
    let limit = 50;

    if last_stream_id.is_none() && is_resume_catchup {
        tracing::warn!(
            user_id = %user_id_str,
            "poll_messages started with no stream cursor after Subscribe carried since_cursor — possible catch-up race regression"
        );
        construct_metrics::MSG_POLL_MISSING_CURSOR_AFTER_SUBSCRIBE_TOTAL.inc();
    }

    let t_xread = std::time::Instant::now();
    let messages = queue
        .read_user_messages_from_stream(&user_id_str, None, last_stream_id.as_deref(), limit)
        .await?;
    let xread_ms = t_xread.elapsed().as_millis();

    let msg_count = messages.len();
    if msg_count > 0 {
        tracing::info!(
            user_id = %user_id_str,
            msg_count,
            xread_ms,
            last_stream_id = ?last_stream_id,
            "poll_messages: read messages from Redis offline stream"
        );
    } else if empty_poll_is_a_finding(msg_count, is_resume_catchup) {
        tracing::info!(
            user_id = %user_id_str,
            msg_count,
            xread_ms,
            last_stream_id = ?last_stream_id,
            "poll_messages: nothing after the client's resume cursor"
        );
    } else if xread_ms > config.stream_xread_slow_ms {
        tracing::info!(xread_ms, msg_count, "poll_messages timing (slow)");
    }

    for (stream_id, envelope) in messages {
        // Convert MessageEnvelope to the appropriate stream response
        let Some(envelope) = envelope else {
            *last_stream_id = Some(stream_id); // advance past corrupt/wrong-recipient entry
            continue;
        };

        let mut response = if matches!(
            envelope.message_type,
            construct_server_shared::message::types::MessageType::Receipt
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
            let proto_envelope = convert_envelope_to_proto(envelope)?;
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

        let delivered_message_id = match &response.response {
            Some(proto::message_stream_response::Response::Message(env)) => env
                .message_id_type
                .as_ref()
                .and_then(|id| match id {
                    construct_server_shared::shared::proto::core::v1::envelope::MessageIdType::MessageId(
                        mid,
                    ) if !mid.is_empty() => Some(mid.clone()),
                    _ => None,
                }),
            _ => None,
        };

        tx.send(Ok(response)).await?;
        tracing::info!(
            user_id = %user_id_str,
            stream_id = %stream_id,
            message_id = delivered_message_id.as_deref().unwrap_or(""),
            "poll_messages: pushed message to gRPC stream"
        );
        *last_stream_id = Some(stream_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exclusive XREAD-style filter: entries with id strictly greater than `since`.
    /// When `since` is `None`, Redis uses start id `"0"` and returns the whole stream.
    fn messages_after_cursor<'a>(ids: &[&'a str], since: Option<&str>) -> Vec<&'a str> {
        match since {
            None => ids.to_vec(),
            Some(cursor) => ids
                .iter()
                .copied()
                .filter(|id| compare_stream_ids(id, cursor) == std::cmp::Ordering::Greater)
                .collect(),
        }
    }

    /// Regression: N offline entries, Subscribe with cursor at N−1 must yield exactly
    /// one delivery. Pre-fix open-time poll used start id "0" and re-delivered all N.
    #[test]
    fn subscribe_then_catchup_delivers_only_after_cursor() {
        let ids = ["1000-0", "1001-0", "1002-0", "1003-0", "1004-0"]; // N = 5
        let cursor_n_minus_1 = ids[ids.len() - 2]; // "1003-0"

        let mut last_stream_id: Option<String> = None;
        // S1 order: apply cursor first, then catch-up (exclusive XREAD after cursor).
        apply_since_cursor(cursor_n_minus_1, &mut last_stream_id);
        assert_eq!(last_stream_id.as_deref(), Some(cursor_n_minus_1));

        let delivered = messages_after_cursor(&ids, last_stream_id.as_deref());
        assert_eq!(
            delivered,
            vec!["1004-0"],
            "expected exactly the one entry after N−1, got {delivered:?}"
        );
    }

    /// Documents the pre-fix race: poll-from-0 before Subscribe re-delivers all N;
    /// advance-only then ignores the client's older cursor so the damage is permanent
    /// for that connection (client already received the replay).
    #[test]
    fn poll_before_subscribe_replays_entire_offline_window() {
        let ids = ["1000-0", "1001-0", "1002-0", "1003-0", "1004-0"];
        let cursor_n_minus_1 = ids[ids.len() - 2];

        let mut last_stream_id: Option<String> = None;
        // Bug order: open-time poll with None → start id "0" → all N.
        let replayed = messages_after_cursor(&ids, last_stream_id.as_deref());
        assert_eq!(replayed.len(), ids.len());
        last_stream_id = Some(ids[ids.len() - 1].to_string());

        // Subscribe arrives too late; advance-only refuses to rewind.
        let advanced = apply_since_cursor(cursor_n_minus_1, &mut last_stream_id);
        assert!(!advanced);
        assert_eq!(last_stream_id.as_deref(), Some(ids[ids.len() - 1]));

        let after_subscribe = messages_after_cursor(&ids, last_stream_id.as_deref());
        assert!(
            after_subscribe.is_empty(),
            "cursor cannot undo the open-time replay"
        );
    }

    /// After a resume the client has named a position and asked what is past it. Zero is the
    /// answer to that question, and it has to be visible — otherwise "ran and found nothing" is
    /// indistinguishable from "never ran", which is exactly the wrong turn taken on 2026-08-18.
    #[test]
    fn empty_poll_after_a_resume_cursor_is_logged() {
        assert!(empty_poll_is_a_finding(0, true));
    }

    /// An idle wakeup on a user with an empty stream is noise, and this runs on every tick for
    /// every connected user.
    #[test]
    fn empty_poll_without_a_resume_cursor_stays_quiet() {
        assert!(!empty_poll_is_a_finding(0, false));
    }

    /// A poll that found something already logs on the success path; reporting it twice would
    /// make the new line meaningless.
    #[test]
    fn a_non_empty_poll_is_never_reported_as_empty() {
        assert!(!empty_poll_is_a_finding(1, true));
        assert!(!empty_poll_is_a_finding(50, true));
    }

    #[test]
    fn apply_since_cursor_only_advances() {
        let mut last = Some("2000-0".to_string());
        assert!(!apply_since_cursor("1000-0", &mut last));
        assert_eq!(last.as_deref(), Some("2000-0"));

        assert!(apply_since_cursor("2001-0", &mut last));
        assert_eq!(last.as_deref(), Some("2001-0"));
    }

    #[test]
    fn s2_canary_fires_when_poll_has_none_after_subscribe_cursor() {
        // After a valid since_cursor Subscribe, last_stream_id must be Some before poll.
        let mut last: Option<String> = None;
        let subscribe_with_cursor_seen = true;

        apply_since_cursor("1000-0", &mut last);
        assert!(last.is_some());
        assert!(
            !(last.is_none() && subscribe_with_cursor_seen),
            "healthy path: cursor applied before poll"
        );

        // Simulated regression: cursor flag set but position cleared / never applied.
        last = None;
        assert!(
            last.is_none() && subscribe_with_cursor_seen,
            "S2 condition: poll with None after Subscribe with cursor"
        );
    }

    #[test]
    fn redis_stream_cursor_accepts_stream_ids_rejects_uuids() {
        assert!(is_valid_redis_stream_cursor("1786052214011-0"));
        assert!(is_valid_redis_stream_cursor("0"));
        assert!(is_valid_redis_stream_cursor("1772726016")); // bare ms timestamp
        assert!(!is_valid_redis_stream_cursor(
            "d22fc8d6-21eb-42dd-9739-baf26fbe67bf"
        ));
        assert!(!is_valid_redis_stream_cursor("not-a-cursor"));
    }

    #[test]
    fn compare_stream_ids_orders_by_ts_then_seq() {
        assert_eq!(
            compare_stream_ids("100-1", "100-0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_stream_ids("99-9", "100-0"),
            std::cmp::Ordering::Less
        );
    }
}
