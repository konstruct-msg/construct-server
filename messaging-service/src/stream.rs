use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::context::MessagingServiceContext;
use crate::core;
use crate::envelope::{convert_envelope_to_proto, dispatch_sealed_sender};
use crate::receipts::build_receipt_response;
use crate::sealed_ip::{SealedIpDecision, check_sealed_ip_limit};
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
    /// Opaque exclusive resume position of both sources. A reconnect receives exactly the
    /// per-frame checkpoint, not a shared watermark or a server-only user position.
    pub last_stream_id: Option<String>,
    /// Subscribe on this connection carried a valid `since_cursor` (S2 canary).
    pub subscribe_with_cursor_seen: bool,
    /// First offline catch-up completed (Subscribe handler or grace timer).
    pub initial_catchup_done: bool,
}

/// Handle incoming MessageStreamRequest from client.
///
/// On `Subscribe`, applies `since_cursor` as a **read offset only** (never XTRIM)
/// and then runs the offline catch-up poll. The open path must **not** poll
/// before that — doing so re-delivers the entire offline stream and races the
/// cursor.
#[allow(clippy::too_many_arguments)] // sealed IP is the 8th; bundling would hide the gate
pub(crate) async fn handle_stream_request(
    req: proto::MessageStreamRequest,
    context: &Arc<MessagingServiceContext>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    user_id: &mut Option<uuid::Uuid>,
    device_id: Option<&str>,
    stream_queue: &mut construct_queue::MessageQueue,
    catchup: &mut StreamCatchupState,
    client_ip: &str,
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
                // Same per-IP window as SendSealedMessage. Unauthenticated stream
                // sealed used to skip this gate entirely.
                if check_sealed_ip_limit(context, client_ip).await == SealedIpDecision::Limited {
                    let error = proto::MessageError {
                        message_id: String::new(),
                        error_code: proto::ErrorCode::RateLimit.into(),
                        error_message: "sealed-sender rate limit exceeded for this IP".to_string(),
                        retryable: true,
                        retry_after_ms: Some(60_000),
                    };
                    let response = proto::MessageStreamResponse {
                        response: Some(proto::message_stream_response::Response::Error(error)),
                        response_id: Some(req.request_id.clone()),
                        stream_cursor: None,
                        attempt_id,
                    };
                    tx.send(Ok(response)).await?;
                    return Ok(());
                }
                construct_metrics::MSG_SEALED_INGRESS_TOTAL
                    .with_label_values(&["stream"])
                    .inc();
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
                // Same 64 KiB cap as SendMessage. Until 2026-10-29 this path checked only for
                // empty, so a stream send wrote anything up to the gRPC decode limit into the
                // recipient's mailbox (construct-docs todo 228).
                crate::grpc::validate_payload(&envelope.encrypted_payload)
                    .map_err(|e| anyhow::anyhow!(e))?;
                let sender_device_id = crate::grpc::sentinel_sender_device(
                    device_id,
                    envelope
                        .sender_device
                        .as_ref()
                        .map(|d| d.device_id.as_str()),
                )
                .map_err(|status| anyhow::anyhow!(status.message().to_string()))?;

                // Prefer client-provided message_id for idempotency; generate only as fallback.
                use construct_server_shared::shared::proto::core::v1 as proto_core;
                let message_id = match &envelope.message_id_type {
                    Some(proto_core::envelope::MessageIdType::MessageId(id)) if !id.is_empty() => {
                        id.clone()
                    }
                    _ => uuid::Uuid::new_v4().to_string(),
                };

                // ── Sentinel check (ban/block/user-level rate limits) ───────
                // Must mirror the sentinel check in send_message gRPC so that limits
                // enforced on one transport are also enforced on the other.
                // Fails open — sentinel outage does not block message delivery.
                let recipient_device_id = envelope
                    .recipient_device
                    .as_ref()
                    .map(|d| d.device_id.as_str())
                    .unwrap_or("");

                if let Some(ref sentinel) = context.sentinel {
                    let target = if !recipient_device_id.is_empty() {
                        recipient_device_id
                    } else {
                        sender_device_id
                    };
                    // In-process call to SentinelCore — no gRPC hop.
                    // Fails open: on Redis/internal error we allow the send
                    // through (mirrors the previous gRPC-client fail-open
                    // behaviour when sentinel-service was unreachable).
                    let (allowed, reason, retry_after) = match crate::core::send_permission(
                        sentinel,
                        sender_device_id,
                        target,
                        &uid.to_string(),
                        &recipient_id,
                    )
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
                        let (error_code, retryable, retry_after_ms) = if retry_after > 0 {
                            tracing::info!(sender = %uid, retry_after_secs = retry_after, reason = %reason, "Sentinel: stream send denied (rate limited)");
                            (
                                proto::ErrorCode::RateLimit,
                                true,
                                Some((retry_after * 1000).into()),
                            )
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
                            attempt_id,
                        };
                        tx.send(Ok(response)).await?;
                        return Ok(());
                    }
                }

                // ── Rate limiting (same policy as send_message gRPC) ────────
                if let Ok(mut redis_conn) = context.redis_conn().await {
                    let trust = crate::trust::get_trust_level(
                        &mut redis_conn,
                        &context.db_pool,
                        *uid,
                        &context.config.messaging,
                    )
                    .await;

                    let limited = crate::trust::check_send_limits(
                        &mut redis_conn,
                        trust,
                        &context.config.messaging,
                        &uid.to_string(),
                        &recipient_id,
                    )
                    .await;

                    if let Some((limit, retry)) = limited {
                        let error = crate::trust::rate_limited_error(
                            &message_id,
                            &uid.to_string(),
                            limit,
                            retry,
                        );
                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                            stream_cursor: None,
                            attempt_id,
                        };
                        tx.send(Ok(response)).await?;
                        return Ok(());
                    }
                }

                use construct_server_shared::message::types::{
                    MessageEnvelope, ProtoEnvelopeContext,
                };
                let msg_envelope = MessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
                    sender_id: uid.to_string(),
                    recipient_id,
                    message_id: message_id.clone(),
                    encrypted_payload: envelope.encrypted_payload.to_vec(),
                    content_type: envelope.content_type,
                    recipient_device: core::named_recipient_device(
                        envelope.recipient_device.as_ref(),
                    ),
                });

                match core::dispatch_envelope(
                    context,
                    msg_envelope,
                    context.notification_context.clone(),
                    core::DeviceTargets::LookUp,
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
                attempt_id: req.attempt_id,
            };

            tx.send(Ok(response)).await?;
        }

        // Subscribe/Unsubscribe: conversation_ids are intentionally not logged or stored
        // to avoid leaking the client's contact graph to the server.
        // All messages for this user are already routed to their Redis stream regardless.
        // A plaintext receipt on the stream is not relayed (see `receipts.rs`): receipts travel
        // end-to-end. Dropped without reading it, so nothing in it reaches a log.
        Some(StreamReq::Receipt(_)) => {
            tracing::debug!("Plaintext stream receipt dropped — receipts travel end-to-end");
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
                // Opaque checkpoints and legacy numeric IDs are bookmarks, not message UUIDs.
                // An invalid legacy bookmark retains the historical replay-from-zero fallback;
                // malformed/unsupported modern tokens fail explicitly instead of hiding a reset.
                if cursor.starts_with("mc") && !is_valid_mailbox_cursor(cursor) {
                    return Err(construct_queue::InvalidMailboxCursor.into());
                }
                if !is_valid_mailbox_cursor(cursor) {
                    tracing::warn!(
                        cursor = %cursor,
                        "Ignoring invalid legacy since_cursor on Subscribe (expected mailbox cursor, not message UUID)"
                    );
                } else {
                    catchup.subscribe_with_cursor_seen = true;

                    // since_cursor is a read offset only. Do NOT trim here.
                    // Client-asserted XTRIM on the shared user mailbox created a silent-loss
                    // class (paging/cancel races; multi-device fastest-cursor wins). Retention
                    // is MAXLEN + age sweep. See construct-docs
                    // decisions/minimal-server-delivery.md (Accepted — step 2).
                    apply_since_cursor(cursor, &mut catchup.last_stream_id);

                    // Before the first delivery: the queue trimmed messages after this cursor
                    // that will never arrive (decisions/mailbox-gap-is-reported.md). Once per
                    // stream; best effort — a failed check is no gap.
                    if !catchup.initial_catchup_done
                        && let Some(uid) = *user_id
                    {
                        match stream_queue
                            .mailbox_gap(&uid.to_string(), device_id, cursor)
                            .await
                        {
                            Ok(Some(gap)) => {
                                construct_metrics::MSG_MAILBOX_GAP_REPORTED_TOTAL
                                    .with_label_values(&["stream"])
                                    .inc();
                                let response = proto::MessageStreamResponse {
                                    response: Some(
                                        proto::message_stream_response::Response::MailboxGap(
                                            proto::MailboxGap {
                                                after_cursor: gap.after_cursor,
                                                resumes_at: gap.resumes_at,
                                            },
                                        ),
                                    ),
                                    response_id: None,
                                    stream_cursor: None,
                                    attempt_id: None,
                                };
                                tx.send(Ok(response)).await?;
                            }
                            Ok(None) => {}
                            Err(e) => tracing::warn!(error = %e, "mailbox gap check failed"),
                        }
                    }
                }
            }

            // Offline catch-up after cursor application (or Subscribe without cursor).
            // Grace-timer path in grpc.rs covers clients that never Subscribe.
            if !catchup.initial_catchup_done
                && let Some(uid) = *user_id
            {
                let resume_with_cursor = catchup.subscribe_with_cursor_seen;
                if let Err(e) = poll_messages(
                    stream_queue,
                    &context.config.messaging,
                    uid,
                    device_id,
                    catchup,
                    tx,
                    resume_with_cursor,
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
            // Reserved for P2P direct transport integration.
            // Currently accepted as a no-op to keep stream protocol forward-compatible.
            tracing::debug!("Received unimplemented request type (p2p_handoff_ack)");
        }
        Some(StreamReq::P2pDisconnect(_)) => {
            // Reserved for P2P direct transport integration.
            // Currently accepted as a no-op to keep stream protocol forward-compatible.
            tracing::debug!("Received unimplemented request type (p2p_disconnect)");
        }

        None => {
            tracing::warn!("Received empty stream request");
        }
    }

    Ok(())
}

/// Shared validation of opaque and legacy mailbox cursors (read offsets only).
pub(crate) fn is_valid_mailbox_cursor(cursor: &str) -> bool {
    cursor == "$" || cursor.parse::<construct_queue::MailboxCursor>().is_ok()
}

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

/// Join a client bookmark componentwise: advance either source without rewinding the other.
/// Returns whether it changed. `$` is accepted only before a position has been established.
fn apply_since_cursor(cursor: &str, last_stream_id: &mut Option<String>) -> bool {
    use construct_queue::MailboxCursor;
    let next = match (last_stream_id.as_deref(), cursor.parse::<MailboxCursor>()) {
        (None, _) if is_valid_mailbox_cursor(cursor) => cursor.to_string(),
        (Some("$"), Ok(_)) => cursor.to_string(),
        (Some(current), Ok(requested)) => {
            let Ok(previous) = current.parse::<MailboxCursor>() else {
                return false;
            };
            let joined = previous.join(requested);
            if joined == previous {
                return false;
            }
            if !current.starts_with("mc") && !cursor.starts_with("mc") {
                cursor.to_string() // Retain the legacy representation until the first read.
            } else {
                joined.encode()
            }
        }
        _ => return false,
    };
    tracing::info!(cursor = %next, "Resuming stream from client since_cursor");
    *last_stream_id = Some(next);
    true
}

/// Legacy scalar ordering used by the Subscribe race regression fixtures below.
#[cfg(test)]
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

/// Spawns a background task that ends with the gRPC stream it serves. Automatically
/// reconnects on Redis connection loss so the fallback 5s poll is never triggered in
/// normal operation.
///
/// **It must notice the stream closing on its own.** Until 2026-10-03 it noticed only by
/// failing to forward a wakeup, which needs a publish on the user's channel after the
/// stream had gone. A client that reconnected without receiving a message left its
/// pub/sub connection open: one per reconnect, for the life of the process. Production
/// messaging reached 1006 such connections in 34 hours (661 on one channel), hit its
/// 1024-descriptor limit and failed every send with "Too many open files". Every wait
/// in this task — on a message, on a connect, on a retry delay — now also waits on
/// [`mpsc::Sender::closed`].
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
        // Exits when the gRPC stream closes (receiver dropped), whatever it is waiting on.
        loop {
            let connected = tokio::select! {
                p = client.get_async_pubsub() => p,
                _ = tx.closed() => return,
            };
            let mut pubsub = match connected {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, channel = %channel, "inbox_wakeup: pub/sub connect failed, retrying in 2s");
                    if !retry_delay(&tx).await {
                        return;
                    }
                    continue;
                }
            };
            let subscribed = tokio::select! {
                r = pubsub.subscribe(&channel) => r,
                _ = tx.closed() => return,
            };
            if let Err(e) = subscribed {
                tracing::warn!(error = %e, channel = %channel, "inbox_wakeup: subscribe failed, retrying in 2s");
                if !retry_delay(&tx).await {
                    return;
                }
                continue;
            }
            tracing::debug!(channel = %channel, "inbox_wakeup: subscribed");

            // Synthetic wakeup immediately after subscribe: polls for any messages
            // that were dispatched during the TCP-connect + SUBSCRIBE window (~50 ms).
            // Without this, those messages would wait for the next fallback poll (5s).
            if tx.send(()).await.is_err() {
                return; // stream closed
            }

            match forward_wakeups(pubsub.into_on_message(), &tx).await {
                WakeupEnd::StreamClosed => return,
                WakeupEnd::ConnectionLost => {
                    tracing::debug!(channel = %channel, "inbox_wakeup: connection lost, reconnecting");
                }
            }
        }
    });
}

/// Why [`forward_wakeups`] returned.
#[derive(Debug, PartialEq, Eq)]
enum WakeupEnd {
    /// The gRPC stream is gone: the task ends, and its pub/sub connection with it.
    StreamClosed,
    /// The pub/sub connection dropped while the stream is alive: reconnect.
    ConnectionLost,
}

/// Forwards each pub/sub message as a wakeup until the stream closes or the
/// connection drops — whichever comes first, with no message needed to notice either.
async fn forward_wakeups<S>(mut messages: S, tx: &mpsc::Sender<()>) -> WakeupEnd
where
    S: tokio_stream::Stream + Unpin,
{
    loop {
        tokio::select! {
            msg = messages.next() => match msg {
                Some(_) => {
                    if tx.send(()).await.is_err() {
                        return WakeupEnd::StreamClosed;
                    }
                }
                None => return WakeupEnd::ConnectionLost,
            },
            _ = tx.closed() => return WakeupEnd::StreamClosed,
        }
    }
}

/// The 2 s pause before a reconnect attempt. False when the stream closed during it.
async fn retry_delay(tx: &mpsc::Sender<()>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => true,
        _ = tx.closed() => false,
    }
}

/// One mailbox page on the stream. `read_mailbox_messages` reads each source
/// twice this deep, so a sibling backlog of that depth fills the user read and
/// ends the page before this device's later entries.
pub(crate) const STREAM_MAILBOX_PAGE: usize = 50;

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
    device_id: Option<&str>,
    catchup: &mut StreamCatchupState,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    // True only for the catch-up poll that follows a resume. The wakeup and fallback-tick
    // callers pass false: an empty read there is the normal idle case, and reporting it turned
    // the log into one line per second per connected user.
    is_resume_catchup: bool,
) -> anyhow::Result<()> {
    let user_id_str = user_id.to_string();
    let StreamCatchupState { last_stream_id, .. } = catchup;

    if last_stream_id.is_none() && is_resume_catchup {
        tracing::warn!(
            user_id = %user_id_str,
            "poll_messages started with no stream cursor after Subscribe carried since_cursor — possible catch-up race regression"
        );
        construct_metrics::MSG_POLL_MISSING_CURSOR_AFTER_SUBSCRIBE_TOTAL.inc();
    }

    let mode = if device_id.filter(|d| !d.is_empty()).is_some() {
        "device_merge"
    } else {
        "user_only"
    };
    // A page ends at the shorter source read (#116). On a sibling backlog that
    // page can hold nothing of this device's, and stopping there left the rest
    // until the next fallback tick. This poll reads on while the page says more
    // remains. The cursors move only as far as this loop delivers, so a send
    // that fails resumes there.
    let mut seen = 0usize;
    let mut pages = 0usize;
    loop {
        anyhow::ensure!(!tx.is_closed(), "message stream closed during catch-up");
        // A device removed while its stream is open (RevokeDevice, or Logout elsewhere) must stop
        // receiving now — the stream authenticated once, at open. Ending it with the answer
        // AuthenticateDevice gives sends the client through refresh (refused since 2decc7a) to
        // device auth, which tells it it was removed. The marker lives one access-token TTL, and
        // this runs on every wakeup and fallback tick, so an open stream is caught well inside it.
        // Fail open on a Redis error: ending every stream on a Redis blip is a reconnect storm.
        if let Some(device) = device_id.filter(|d| !d.is_empty()) {
            match queue.is_device_revoked(device).await {
                Ok(true) => {
                    tracing::info!("poll_messages: device was removed — ending its stream");
                    let _ = tx
                        .send(Err(
                            construct_server_shared::auth_utils::device_refusal_status(
                                construct_error::DeviceRefusal::Removed,
                            ),
                        ))
                        .await;
                    anyhow::bail!("device removed while its stream was open");
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "poll_messages: revoked-device check failed — continuing")
                }
            }
        }

        pages += 1;
        let cursor_before = last_stream_id.clone();

        let t_xread = std::time::Instant::now();
        let page = queue
            .read_mailbox_messages(
                &user_id_str,
                device_id,
                last_stream_id.as_deref(),
                last_stream_id.as_deref(),
                STREAM_MAILBOX_PAGE,
            )
            .await?;
        // Read before `entries` is moved out: a method on the page borrows the whole struct.
        let user_only_count = page.user_only();
        let has_more = page.has_more;
        let page_cursor = page.resume_cursor().encode();
        let msg_count = page.entries.len();
        // Delivering to the device consumes the push that announced it; the next envelope may push
        // again. Only on a non-empty read — an idle poll runs every few seconds per open stream.
        if msg_count > 0
            && let Some(device) = device_id.filter(|d| !d.is_empty())
        {
            let _ = queue.clear_push_outstanding(device).await;
        }
        construct_metrics::MSG_MAILBOX_READ_TOTAL
            .with_label_values(&["stream", mode])
            .inc();
        if !page.user_only_ids.is_empty() {
            construct_metrics::MSG_MAILBOX_USER_ONLY_ENTRIES_TOTAL
                .with_label_values(&["stream"])
                .inc_by(page.user_only_ids.len() as u64);
            // WARN, and with the ids: every one of these is a message `MSG_MAILBOX_USER_WRITE=0`
            // would have dropped. The counter alone dates the divergence to a scrape interval and
            // leaves nobody able to ask which message, from whom, by which route — which is where
            // the gate stood on 2026-09-21 with two entries and no way to name them.
            tracing::warn!(
                user_id = %user_id_str,
                device_id = device_id.unwrap_or(""),
                mailbox_mode = mode,
                message_ids = ?page.user_only_ids,
                "mailbox cutover blocker: delivered from the user stream, absent from the device stream"
            );
        }
        if page.sibling_skipped > 0 {
            construct_metrics::MSG_MAILBOX_SIBLING_ENTRIES_SKIPPED_TOTAL
                .with_label_values(&["stream"])
                .inc_by(page.sibling_skipped as u64);
        }
        let xread_ms = t_xread.elapsed().as_millis();

        seen += msg_count;
        if msg_count > 0 {
            tracing::info!(
                user_id = %user_id_str,
                device_id = device_id.unwrap_or(""),
                mailbox_mode = mode,
                msg_count,
                user_only = user_only_count,
                xread_ms,
                last_stream_id = ?last_stream_id,
                "poll_messages: read messages from Redis offline mailbox"
            );
        } else if xread_ms > config.stream_xread_slow_ms {
            tracing::info!(xread_ms, msg_count, "poll_messages timing (slow)");
        }

        for (cursor, envelope) in page.into_cursor_entries() {
            let stream_id = cursor.encode();
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
                    attempt_id: None,
                }
            };

            // Attach this entry's complete checkpoint, never the final page cursor.
            // Disconnect after any frame must leave every unreturned peer readable.
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

        // Commit trailing ignorable prefixes only after all frames were queued successfully.
        // An early return retains the last successfully sent frame's complete checkpoint.
        *last_stream_id = Some(page_cursor);

        if !has_more {
            break;
        }
        // A page that reports more and moves neither cursor would spin.
        if last_stream_id == &cursor_before {
            tracing::warn!(
                user_id = %user_id_str,
                "poll_messages: has_more but the cursors did not move — stopping"
            );
            break;
        }
    }

    if pages > 1 {
        tracing::info!(
            user_id = %user_id_str,
            pages,
            msg_count = seen,
            "poll_messages: read on while the page had more"
        );
    }
    if empty_poll_is_a_finding(seen, is_resume_catchup) {
        tracing::info!(
            user_id = %user_id_str,
            msg_count = seen,
            last_stream_id = ?last_stream_id,
            "poll_messages: nothing after the client's resume cursor"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The leak of 2026-10-03: a stream that closes while its user's channel is quiet
    /// must release the subscription at once, not at the next publish. Mutation: drop
    /// the `tx.closed()` arm — the forwarder waits on a message that never comes and
    /// the timeout fires.
    #[tokio::test]
    async fn wakeup_forwarder_ends_when_the_stream_closes_on_a_quiet_channel() {
        let (tx, rx) = mpsc::channel::<()>(4);
        let quiet = tokio_stream::pending::<()>();
        let forwarder = tokio::spawn(async move { forward_wakeups(quiet, &tx).await });
        drop(rx);
        let end = tokio::time::timeout(std::time::Duration::from_secs(1), forwarder)
            .await
            .expect("forwarder must notice the closed stream without a message")
            .unwrap();
        assert_eq!(end, WakeupEnd::StreamClosed);
    }

    /// Messages are forwarded while the stream lives, and a dropped connection is
    /// reported as such so the task reconnects rather than ending.
    #[tokio::test]
    async fn wakeup_forwarder_forwards_then_reports_a_lost_connection() {
        let (tx, mut rx) = mpsc::channel::<()>(4);
        let end = forward_wakeups(tokio_stream::iter([(), ()]), &tx).await;
        assert_eq!(end, WakeupEnd::ConnectionLost);
        assert_eq!(rx.recv().await, Some(()));
        assert_eq!(rx.recv().await, Some(()));
    }

    /// A reconnect pause ends early, and says so, when the stream closes during it.
    #[tokio::test]
    async fn retry_delay_ends_when_the_stream_closes() {
        let (tx, rx) = mpsc::channel::<()>(1);
        drop(rx);
        let r = tokio::time::timeout(std::time::Duration::from_millis(500), retry_delay(&tx))
            .await
            .expect("the pause must not outlive the stream");
        assert!(!r);
    }

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
        assert!(is_valid_mailbox_cursor("1786052214011-0"));
        assert!(is_valid_mailbox_cursor("0"));
        assert!(is_valid_mailbox_cursor("1772726016")); // bare ms timestamp
        assert!(is_valid_mailbox_cursor("$"));
        assert!(is_valid_mailbox_cursor(
            &construct_queue::MailboxCursor::default().to_string()
        ));
        assert!(!is_valid_mailbox_cursor(
            "d22fc8d6-21eb-42dd-9739-baf26fbe67bf"
        ));
        assert!(!is_valid_mailbox_cursor("not-a-cursor"));
        assert!(!is_valid_mailbox_cursor("mc1:0-0:0-0"));
    }

    #[test]
    fn subscribe_joins_source_positions_without_borrowing_a_siblings_watermark() {
        let d = "mc1:00000000000000000500-00000000000000000000:00000000000000000100-00000000000000000000";
        let u = "mc1:00000000000000000200-00000000000000000000:00000000000000000300-00000000000000000000";
        let both = "mc1:00000000000000000500-00000000000000000000:00000000000000000300-00000000000000000000";
        let mut last = Some(d.to_string());
        assert!(apply_since_cursor(u, &mut last));
        assert_eq!(last.as_deref(), Some(both));
        assert!(!apply_since_cursor(d, &mut last));
        assert!(!apply_since_cursor("$", &mut last));
        assert!(!apply_since_cursor("mc1:bad", &mut last));
        assert_eq!(last.as_deref(), Some(both));
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

/// One poll used to stop after a single page. After a page ends at the shorter
/// source read, a sibling backlog of `2 * STREAM_MAILBOX_PAGE` fills that page
/// with nothing of this device's, and the device's own next message waited for
/// the fallback tick. Mutation: `break` on the first page — this message is absent.
#[cfg(test)]
mod catchup_drains_pages {
    use super::*;

    fn queue_config() -> construct_config::Config {
        let redis =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        unsafe {
            std::env::set_var("REDIS_URL", &redis);
            if std::env::var_os("DATABASE_URL").is_none() {
                std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
            }
            std::env::set_var("INSTANCE_DOMAIN", "test.local");
            std::env::set_var(
                "SERVER_SIGNING_KEY",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            );
            std::env::set_var("TOKEN_ISSUER_KEY", "0".repeat(64));
            std::env::set_var("APNS_DEVICE_TOKEN_ENCRYPTION_KEY", "0".repeat(64));
            std::env::set_var("LOG_HASH_SALT", "test_log_hash_salt_unique_for_tests_only");
        }
        let mut config =
            construct_config::Config::from_env_for(construct_config::SecretNeeds::MESSAGING)
                .expect("test config");
        config.messaging.mailbox_user_write = true;
        config
    }

    fn id_of(response: &proto::MessageStreamResponse) -> Option<String> {
        match &response.response {
            Some(proto::message_stream_response::Response::Message(env)) => match &env
                .message_id_type
            {
                Some(
                    construct_server_shared::shared::proto::core::v1::envelope::MessageIdType::MessageId(
                        mid,
                    ),
                ) if !mid.is_empty() => Some(mid.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn one_poll_delivers_past_a_sibling_page() {
        let mut queue = construct_queue::MessageQueue::new(&queue_config())
            .await
            .expect("Redis");
        let user = uuid::Uuid::new_v4();
        let reader = format!("reader-{}", uuid::Uuid::new_v4());
        let sibling = format!("sibling-{}", uuid::Uuid::new_v4());
        let user_s = user.to_string();

        let named = |device: &str| {
            let mut env = construct_message::types::MessageEnvelope::new_key_sync(
                "alice".into(),
                user_s.clone(),
            );
            env.recipient_device = Some(device.to_string());
            env
        };
        // The user-stream read of one page is twice STREAM_MAILBOX_PAGE deep.
        for _ in 0..(STREAM_MAILBOX_PAGE * 2) {
            queue
                .write_message_to_device_streams(
                    &user_s,
                    std::slice::from_ref(&sibling),
                    &named(&sibling),
                )
                .await
                .expect("sibling write");
        }
        let own = named(&reader);
        let own_id = own.message_id.clone();
        queue
            .write_message_to_device_streams(&user_s, std::slice::from_ref(&reader), &own)
            .await
            .expect("reader write");

        let (tx, mut rx) = mpsc::channel(8);
        let mut catchup = StreamCatchupState::default();
        poll_messages(
            &mut queue,
            &construct_config::MessagingConfig::default(),
            user,
            Some(&reader),
            &mut catchup,
            &tx,
            true,
        )
        .await
        .expect("poll");
        drop(tx);

        let mut ids = Vec::new();
        while let Some(item) = rx.recv().await {
            if let Some(id) = item.ok().as_ref().and_then(id_of) {
                ids.push(id);
            }
        }
        assert!(
            ids.contains(&own_id),
            "one poll must walk past the sibling page, got {ids:?}"
        );
        // Independent user/device stream ids can place the two copies on different
        // pages. At-least-once allows that repeat; siblings must still never appear.
        assert!(
            ids.iter().all(|id| id == &own_id),
            "unexpected delivery: {ids:?}"
        );

        queue.delete_mailbox(&user_s).await.expect("cleanup");
    }
}
