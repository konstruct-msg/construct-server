use construct_db::mls::{
    get_group_retention_days, insert_group_message, list_group_messages,
    next_group_message_sequence, NewGroupMessage,
};
use construct_server_shared::shared::proto::services::v1::{self as proto};
use futures_util::StreamExt;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{
    check_group_member, extract_device_id, extract_user_id, get_group_dissolved_at, get_group_epoch,
};
use crate::service::MlsServiceImpl;

pub(crate) type FetchGroupMessagesStream = tonic::codegen::BoxStream<proto::GroupMessageEnvelope>;
pub(crate) type MessageStreamStream = tonic::codegen::BoxStream<proto::GroupStreamResponse>;

// ============================================================================
// SendGroupMessage
// ============================================================================

pub(crate) async fn send_group_message(
    svc: &MlsServiceImpl,
    request: Request<proto::SendGroupMessageRequest>,
) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
    let meta = request.metadata();
    let user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    // Rate limit: 1000 messages per hour per user
    let rate_limit_key = format!("rate_limit:group_msg:{}", user_id);

    // Check if user has exceeded rate limit in last hour
    let recent_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rate_limit_events 
         WHERE key = $1 AND created_at > NOW() - INTERVAL '1 hour'",
    )
    .bind(&rate_limit_key)
    .fetch_one(svc.db.as_ref())
    .await
    .unwrap_or(0);

    if recent_count >= 1000 {
        return Err(Status::resource_exhausted(
            "Rate limit exceeded: maximum 1000 messages per hour",
        ));
    }

    // Record this attempt
    sqlx::query("INSERT INTO rate_limit_events (key, created_at) VALUES ($1, NOW())")
        .bind(&rate_limit_key)
        .execute(svc.db.as_ref())
        .await
        .ok();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    if req.mls_ciphertext.is_empty() {
        return Err(Status::invalid_argument("mls_ciphertext must not be empty"));
    }

    // Reject dissolved groups.
    if get_group_dissolved_at(&svc.db, group_id).await?.is_some() {
        return Err(Status::failed_precondition("Group has been dissolved"));
    }

    // Caller must be a current member.
    check_group_member(&svc.db, group_id, &device_id).await?;

    // Epoch validation: reject stale clients.
    let current_epoch = get_group_epoch(&svc.db, group_id).await?;
    if req.epoch != current_epoch as u64 {
        return Err(Status::failed_precondition(format!(
            "Epoch mismatch: client has {}, server is at {}",
            req.epoch, current_epoch
        )));
    }

    // Retention period → expiry timestamp.
    let retention_days = get_group_retention_days(&svc.db, group_id)
        .await
        .map_err(|e| Status::internal(format!("Retention lookup failed: {e}")))?;
    let expires_at = chrono::Utc::now() + chrono::Duration::days(retention_days as i64);

    // Parse optional UUIDs.
    let thread_id = req
        .thread_id
        .as_deref()
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| Status::invalid_argument("Invalid thread_id"))?;

    let topic_id = req
        .topic_id
        .as_deref()
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| Status::invalid_argument("Invalid topic_id"))?;

    let client_message_id = if req.client_message_id.is_empty() {
        None
    } else if req.client_message_id.len() > 64 {
        return Err(Status::invalid_argument(
            "client_message_id must not exceed 64 characters",
        ));
    } else {
        Some(req.client_message_id.clone())
    };

    // Atomically allocate the next sequence number.
    let sequence_number = next_group_message_sequence(&svc.db, group_id)
        .await
        .map_err(|e| Status::internal(format!("Sequence allocation failed: {e}")))?;

    let new_msg = NewGroupMessage {
        group_id,
        epoch: current_epoch,
        mls_ciphertext: req.mls_ciphertext.clone(),
        sequence_number,
        client_message_id,
        thread_id,
        topic_id,
        expires_at,
    };

    let row = insert_group_message(&svc.db, &new_msg).await.map_err(|e| {
        tracing::error!(
            group_id = %group_id,
            user_id  = %user_id,
            device_id = %device_id,
            "insert_group_message failed: {e}"
        );
        Status::internal("Failed to store message")
    })?;

    // Fan-out to active MessageStream subscribers.
    let envelope = group_message_row_to_envelope(&row);
    svc.hub.publish(
        group_id,
        proto::GroupStreamResponse {
            response: Some(proto::group_stream_response::Response::Message(
                envelope.clone(),
            )),
            response_id: None,
        },
    );

    Ok(Response::new(proto::SendGroupMessageResponse {
        message_id: row.message_id.to_string(),
        sent_at: row.sent_at.timestamp(),
        sequence_number: row.sequence_number as u64,
        expires_at: row.expires_at.timestamp(),
    }))
}

// ============================================================================
// FetchGroupMessages
// ============================================================================

pub(crate) async fn fetch_group_messages(
    svc: &MlsServiceImpl,
    request: Request<proto::FetchGroupMessagesRequest>,
) -> Result<Response<FetchGroupMessagesStream>, Status> {
    let meta = request.metadata();
    let _user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    check_group_member(&svc.db, group_id, &device_id).await?;

    let limit = req.limit.clamp(1, 200) as i64;

    let topic_id = req
        .topic_id
        .as_deref()
        .map(|s| s.parse::<Uuid>())
        .transpose()
        .map_err(|_| Status::invalid_argument("Invalid topic_id"))?;

    let after_sequence = req.after_sequence.map(|s| s as i64);

    let rows = list_group_messages(&svc.db, group_id, after_sequence, limit, topic_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to fetch messages: {e}")))?;

    let envelopes: Vec<Result<proto::GroupMessageEnvelope, Status>> = rows
        .into_iter()
        .map(|r| Ok(group_message_row_to_envelope(&r)))
        .collect();

    let stream = futures_util::stream::iter(envelopes);
    Ok(Response::new(Box::pin(stream)))
}

// ============================================================================
// MessageStream (bidirectional)
// ============================================================================

pub(crate) async fn message_stream(
    svc: &MlsServiceImpl,
    request: Request<tonic::Streaming<proto::GroupStreamRequest>>,
) -> Result<Response<MessageStreamStream>, Status> {
    let meta = request.metadata().clone();
    let _user_id = extract_user_id(&meta)?;
    let device_id = extract_device_id(&meta)?;

    let db = svc.db.clone();
    let hub = svc.hub.clone();
    let mut inbound = request.into_inner();

    // We use an mpsc channel to multiplex events from multiple group broadcast
    // receivers and the inbound stream into a single outbound stream.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<proto::GroupStreamResponse, Status>>(512);

    tokio::spawn(async move {
        // Keep track of the broadcast receivers so they live long enough.
        let mut group_receivers: Vec<tokio::sync::broadcast::Receiver<proto::GroupStreamResponse>> =
            Vec::new();

        loop {
            tokio::select! {
                // Process inbound client frames.
                msg = inbound.next() => {
                    match msg {
                        None => break, // client closed stream
                        Some(Err(e)) => {
                            tracing::warn!("MessageStream inbound error for {device_id}: {e}");
                            break;
                        }
                        Some(Ok(frame)) => {
                            match frame.request {
                                Some(proto::group_stream_request::Request::Subscribe(sub)) => {
                                    for gid_str in &sub.group_ids {
                                        let gid = match gid_str.parse::<Uuid>() {
                                            Ok(v) => v,
                                            Err(_) => continue,
                                        };
                                        // Verify membership before subscribing.
                                        if check_group_member(&db, gid, &device_id).await.is_ok() {
                                            group_receivers.push(hub.subscribe(gid));
                                        }
                                    }
                                }
                                Some(proto::group_stream_request::Request::Heartbeat(hb)) => {
                                    let ack = proto::GroupStreamResponse {
                                        response: Some(
                                            proto::group_stream_response::Response::HeartbeatAck(
                                                proto::GroupHeartbeatAck {
                                                    timestamp: hb.timestamp,
                                                    server_timestamp: chrono::Utc::now().timestamp(),
                                                },
                                            ),
                                        ),
                                        response_id: None,
                                    };
                                    if tx.send(Ok(ack)).await.is_err() {
                                        break;
                                    }
                                }
                                // SendGroupMessageRequest inside a stream is not yet
                                // supported — direct SendGroupMessage RPC is preferred.
                                Some(proto::group_stream_request::Request::Send(_)) => {
                                    let err = proto::GroupStreamResponse {
                                        response: Some(
                                            proto::group_stream_response::Response::Error(
                                                proto::GroupStreamError {
                                                    request_id: frame.request_id.clone(),
                                                    error_code: proto::GroupErrorCode::Unspecified as i32,
                                                    error_message: "In-stream send not supported; use SendGroupMessage RPC".into(),
                                                    retryable: false,
                                                },
                                            ),
                                        ),
                                        response_id: None,
                                    };
                                    if tx.send(Ok(err)).await.is_err() {
                                        break;
                                    }
                                }
                                None => {}
                            }
                        }
                    }
                }

                // Forward broadcast events from subscribed groups.
                // We poll each receiver round-robin by trying each in sequence.
                // Using try_recv avoids blocking; the outer loop drives wakeups.
                else => {
                    let mut any = false;
                    for rx in group_receivers.iter_mut() {
                        match rx.try_recv() {
                            Ok(event) => {
                                any = true;
                                if tx.send(Ok(event)).await.is_err() {
                                    return;
                                }
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                                tracing::warn!(
                                    "MessageStream receiver lagged by {n} messages for {device_id}"
                                );
                            }
                            Err(_) => {}
                        }
                    }
                    if !any {
                        // No events ready — yield to avoid busy-spinning.
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        }
    });

    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    Ok(Response::new(Box::pin(outbound)))
}

// ============================================================================
// Helpers
// ============================================================================

fn group_message_row_to_envelope(
    row: &construct_db::mls::GroupMessageRow,
) -> proto::GroupMessageEnvelope {
    proto::GroupMessageEnvelope {
        message_id: row.message_id.to_string(),
        group_id: row.group_id.to_string(),
        epoch: row.epoch as u64,
        mls_ciphertext: row.mls_ciphertext.clone(),
        sent_at: row.sent_at.timestamp(),
        sequence_number: row.sequence_number as u64,
        thread_id: row.thread_id.map(|id| id.to_string()),
        topic_id: row.topic_id.map(|id| id.to_string()),
        expires_at: row.expires_at.timestamp(),
    }
}
