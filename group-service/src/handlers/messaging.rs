use construct_db::mls::{
    NewGroupMessage, get_group_retention_days, insert_group_message, list_group_messages,
};
use construct_server_shared::shared::proto::services::v1::{self as proto};
use std::sync::Arc;

use futures_util::{Stream, StreamExt};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_stream::StreamMap;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{
    check_group_member, extract_device_id, extract_user_id, get_group_dissolved_at, get_group_epoch,
};
use crate::service::{GroupHub, GroupServiceImpl, HubEvent};

pub(crate) type FetchGroupMessagesStream = tonic::codegen::BoxStream<proto::GroupMessageEnvelope>;
pub(crate) type MessageStreamStream = tonic::codegen::BoxStream<proto::GroupStreamResponse>;

pub(crate) async fn send_group_message(
    svc: &GroupServiceImpl,
    request: Request<proto::SendGroupMessageRequest>,
) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
    let meta = request.metadata();
    let user_id = extract_user_id(svc, meta)?;
    let device_id = extract_device_id(svc, meta)?;
    let req = request.into_inner();

    let rl_key = format!("rl:group_msg:{}", user_id);
    let allowed = construct_rate_limit::sliding_window_check_and_record(
        &mut svc.redis.clone(),
        &rl_key,
        1000,
        3600,
    )
    .await
    .map_err(|e| Status::internal(format!("Rate limit error: {e}")))?;
    if !allowed {
        return Err(Status::resource_exhausted(
            "Rate limit exceeded: maximum 1000 messages per hour",
        ));
    }

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    if req.mls_ciphertext.is_empty() {
        return Err(Status::invalid_argument("mls_ciphertext must not be empty"));
    }

    if get_group_dissolved_at(&svc.db, group_id).await?.is_some() {
        return Err(Status::failed_precondition("Group has been dissolved"));
    }

    let is_member = check_group_member(&svc.db, group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    let current_epoch = get_group_epoch(&svc.db, group_id).await?;
    if req.epoch != current_epoch as u64 {
        return Err(Status::failed_precondition(format!(
            "Epoch mismatch: client has {}, server is at {}",
            req.epoch, current_epoch
        )));
    }

    let retention_days = get_group_retention_days(&svc.db, group_id)
        .await
        .map_err(|e| Status::internal(format!("Retention lookup failed: {e}")))?;
    let expires_at = chrono::Utc::now() + chrono::Duration::days(retention_days as i64);

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

    let new_msg = NewGroupMessage {
        group_id,
        epoch: current_epoch,
        mls_ciphertext: req.mls_ciphertext.clone(),
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

pub(crate) async fn fetch_group_messages(
    svc: &GroupServiceImpl,
    request: Request<proto::FetchGroupMessagesRequest>,
) -> Result<Response<FetchGroupMessagesStream>, Status> {
    let meta = request.metadata();
    let _user_id = extract_user_id(svc, meta)?;
    let device_id = extract_device_id(svc, meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    let is_member = check_group_member(&svc.db, group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

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

pub(crate) async fn message_stream(
    svc: &GroupServiceImpl,
    request: Request<tonic::Streaming<proto::GroupStreamRequest>>,
) -> Result<Response<MessageStreamStream>, Status> {
    let meta = request.metadata().clone();
    let _user_id = extract_user_id(svc, &meta)?;
    let device_id = extract_device_id(svc, &meta)?;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<proto::GroupStreamResponse, Status>>(512);
    tokio::spawn(serve_message_stream(
        svc.db.clone(),
        svc.hub.clone(),
        device_id,
        request.into_inner(),
        tx,
    ));

    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    Ok(Response::new(Box::pin(outbound)))
}

/// One device's `MessageStream`: answers its frames and forwards the hub events of the groups
/// it subscribed to while it is a member. Ends when either side closes.
pub(crate) async fn serve_message_stream<S>(
    db: Arc<PgPool>,
    hub: Arc<GroupHub>,
    device_id: String,
    mut inbound: S,
    tx: mpsc::Sender<Result<proto::GroupStreamResponse, Status>>,
) where
    S: Stream<Item = Result<proto::GroupStreamRequest, Status>> + Unpin,
{
    let mut groups: StreamMap<Uuid, BroadcastStream<HubEvent>> = StreamMap::new();

    loop {
        let reply = tokio::select! {
            msg = inbound.next() => match msg {
                None => return,
                Some(Err(e)) => {
                    tracing::warn!("MessageStream inbound error for {device_id}: {e}");
                    return;
                }
                Some(Ok(frame)) => match frame.request {
                    Some(proto::group_stream_request::Request::Subscribe(sub)) => {
                        subscribe(&db, &hub, &device_id, &sub.group_ids, &mut groups).await;
                        let refused: Vec<&str> = sub
                            .group_ids
                            .iter()
                            .map(String::as_str)
                            .filter(|gid| gid.parse::<Uuid>().map_or(true, |g| !groups.contains_key(&g)))
                            .collect();
                        (!refused.is_empty()).then(|| {
                            stream_error(
                                frame.request_id,
                                proto::GroupErrorCode::NotMember,
                                format!("Not subscribed (not a member, or the check failed): {}", refused.join(",")),
                            )
                        })
                    }
                    Some(proto::group_stream_request::Request::Heartbeat(hb)) => {
                        Some(proto::GroupStreamResponse {
                            response: Some(proto::group_stream_response::Response::HeartbeatAck(
                                proto::GroupHeartbeatAck {
                                    timestamp: hb.timestamp,
                                    server_timestamp: chrono::Utc::now().timestamp(),
                                },
                            )),
                            response_id: None,
                        })
                    }
                    Some(proto::group_stream_request::Request::Send(_)) => Some(stream_error(
                        frame.request_id,
                        proto::GroupErrorCode::Unspecified,
                        "In-stream send not supported; use SendGroupMessage RPC".into(),
                    )),
                    None => None,
                },
            },
            // An empty map yields `None` at once, which disables this branch for this turn.
            Some((group_id, event)) = groups.next() => match event {
                Ok(HubEvent::Frame(frame)) => Some(frame),
                Ok(HubEvent::Removed(removed)) => {
                    if removed == device_id {
                        groups.remove(&group_id);
                    }
                    None
                }
                Err(BroadcastStreamRecvError::Lagged(n)) => {
                    // Frames were dropped; close the stream so the client re-fetches from its
                    // last sequence number instead of silently missing messages.
                    tracing::warn!(
                        group_id = %group_id,
                        "MessageStream for {device_id} lagged by {n} events; closing"
                    );
                    let _ = tx
                        .send(Err(Status::data_loss(format!(
                            "group {group_id}: stream fell behind; FetchGroupMessages from the last sequence_number"
                        ))))
                        .await;
                    return;
                }
            },
        };

        if let Some(reply) = reply
            && tx.send(Ok(reply)).await.is_err()
        {
            return;
        }
    }
}

/// Adds the groups this device is a member of. The hub receiver is taken before the membership
/// check, so a removal that lands between the two still reaches the stream.
async fn subscribe(
    db: &PgPool,
    hub: &GroupHub,
    device_id: &str,
    group_ids: &[String],
    groups: &mut StreamMap<Uuid, BroadcastStream<HubEvent>>,
) {
    for gid_str in group_ids {
        let Ok(gid) = gid_str.parse::<Uuid>() else {
            continue;
        };
        if groups.contains_key(&gid) {
            continue;
        }
        let rx = hub.subscribe(gid);
        match check_group_member(db, gid, device_id).await {
            Ok(true) => {
                groups.insert(gid, BroadcastStream::new(rx));
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(group_id = %gid, "MessageStream membership check failed: {e}"),
        }
    }
}

fn stream_error(
    request_id: String,
    code: proto::GroupErrorCode,
    message: String,
) -> proto::GroupStreamResponse {
    proto::GroupStreamResponse {
        response: Some(proto::group_stream_response::Response::Error(
            proto::GroupStreamError {
                request_id,
                error_code: code as i32,
                error_message: message,
                retryable: false,
            },
        )),
        response_id: None,
    }
}

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
