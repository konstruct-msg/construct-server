use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Status};
use uuid::Uuid;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db, make_test_service,
};
use crate::handlers::messaging::serve_message_stream;
use crate::service::{GroupHub, GroupServiceImpl};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, group_stream_request::Request as In, group_stream_response::Response as Out,
    mls_service_server::MlsService,
};

/// The client side of one `MessageStream`.
struct Client {
    up: mpsc::Sender<Result<proto::GroupStreamRequest, Status>>,
    down: mpsc::Receiver<Result<proto::GroupStreamResponse, Status>>,
}

impl Client {
    fn open(db: Arc<sqlx::PgPool>, hub: Arc<GroupHub>, device_id: &str) -> Self {
        let (up, up_rx) = mpsc::channel(16);
        let (down_tx, down) = mpsc::channel(16);
        tokio::spawn(serve_message_stream(
            db,
            hub,
            device_id.to_string(),
            ReceiverStream::new(up_rx),
            down_tx,
        ));
        Self { up, down }
    }

    async fn send(&self, request: In) {
        self.up
            .send(Ok(proto::GroupStreamRequest {
                request: Some(request),
                request_id: "r1".into(),
            }))
            .await
            .expect("stream is open");
    }

    async fn subscribe(&self, group_id: Uuid) {
        self.send(In::Subscribe(proto::GroupSubscribeRequest {
            group_ids: vec![group_id.to_string()],
        }))
        .await;
    }

    async fn next(&mut self) -> Result<proto::GroupStreamResponse, Status> {
        tokio::time::timeout(Duration::from_secs(1), self.down.recv())
            .await
            .expect("a frame within 1 s")
            .expect("stream still open")
    }

    /// Every frame the server sent before it answered this heartbeat.
    async fn until_heartbeat_ack(&mut self) -> Vec<Out> {
        self.send(In::Heartbeat(proto::GroupHeartbeat { timestamp: 7 }))
            .await;
        let mut before = Vec::new();
        loop {
            match self.next().await.expect("no stream error").response {
                Some(Out::HeartbeatAck(ack)) if ack.timestamp == 7 => return before,
                Some(other) => before.push(other),
                None => {}
            }
        }
    }
}

async fn add_member(db: &sqlx::PgPool, group_id: Uuid, device_id: &str, leaf_index: i32) {
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(group_id)
    .bind(device_id)
    .bind(leaf_index)
    .bind(Utc::now())
    .execute(db)
    .await
    .expect("add member");
}

async fn send_message(
    svc: &GroupServiceImpl,
    user_id: &Uuid,
    device_id: &str,
    group_id: Uuid,
) -> String {
    let mut request = Request::new(proto::SendGroupMessageRequest {
        group_id: group_id.to_string(),
        epoch: 0,
        mls_ciphertext: b"ciphertext".to_vec(),
        client_message_id: String::new(),
        thread_id: None,
        topic_id: None,
    });
    *request.metadata_mut() = create_metadata(user_id, device_id);
    svc.send_group_message(request)
        .await
        .expect("send")
        .into_inner()
        .message_id
}

fn message_ids(frames: &[Out]) -> Vec<String> {
    frames
        .iter()
        .filter_map(|f| match f {
            Out::Message(m) => Some(m.message_id.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn a_member_hears_a_message_another_member_sends() {
    let db = get_test_db().await;
    let svc = make_test_service(db.clone()).await;
    let (sender_user, sender_device, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &sender_device).await;
    let (_, member_device, _) = create_test_device(&db).await;
    add_member(&db, group_id, &member_device, 1).await;

    let mut member = Client::open(db.clone(), svc.hub.clone(), &member_device);
    member.subscribe(group_id).await;
    assert!(member.until_heartbeat_ack().await.is_empty());

    let message_id = send_message(&svc, &sender_user, &sender_device, group_id).await;

    match member.next().await.expect("no stream error").response {
        Some(Out::Message(m)) => {
            assert_eq!(m.message_id, message_id);
            assert_eq!(m.group_id, group_id.to_string());
            assert_eq!(m.mls_ciphertext, b"ciphertext");
        }
        other => panic!("expected the message, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn a_device_outside_the_group_is_refused_and_hears_nothing() {
    let db = get_test_db().await;
    let svc = make_test_service(db.clone()).await;
    let (sender_user, sender_device, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &sender_device).await;
    let (_, outsider_device, _) = create_test_device(&db).await;

    let mut outsider = Client::open(db.clone(), svc.hub.clone(), &outsider_device);
    outsider.subscribe(group_id).await;
    match outsider.until_heartbeat_ack().await.as_slice() {
        [Out::Error(e)] => {
            assert_eq!(e.error_code, proto::GroupErrorCode::NotMember as i32);
            assert_eq!(e.request_id, "r1");
        }
        other => panic!("expected one NOT_MEMBER error, got {other:?}"),
    }

    let mut sender = Client::open(db.clone(), svc.hub.clone(), &sender_device);
    sender.subscribe(group_id).await;
    assert!(sender.until_heartbeat_ack().await.is_empty());

    let message_id = send_message(&svc, &sender_user, &sender_device, group_id).await;

    // The member's stream carries it, so it was published; the outsider's does not.
    assert_eq!(
        message_ids(&sender.until_heartbeat_ack().await),
        [message_id]
    );
    assert!(outsider.until_heartbeat_ack().await.is_empty());
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn a_device_that_left_hears_nothing_more() {
    let db = get_test_db().await;
    let svc = make_test_service(db.clone()).await;
    let (sender_user, sender_device, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &sender_device).await;
    let (leaver_user, leaver_device, _) = create_test_device(&db).await;
    add_member(&db, group_id, &leaver_device, 1).await;

    let mut leaver = Client::open(db.clone(), svc.hub.clone(), &leaver_device);
    leaver.subscribe(group_id).await;
    assert!(leaver.until_heartbeat_ack().await.is_empty());

    let first = send_message(&svc, &sender_user, &sender_device, group_id).await;
    assert_eq!(message_ids(&leaver.until_heartbeat_ack().await), [first]);

    let mut leave = Request::new(proto::LeaveGroupRequest {
        group_id: group_id.to_string(),
        mls_remove_proposal: vec![1, 2, 3],
    });
    *leave.metadata_mut() = create_metadata(&leaver_user, &leaver_device);
    svc.leave_group(leave).await.expect("leave");

    send_message(&svc, &sender_user, &sender_device, group_id).await;

    assert!(leaver.until_heartbeat_ack().await.is_empty());
    // The heartbeat may be answered before the hub events are drained; give them a turn.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(leaver.down.try_recv().is_err());
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn a_stream_that_falls_behind_is_closed_not_left_with_a_gap() {
    let db = get_test_db().await;
    let hub = GroupHub::with_capacity(2);
    let (_, device, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device).await;

    let mut client = Client::open(db.clone(), hub.clone(), &device);
    client.subscribe(group_id).await;
    assert!(client.until_heartbeat_ack().await.is_empty());

    // Current-thread runtime: the stream task does not run until this test awaits.
    for _ in 0..5 {
        hub.publish(
            group_id,
            proto::GroupStreamResponse {
                response: None,
                response_id: None,
            },
        );
    }

    let status = client.next().await.expect_err("the lag closes the stream");
    assert_eq!(status.code(), tonic::Code::DataLoss);
    assert!(client.down.recv().await.is_none());
}
