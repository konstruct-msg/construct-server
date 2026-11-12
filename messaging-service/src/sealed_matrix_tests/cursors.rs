//! Actual gRPC readers: unary paging and reconnect through MessageStream's bearer + Subscribe
//! path. No duplicate dispatcher/merger, no client-side interpretation of the resume token.

use super::*;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, messaging_service_client::MessagingServiceClient,
    messaging_service_server::MessagingServiceServer,
};
use std::time::Duration;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

struct RpcStand {
    client: MessagingServiceClient<tonic::transport::Channel>,
    server: tokio::task::JoinHandle<()>,
}

impl RpcStand {
    async fn start(h: &TestHarness) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = crate::grpc::MessagingGrpcService {
            context: h.ctx.clone(),
        };
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(MessagingServiceServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = MessagingServiceClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        Self { client, server }
    }
}

impl Drop for RpcStand {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct Fixture {
    user: uuid::Uuid,
    user_key: String,
    device_key: String,
    token: String,
    legacy_token: String,
}

impl Fixture {
    async fn new(h: &TestHarness) -> Self {
        let user = uuid::Uuid::new_v4();
        let device = random_device();
        let user_key = format!("delivery:offline:{user}");
        let device_key = format!("{user_key}:{device}");
        let (token, _, _) = h
            .ctx
            .auth_manager
            .create_token_for_device(&user, Some(&device))
            .unwrap();
        let (legacy_token, _, _) = h.ctx.auth_manager.create_token(&user).unwrap();
        let fixture = Self {
            user,
            user_key,
            device_key,
            token,
            legacy_token,
        };
        // Different envelopes with exactly equal Redis IDs at both possible cut points.
        for (device, id, message) in [
            (true, "100-0", "first"),
            (true, "200-0", "device-peer"),
            (true, "300-0", "device-late"),
            (false, "200-0", "user-peer"),
            (false, "300-0", "user-late"),
        ] {
            fixture.insert(h, device, id, message).await;
        }
        fixture
    }

    async fn insert(&self, h: &TestHarness, device: bool, id: &str, message: &str) {
        let payload = [vec![0, 255, 128], message.as_bytes().to_vec()].concat();
        let envelope = construct_message::MessageEnvelope::new_direct_message(
            message.into(),
            "alice".into(),
            self.user.to_string(),
            vec![0; 32],
            0,
            payload,
            String::new(),
        );
        let mut conn = h.ctx.redis_conn.clone();
        let inserted: String = redis::cmd("XADD")
            .arg(if device {
                &self.device_key
            } else {
                &self.user_key
            })
            .arg(id)
            .arg("message_id")
            .arg(message)
            .arg("payload")
            .arg(rmp_serde::encode::to_vec_named(&envelope).unwrap())
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(inserted, id);
    }

    async fn clear(&self, h: &TestHarness) {
        let mut conn = h.ctx.redis_conn.clone();
        del(
            &mut conn,
            &[
                self.user_key.clone(),
                self.device_key.clone(),
                format!("user:{}:server_instance_id", self.user),
            ],
        )
        .await;
    }

    async fn unchanged(&self, h: &TestHarness) {
        let mut conn = h.ctx.redis_conn.clone();
        for (key, expected) in [(&self.device_key, 3_i64), (&self.user_key, 2_i64)] {
            let n: i64 = redis::cmd("XLEN")
                .arg(key)
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(n, expected, "reading/reconnect must not trim a mailbox");
        }
    }
}

fn authorized<T>(body: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

async fn pending(
    stand: &mut RpcStand,
    token: &str,
    cursor: Option<String>,
    limit: i32,
) -> proto::GetPendingMessagesResponse {
    tokio::time::timeout(
        Duration::from_secs(5),
        stand.client.get_pending_messages(authorized(
            proto::GetPendingMessagesRequest {
                since_cursor: cursor,
                limit: Some(limit),
            },
            token,
        )),
    )
    .await
    .expect("pending RPC stalled")
    .unwrap()
    .into_inner()
}

fn verify_payload(id: &str, bytes: &[u8]) {
    assert_eq!(bytes, [vec![0, 255, 128], id.as_bytes().to_vec()].concat());
}

#[tokio::test]
#[serial]
async fn cursor_rpc_strict_pages_deliver_equal_id_peers_and_legacy_reads() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let fixture = Fixture::new(&h).await;
    let mut stand = RpcStand::start(&h).await;
    for (token, expected) in [
        (
            &fixture.token,
            vec![
                "device-late",
                "device-peer",
                "first",
                "user-late",
                "user-peer",
            ],
        ),
        (&fixture.legacy_token, vec!["user-late", "user-peer"]),
    ] {
        let zero = pending(&mut stand, token, None, 0).await;
        assert!(
            zero.messages.is_empty(),
            "Redis COUNT 0 must not become an unbounded fetch"
        );
        assert!(zero.has_more, "zero did not consume the queued messages");
        assert_eq!(
            zero.next_cursor,
            construct_queue::MailboxCursor::default().to_string()
        );
        for limit in [1, 2] {
            // A legacy stored bookmark is accepted, then the client only echoes opaque strings.
            let mut cursor = "0-0".to_string();
            let mut received = Vec::new();
            let mut complete = false;
            for _ in 0..16 {
                let page = pending(&mut stand, token, Some(cursor.clone()), limit).await;
                assert!(
                    page.messages.len() <= limit as usize,
                    "maximum is not a soft target"
                );
                assert!(page.gap.is_none());
                for message in page.messages {
                    verify_payload(&message.message_id, &message.encrypted_payload);
                    received.push(message.message_id);
                }
                if !page.has_more {
                    complete = true;
                    break;
                }
                assert_ne!(page.next_cursor, cursor, "paging stalled");
                cursor = page.next_cursor;
            }
            assert!(complete);
            received.sort();
            received.dedup();
            assert_eq!(received, expected, "limit={limit}");
        }
    }
    // Modern malformed/unsupported cursors must be an explicit error, not a hidden rewind.
    for cursor in ["mc1:bad", "mc2:unsupported"] {
        let error = stand
            .client
            .get_pending_messages(authorized(
                proto::GetPendingMessagesRequest {
                    since_cursor: Some(cursor.into()),
                    limit: Some(1),
                },
                &fixture.token,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        let (commands, mut stream) =
            open_stream(&mut stand, &fixture.token, Some(cursor.into())).await;
        let status = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match stream.message().await {
                    Err(status) => break status,
                    Ok(Some(frame))
                        if matches!(
                            frame.response,
                            Some(proto::message_stream_response::Response::HeartbeatAck(_))
                        ) =>
                    {
                        continue;
                    }
                    other => panic!("bad Subscribe must fail before any delivery, got {other:?}"),
                }
            }
        })
        .await
        .expect("malformed Subscribe did not fail");
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "same refusal on both carriers"
        );
        drop(commands);
    }
    let error = stand
        .client
        .get_pending_messages(authorized(
            proto::GetPendingMessagesRequest {
                since_cursor: None,
                limit: Some(-1),
            },
            &fixture.token,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    let error = stand
        .client
        .get_pending_messages(tonic::Request::new(proto::GetPendingMessagesRequest {
            since_cursor: Some("mc1:bad".into()),
            limit: Some(1),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        tonic::Code::Unauthenticated,
        "auth precedes cursor parsing"
    );
    fixture.unchanged(&h).await;
    fixture.clear(&h).await;
}

async fn open_stream(
    stand: &mut RpcStand,
    token: &str,
    cursor: Option<String>,
) -> (
    tokio::sync::mpsc::Sender<proto::MessageStreamRequest>,
    tonic::Streaming<proto::MessageStreamResponse>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(proto::MessageStreamRequest {
        request: Some(proto::message_stream_request::Request::Subscribe(
            proto::SubscribeRequest {
                since_cursor: cursor,
                ..Default::default()
            },
        )),
        ..Default::default()
    })
    .await
    .unwrap();
    let stream = stand
        .client
        .message_stream(authorized(ReceiverStream::new(rx), token))
        .await
        .unwrap()
        .into_inner();
    (tx, stream)
}

async fn next_message(
    stream: &mut tonic::Streaming<proto::MessageStreamResponse>,
) -> (String, String) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = stream
                .message()
                .await
                .unwrap()
                .expect("stream ended before backlog drained");
            if let Some(proto::message_stream_response::Response::Message(env)) = frame.response {
                let Some(core_proto::envelope::MessageIdType::MessageId(id)) = env.message_id_type
                else {
                    panic!("message id missing");
                };
                verify_payload(&id, &env.encrypted_payload);
                return (
                    id,
                    frame
                        .stream_cursor
                        .expect("frame must carry a reconnect checkpoint"),
                );
            }
        }
    })
    .await
    .expect("message stream stalled")
}

#[tokio::test]
#[serial]
async fn cursor_rpc_reconnect_after_every_frame_does_not_commit_the_rest_of_the_page() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let fixture = Fixture::new(&h).await;
    let mut stand = RpcStand::start(&h).await;
    let expected = [
        "device-late",
        "device-peer",
        "first",
        "user-late",
        "user-peer",
    ];
    // In particular, cuts 2 and 4 fall BETWEEN distinct messages at one Redis ID.
    for cut in 1..5 {
        let (commands, mut stream) =
            open_stream(&mut stand, &fixture.token, Some("0-0".into())).await;
        let mut received = Vec::new();
        let mut committed = String::new();
        for _ in 0..cut {
            let (id, checkpoint) = next_message(&mut stream).await;
            received.push(id);
            committed = checkpoint; // Fake client's durable FIFO completion, not server queue state.
        }
        drop(stream);
        drop(commands);
        let (commands, mut resumed) =
            open_stream(&mut stand, &fixture.token, Some(committed)).await;
        for _ in cut..5 {
            let (id, _) = next_message(&mut resumed).await;
            received.push(id);
        }
        drop(resumed);
        drop(commands);
        received.sort();
        assert_eq!(received, expected, "disconnect after frame {cut}");
    }
    fixture.unchanged(&h).await;
    fixture.clear(&h).await;
}

#[tokio::test]
#[serial]
async fn cursor_rpc_gap_uses_the_offset_of_the_source_that_actually_lost_data() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let mut stand = RpcStand::start(&h).await;
    for lost_device in [false, true] {
        let fixture = Fixture::new(&h).await;
        let mut conn = h.ctx.redis_conn.clone();
        let removed: i64 = redis::cmd("XDEL")
            .arg(if lost_device {
                &fixture.device_key
            } else {
                &fixture.user_key
            })
            .arg("100-0")
            .arg("200-0")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(removed, if lost_device { 2 } else { 1 });
        let cursor = if lost_device {
            "mc1:00000000000000000100-00000000000000000000:00000000000000000300-00000000000000000000"
        } else {
            "mc1:00000000000000000300-00000000000000000000:00000000000000000100-00000000000000000000"
        };
        let response = pending(&mut stand, &fixture.token, Some(cursor.into()), 10).await;
        assert_eq!(response.messages.len(), 1);
        let gap = response
            .gap
            .expect("the other source's later watermark must not hide this gap");
        // Existing core/iOS/Android gap readers consume numeric diagnostic intervals, not mc1.
        assert_eq!(gap.after_cursor, "100-0");
        assert_eq!(gap.resumes_at, "300-0");
        let (commands, mut stream) =
            open_stream(&mut stand, &fixture.token, Some(cursor.into())).await;
        let gap = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let frame = stream.message().await.unwrap().expect("gap stream ended");
                match frame.response {
                    Some(proto::message_stream_response::Response::HeartbeatAck(_)) => continue,
                    Some(proto::message_stream_response::Response::MailboxGap(g)) => break g,
                    other => panic!("gap must precede delivery, got {other:?}"),
                }
            }
        })
        .await
        .expect("gap event missing");
        assert_eq!(gap.after_cursor, "100-0");
        assert_eq!(gap.resumes_at, "300-0");
        drop(stream);
        drop(commands);
        // A lagging HEALTHY source must not invent a gap in the already-read damaged source.
        let caught_up = if lost_device {
            "mc1:00000000000000000300-00000000000000000000:00000000000000000100-00000000000000000000"
        } else {
            "mc1:00000000000000000100-00000000000000000000:00000000000000000300-00000000000000000000"
        };
        assert!(
            pending(&mut stand, &fixture.token, Some(caught_up.into()), 10)
                .await
                .gap
                .is_none()
        );
        fixture.clear(&h).await;
    }
}

#[tokio::test]
#[serial]
async fn cursor_rpc_tail_keeps_the_healthy_source_when_its_peer_is_missing_or_wrongtype() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let mut stand = RpcStand::start(&h).await;
    for bad_device in [false, true] {
        for wrongtype in [false, true] {
            let fixture = Fixture::new(&h).await;
            let bad_key = if bad_device {
                &fixture.device_key
            } else {
                &fixture.user_key
            };
            let mut conn = h.ctx.redis_conn.clone();
            if wrongtype {
                let _: () = redis::cmd("SET")
                    .arg(bad_key)
                    .arg("wrong type")
                    .query_async(&mut conn)
                    .await
                    .unwrap();
            } else {
                let _: i64 = redis::cmd("DEL")
                    .arg(bad_key)
                    .query_async(&mut conn)
                    .await
                    .unwrap();
            }
            let tail = pending(&mut stand, &fixture.token, Some("$".into()), 1).await;
            assert!(tail.messages.is_empty());
            assert!(!tail.has_more);
            fixture
                .insert(&h, !bad_device, "400-0", "healthy-after-tail")
                .await;
            let response = pending(&mut stand, &fixture.token, Some(tail.next_cursor), 1).await;
            assert_eq!(
                response.messages.len(),
                1,
                "bad_device={bad_device}, wrongtype={wrongtype}"
            );
            assert_eq!(response.messages[0].message_id, "healthy-after-tail");
            verify_payload(
                "healthy-after-tail",
                &response.messages[0].encrypted_payload,
            );
            fixture.clear(&h).await;
        }
    }
}

#[tokio::test]
#[serial]
async fn cursor_rpc_tail_is_resolved_once_even_when_all_old_entries_were_deleted() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let mut stand = RpcStand::start(&h).await;
    for delete_old in [false, true] {
        let fixture = Fixture::new(&h).await;
        if delete_old {
            let mut conn = h.ctx.redis_conn.clone();
            for key in [&fixture.user_key, &fixture.device_key] {
                let _: i64 = redis::cmd("XDEL")
                    .arg(key)
                    .arg("100-0")
                    .arg("200-0")
                    .arg("300-0")
                    .query_async(&mut conn)
                    .await
                    .unwrap();
            }
        }
        let tail = pending(&mut stand, &fixture.token, Some("$".into()), 1).await;
        assert!(tail.messages.is_empty());
        assert!(!tail.has_more);
        assert!(tail.gap.is_none());
        assert_eq!(
            tail.next_cursor,
            "mc1:00000000000000000300-00000000000000000000:00000000000000000300-00000000000000000000"
        );
        let (commands, mut live) = open_stream(&mut stand, &fixture.token, Some("$".into())).await;
        // FIFO heartbeat response is a processing barrier AFTER Subscribe, not a sleep or the
        // initial connection ack (which is sent before the tail snapshot has run).
        commands
            .send(proto::MessageStreamRequest {
                request_id: "tail-applied".into(),
                request: Some(proto::message_stream_request::Request::Heartbeat(
                    proto::Heartbeat { timestamp: 7 },
                )),
                ..Default::default()
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let frame = live.message().await.unwrap().expect("tail stream ended");
                assert!(
                    matches!(
                        frame.response,
                        Some(proto::message_stream_response::Response::HeartbeatAck(_))
                    ),
                    "old backlog or a spurious gap leaked before the processing barrier"
                );
                if frame.response_id.as_deref() == Some("tail-applied") {
                    break;
                }
            }
        })
        .await
        .expect("Subscribe processing barrier stalled");
        fixture.insert(&h, true, "400-0", "after-tail-device").await;
        fixture.insert(&h, false, "400-0", "after-tail-user").await;
        let _: i64 = redis::cmd("PUBLISH")
            .arg(format!("inbox:wakeup:{}", fixture.user))
            .arg("1")
            .query_async(&mut h.ctx.redis_conn.clone())
            .await
            .unwrap();
        let mut cursor = tail.next_cursor;
        let mut received = Vec::new();
        let mut finished = false;
        for _ in 0..8 {
            let page = pending(&mut stand, &fixture.token, Some(cursor), 1).await;
            assert!(page.messages.len() <= 1);
            assert!(
                page.gap.is_none(),
                "tail already passed the deleted entries"
            );
            received.extend(page.messages.into_iter().map(|e| e.message_id));
            if !page.has_more {
                finished = true;
                break;
            }
            cursor = page.next_cursor;
        }
        assert!(finished);
        received.sort();
        assert_eq!(received, ["after-tail-device", "after-tail-user"]);
        let mut streamed = vec![
            next_message(&mut live).await.0,
            next_message(&mut live).await.0,
        ];
        streamed.sort();
        assert_eq!(
            streamed,
            ["after-tail-device", "after-tail-user"],
            "Subscribe $ must not move its tail again"
        );
        drop(live);
        drop(commands);
        fixture.clear(&h).await;
    }
}
