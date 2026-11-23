//! Opt-in profile of the group hub fan-out: production `serve_message_stream`, PostgreSQL
//! membership checks, several readers and some that never read. Run alone, in a fresh process.
use super::{
    group_send_profile::{allocations::AllocationSample, process_cpu_seconds},
    postgres::Database,
    test_helpers::{create_test_device, create_test_group_in_db},
};
use crate::{handlers::messaging::serve_message_stream, service::GroupHub};
use anyhow::{Context, Result, ensure};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, group_stream_request::Request as In, group_stream_response::Response as Out,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use uuid::Uuid;

const OUTBOUND: usize = 512; // message_stream's own channel
const FRAMES: usize = 128; // below the hub's ring (256): no reader is closed for lagging

struct Reader {
    down: mpsc::Receiver<Result<proto::GroupStreamResponse, Status>>,
    // Keeps the inbound half open.
    _up: mpsc::Sender<Result<proto::GroupStreamRequest, Status>>,
}

impl Reader {
    async fn open(db: Arc<sqlx::PgPool>, hub: Arc<GroupHub>, device: String, group: Uuid) -> Self {
        let (up, up_rx) = mpsc::channel(4);
        let (tx, mut down) = mpsc::channel(OUTBOUND);
        tokio::spawn(serve_message_stream(
            db,
            hub,
            device,
            ReceiverStream::new(up_rx),
            tx,
        ));
        for request in [
            In::Subscribe(proto::GroupSubscribeRequest {
                group_ids: vec![group.to_string()],
            }),
            // Its answer says the subscription above is in place.
            In::Heartbeat(proto::GroupHeartbeat { timestamp: 1 }),
        ] {
            up.send(Ok(proto::GroupStreamRequest {
                request: Some(request),
                request_id: "r".into(),
            }))
            .await
            .expect("stream is open");
        }
        match down.recv().await.expect("an answer").expect("no error") {
            proto::GroupStreamResponse {
                response: Some(Out::HeartbeatAck(_)),
                ..
            } => {}
            other => panic!("expected the heartbeat answer, got {other:?}"),
        }
        Self { down, _up: up }
    }

    async fn message(&mut self) -> Result<proto::GroupMessageEnvelope> {
        match tokio::time::timeout(Duration::from_secs(10), self.down.recv())
            .await
            .context("frame deadline")?
            .context("stream closed")??
            .response
        {
            Some(Out::Message(m)) => Ok(m),
            other => anyhow::bail!("expected a message, got {other:?}"),
        }
    }
}

/// Without a comparison buffer: the sample must hold only what the fan-out allocates.
fn exact(m: &proto::GroupMessageEnvelope, n: usize, size: usize) -> bool {
    m.mls_ciphertext.len() == size && m.mls_ciphertext.iter().all(|&b| b == n as u8)
}

fn frame(n: usize, size: usize) -> proto::GroupStreamResponse {
    proto::GroupStreamResponse {
        response: Some(Out::Message(proto::GroupMessageEnvelope {
            message_id: format!("m{n}"),
            sequence_number: n as u64,
            mls_ciphertext: vec![n as u8; size],
            ..Default::default()
        })),
        response_id: None,
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a local disposable PostgreSQL, run alone"]
async fn profile_local_group_fanout() -> Result<()> {
    let db = Database::new(&sqlx::migrate!("../shared/migrations")).await;
    let pool = Arc::new(db.pool.clone());
    for size in [1024, 65_536] {
        for (fast, slow) in [(1, 0), (4, 0), (16, 0), (4, 1), (4, 4)] {
            let (_, owner, _) = create_test_device(&pool).await;
            let group = create_test_group_in_db(&pool, &owner).await;
            let hub = GroupHub::new();
            let mut readers = Vec::new();
            for i in 0..fast + slow {
                let (_, device, _) = create_test_device(&pool).await;
                sqlx::query("INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, $3, now())")
                    .bind(group)
                    .bind(&device)
                    .bind(i as i32 + 1)
                    .execute(&*pool)
                    .await?;
                readers.push(Reader::open(pool.clone(), hub.clone(), device, group).await);
            }
            let mut lagging = readers.split_off(fast);

            // Outside the sample: the published payloads. Inside: what the fan-out adds.
            let frames: Vec<_> = (0..FRAMES).map(|n| frame(n, size)).collect();
            let cpu = process_cpu_seconds()?;
            let sample = AllocationSample::start();
            let before = AllocationSample::live_bytes();
            for (n, f) in frames.into_iter().enumerate() {
                hub.publish(group, f);
                for r in &mut readers {
                    let m = r.message().await?;
                    ensure!(m.message_id == format!("m{n}"), "order");
                    ensure!(exact(&m, n, size), "bytes");
                }
            }
            // Every lagging stream has moved its copies from the ring to its own queue.
            for r in &lagging {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while r.down.len() < FRAMES {
                    ensure!(
                        std::time::Instant::now() < deadline,
                        "lagging stream stalled"
                    );
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            let cpu = process_cpu_seconds()? - cpu;
            let delta = sample.finish();
            let published = FRAMES * size;
            // `before` still counts the payloads that were built outside the sample.
            let held = delta.live as i64 - (before - published) as i64;
            let sends = FRAMES * (fast + slow);
            println!(
                "fanout: bytes={size} fast={fast} slow={slow} cpu_us/delivery={:.1} requested/delivery={:.0} allocs/delivery={:.1} held_after={held} ({:.2} x published)",
                cpu * 1e6 / sends as f64,
                delta.bytes as f64 / sends as f64,
                delta.calls as f64 / sends as f64,
                held as f64 / published as f64,
            );
            // At 64 KiB the payload dominates: one copy per delivery, and nothing kept but the
            // lagging readers' own queues. The bookkeeping margin is 16 KiB per delivery.
            if size == 65_536 {
                ensure!(
                    delta.bytes / sends <= size + 16_384,
                    "more than one copy per delivery"
                );
                let kept = held as f64 / published as f64;
                ensure!((kept - slow as f64).abs() < 0.1, "{kept} x published kept");
            }
            // A lagging reader still gets every byte, in order.
            for r in &mut lagging {
                for n in 0..FRAMES {
                    let m = r.message().await?;
                    ensure!(m.sequence_number == n as u64 && exact(&m, n, size));
                }
            }
        }
    }
    db.cleanup().await;
    Ok(())
}
