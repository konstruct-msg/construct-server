//! Opt-in profile of SendGroupMessage through PostgreSQL, Redis, and the live hub.
use super::{
    postgres::Database,
    test_helpers::{TEST_AUTH, create_metadata, create_test_device, create_test_group_in_db},
};
use crate::service::{GroupHub, GroupServiceImpl, HubEvent};
use anyhow::{Context, Result, ensure};
use construct_db::mls::list_group_messages;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};
use std::{sync::Arc, time::Instant};
use tonic::{Request, metadata::MetadataMap};
use uuid::Uuid;

#[path = "../../../shared/test_support/allocations.rs"]
pub(super) mod allocations;

pub(super) fn process_cpu_seconds() -> Result<f64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid writable timespec for the duration of the call.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read process CPU time");
    }
    Ok(ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9)
}

fn request(
    group: Uuid,
    meta: &MetadataMap,
    id: String,
    payload: Vec<u8>,
) -> Request<proto::SendGroupMessageRequest> {
    let mut request = Request::new(proto::SendGroupMessageRequest {
        group_id: group.to_string(),
        epoch: 0,
        mls_ciphertext: payload,
        client_message_id: id,
        thread_id: None,
        topic_id: None,
    });
    *request.metadata_mut() = meta.clone();
    request
}

fn next_frame(
    rx: &mut tokio::sync::broadcast::Receiver<HubEvent>,
) -> Result<proto::GroupMessageEnvelope> {
    match rx
        .try_recv()
        .context("send must publish before returning")?
    {
        HubEvent::Frame(proto::GroupStreamResponse {
            response: Some(proto::group_stream_response::Response::Message(message)),
            response_id: None,
        }) => Ok(message),
        _ => anyhow::bail!("expected a message frame"),
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires local disposable Redis and PostgreSQL, run alone"]
async fn profile_local_mls_send() -> Result<()> {
    let local = |host: &str| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    };
    let pg: sqlx::postgres::PgConnectOptions = std::env::var("DATABASE_URL")
        .context("DATABASE_URL required")?
        .parse()?;
    ensure!(local(pg.get_host()), "PostgreSQL must be loopback");
    let redis_url = std::env::var("REDIS_URL").context("REDIS_URL required")?;
    let client = redis::Client::open(redis_url.as_str())?;
    ensure!(
        matches!(client.get_connection_info().addr(), redis::ConnectionAddr::Tcp(host, _) if local(host)),
        "Redis must be loopback TCP"
    );
    let mut conn = construct_redis::connect_manager(&redis_url).await?;
    let db = Database::new(&sqlx::migrate!("../shared/migrations")).await;
    let svc = GroupServiceImpl {
        db: Arc::new(db.pool.clone()),
        hub: GroupHub::new(),
        notification_client: None,
        redis: conn.clone(),
        auth: TEST_AUTH.clone(),
    };
    let (user, device, _) = create_test_device(&db.pool).await;
    let group = create_test_group_in_db(&db.pool, &device).await;
    let meta = create_metadata(&user, &device);
    let mut rx = svc.hub.subscribe(group);
    let mut seq = 0;
    for (round, count) in [(0, 8), (1, 32), (2, 32), (3, 32)] {
        for size in [1024, 65_536] {
            let expected: Vec<Vec<u8>> = (0..count).map(|i| vec![0x80 | i as u8; size]).collect();
            let requests: Vec<_> = expected
                .iter()
                .enumerate()
                .map(|(i, payload)| {
                    request(
                        group,
                        &meta,
                        format!("profile-{size}-{round}-{i}"),
                        payload.clone(),
                    )
                })
                .collect();
            let mut replies = Vec::with_capacity(count);
            let cpu = process_cpu_seconds()?;
            let wall = Instant::now();
            let sample = allocations::AllocationSample::start();
            for request in requests {
                replies.push(svc.send_group_message(request).await?.into_inner());
            }
            let delta = sample.finish();
            let wall = wall.elapsed().as_secs_f64();
            let cpu = process_cpu_seconds()? - cpu;
            ensure!(
                delta.calls > 0 && delta.bytes > 0 && delta.peak >= delta.live,
                "allocator did not capture the sample"
            );

            let rows =
                list_group_messages(&db.pool, group, Some(seq), count as i64 + 1, None).await?;
            assert_eq!(rows.len(), count, "stored batch size");
            for ((reply, row), payload) in replies.iter().zip(rows).zip(expected) {
                seq += 1;
                assert_eq!(row.sequence_number, seq);
                assert_eq!(row.mls_ciphertext, payload, "stored ciphertext");
                assert_eq!(row.group_id, group);
                assert_eq!(row.epoch, 0);
                assert_eq!(reply.message_id, row.message_id.to_string());
                assert_eq!(reply.sequence_number, seq as u64);
                assert_eq!(reply.sent_at, row.sent_at.timestamp());
                assert_eq!(reply.expires_at, row.expires_at.timestamp());
                let frame = next_frame(&mut rx)?;
                assert_eq!(frame.mls_ciphertext, payload, "published ciphertext");
                assert_eq!(frame.message_id, reply.message_id);
                assert_eq!(frame.group_id, group.to_string());
                assert_eq!(frame.epoch, 0);
                assert_eq!(frame.sequence_number, reply.sequence_number);
                assert_eq!(frame.sent_at, reply.sent_at);
                assert_eq!(frame.expires_at, reply.expires_at);
                assert_eq!((frame.thread_id, frame.topic_id), (None, None));
            }
            assert!(matches!(
                rx.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ));
            if round != 0 {
                let n = count as f64;
                println!(
                    "mls_send: round={round} bytes={size} ops={count} allocations/op={:.3} requested_bytes/op={:.1} cpu_us/op={:.1} wall_us/op={:.1} peak_delta={}",
                    delta.calls as f64 / n,
                    delta.bytes as f64 / n,
                    cpu * 1e6 / n,
                    wall * 1e6 / n,
                    delta.peak_delta
                );
            }
        }
    }

    // A repeat returns and republishes the original row, rather than replacing its bytes.
    let payload = vec![0xfe, 0, 0xff];
    let initial = svc
        .send_group_message(request(group, &meta, "retry".into(), payload.clone()))
        .await?
        .into_inner();
    assert_eq!(next_frame(&mut rx)?.mls_ciphertext, payload);
    let repeat = svc
        .send_group_message(request(group, &meta, "retry".into(), vec![0x81]))
        .await?
        .into_inner();
    assert_eq!(repeat, initial);
    let frame = next_frame(&mut rx)?;
    assert_eq!(frame.message_id, initial.message_id);
    assert_eq!(frame.mls_ciphertext, payload);
    let rows = list_group_messages(&db.pool, group, Some(seq), 2, None).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].mls_ciphertext, payload);

    let removed: usize = redis::cmd("DEL")
        .arg(format!("rl:group_msg:{user}"))
        .query_async(&mut conn)
        .await?;
    assert_eq!(removed, 1, "request used the per-account rate bucket");
    db.cleanup().await;
    Ok(())
}
