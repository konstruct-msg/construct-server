//! Opt-in, isolated measurement of the production local sealed dispatch path.
use super::{
    account_with_two_devices, core_proto, dispatch_sealed_sender, issue_client_token, make_config,
    make_ed25519_pems, random_bytes32, seal_token_for_server,
};
use crate::{context::MessagingServiceContext, spent_tag::unmark_delivery_tag};
use anyhow::{Context, Result, ensure};
use construct_auth::AuthManager;
use construct_config::StealthTokenPolicy;
use construct_queue::MessageQueue;
use prost::Message;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::Mutex;
use x25519_dalek::StaticSecret;

#[path = "../../test_support/allocations.rs"]
mod allocations;
#[path = "../../../shared/test_support/postgres.rs"]
mod postgres;
use allocations::AllocationSample;

fn process_cpu_seconds() -> Result<f64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts points to a writable timespec that lives across the call.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read process CPU clock");
    }
    Ok(ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires local disposable Redis and PostgreSQL, run alone"]
async fn profile_local_sealed_dispatch() -> Result<()> {
    ensure!(
        std::env::var("PROFILE_LOCAL_REDIS").as_deref() == Ok("1"),
        "use local disposable services only"
    );
    let redis_url = std::env::var("REDIS_URL").context("REDIS_URL required")?;
    let db_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;
    let loopback = |host: &str| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    };
    let client = redis::Client::open(redis_url.as_str())?;
    ensure!(
        matches!(client.get_connection_info().addr(), redis::ConnectionAddr::Tcp(host, _) if loopback(host)),
        "Redis must be loopback TCP"
    );
    let pg: sqlx::postgres::PgConnectOptions = db_url.parse()?;
    ensure!(loopback(pg.get_host()), "PostgreSQL must be loopback");

    let db = postgres::Database::new(&sqlx::migrate!("../shared/migrations")).await;
    let (priv_pem, pub_pem) = make_ed25519_pems();
    let mut cfg = make_config(
        &redis_url,
        &db_url,
        &priv_pem,
        &pub_pem,
        StealthTokenPolicy::Enforce,
    );
    cfg.delivery_queue_prefix = format!("profile:sealed:{}", uuid::Uuid::new_v4());
    cfg.messaging.mailbox_user_write = true;
    let queue = MessageQueue::new(&cfg).await?;
    let mut conn = construct_redis::connect_manager(&redis_url).await?;
    let issuer = random_bytes32();
    let token_secret = StaticSecret::from(random_bytes32());
    let ctx = Arc::new(MessagingServiceContext {
        db_pool: Arc::new(db.pool.clone()),
        queue: Arc::new(Mutex::new(queue.clone())),
        auth_manager: Arc::new(AuthManager::new(&cfg)?),
        notification_context: None,
        sentinel: None,
        server_signer: None,
        server_instance_id: cfg.delivery_queue_prefix.clone(),
        config: Arc::new(cfg),
        redis_conn: conn.clone(),
        token_issuer_key: Some(issuer),
        token_enc_static_secret: Some(token_secret.clone()),
    });
    let (user, devices) = account_with_two_devices(&db.pool, &random_bytes32()).await;
    let recipient = user.to_string();
    let user_stream = format!("{}:offline:{recipient}", ctx.config.delivery_queue_prefix);
    let target_stream = format!("{user_stream}:{}", devices[0]);
    let sibling_stream = format!("{user_stream}:{}", devices[1]);

    for (round, count) in [(0, 8), (1, 48), (2, 48), (3, 48)] {
        for size in [1024, 65_536] {
            let mut requests = Vec::with_capacity(count);
            let expected_inputs = (0..count)
                .map(|i| {
                    let tag = random_bytes32();
                    let nonce = random_bytes32();
                    let token = issue_client_token(&issuer, &nonce);
                    let inner = core_proto::SealedInner {
                        recipient_user_id: recipient.clone(),
                        recipient_device: devices[0].clone(),
                        delivery_tag: tag.to_vec(),
                        sender_cert_ciphertext: vec![0x9a; 48],
                        encrypted_payload: vec![0x80 | i as u8; size],
                        token_nonce: nonce.to_vec(),
                        token_bytes: seal_token_for_server(&token, &token_secret),
                        ..Default::default()
                    };
                    let sealed = core_proto::SealedSenderEnvelope {
                        sealed_inner: inner.encode_to_vec(),
                        ..Default::default()
                    };
                    let expected_bytes = sealed.sealed_inner.clone();
                    requests.push(sealed);
                    (
                        expected_bytes,
                        tag,
                        format!("spent:{}", hex::encode(Sha256::digest(nonce))),
                    )
                })
                .collect::<Vec<_>>();
            let mut replies = Vec::with_capacity(count);
            let cpu = process_cpu_seconds()?;
            let wall = Instant::now();
            let sample = AllocationSample::start();
            for sealed in requests {
                replies.push(dispatch_sealed_sender(&ctx, &sealed).await?);
            }
            let delta = sample.finish();
            let wall = wall.elapsed().as_secs_f64();
            let cpu = process_cpu_seconds()? - cpu;

            let expected = replies
                .iter()
                .zip(&expected_inputs)
                .map(|(reply, (sealed_bytes, _, _))| {
                    ensure!(
                        reply.success && reply.error.is_none() && !reply.message_id.is_empty(),
                        "invalid send reply"
                    );
                    ensure!(
                        reply.recipient_active_devices == devices,
                        "active device directory changed"
                    );
                    Ok((reply.message_id.as_str(), sealed_bytes.as_slice()))
                })
                .collect::<Result<HashMap<_, _>>>()?;
            ensure!(expected.len() == count, "duplicate reply IDs");
            for (key, expected_len) in [
                (&user_stream, count),
                (&target_stream, count),
                (&sibling_stream, 0),
            ] {
                let len: usize = redis::cmd("XLEN").arg(key).query_async(&mut conn).await?;
                ensure!(
                    len == expected_len,
                    "unexpected stream length: {len} != {expected_len}"
                );
            }
            let mut reader = queue.clone();
            for device in [None, Some(devices[0].as_str())] {
                let page = reader
                    .read_mailbox_messages(&recipient, device, None, None, count + 1)
                    .await?;
                ensure!(
                    !page.has_more && page.entries.len() == count,
                    "incomplete mailbox"
                );
                let mut unseen = expected.clone();
                for (_, entry) in page.entries {
                    let env = entry.context("unreadable envelope")?;
                    ensure!(
                        env.is_sealed_sender
                            && env.sender_id.is_empty()
                            && env.encrypted_payload.is_empty(),
                        "sealed shape changed"
                    );
                    ensure!(
                        env.recipient_id == recipient
                            && env.recipient_device.as_deref() == Some(devices[0].as_str()),
                        "wrong destination"
                    );
                    ensure!(
                        unseen
                            .remove(env.message_id.as_str())
                            .is_some_and(|bytes| env.sealed_inner.as_deref() == Some(bytes)),
                        "wrong ID or sealed bytes"
                    );
                }
                ensure!(unseen.is_empty(), "missing message IDs");
            }
            let sibling = reader
                .read_mailbox_messages(&recipient, Some(&devices[1]), None, None, count + 1)
                .await?;
            ensure!(
                sibling.entries.iter().all(|(_, entry)| entry.is_none()),
                "sibling received ciphertext"
            );
            ensure!(
                reader.delete_mailbox(&recipient).await? == 2,
                "expected exactly user and target streams to be removed"
            );
            for (_, tag, spent) in &expected_inputs {
                let removed: usize = redis::cmd("DEL").arg(spent).query_async(&mut conn).await?;
                ensure!(removed == 1, "enforced send must spend a fresh token");
                unmark_delivery_tag(&mut conn, tag).await?;
            }
            ensure!(
                delta.calls > 0 && delta.bytes > 0,
                "allocator collected no sample"
            );
            ensure!(
                delta.peak_delta < 16 * 1024 * 1024,
                "sample exceeded its Rust heap guard"
            );
            if round != 0 {
                println!(
                    "sealed_dispatch: round={round} ciphertext_bytes={size} ops={count} cpu_us/op={:.1} wall_us/op={:.1} allocations/op={:.3} requested_bytes/op={:.1} live_heap={} peak_heap={} peak_delta={}",
                    cpu * 1e6 / count as f64,
                    wall * 1e6 / count as f64,
                    delta.calls as f64 / count as f64,
                    delta.bytes as f64 / count as f64,
                    delta.live,
                    delta.peak,
                    delta.peak_delta
                );
            }
        }
    }
    db.cleanup().await;
    Ok(())
}
