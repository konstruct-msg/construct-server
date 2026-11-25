//! Allocation/CPU probe of the real queue and logging helpers, not an RPC or group benchmark.
//! See `examples/README.md`. Run in a fresh process per mode for meaningful OS peak RSS.

use std::{
    hint::black_box,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use construct_config::{Config, SecretNeeds};
use construct_message::MessageEnvelope;
use construct_queue::{MailboxCursor, MessageDedupKey, MessageQueue};
use construct_utils::log_safe_id;

#[path = "../../shared/test_support/allocations.rs"]
mod allocations;
use allocations::{AllocationDelta, AllocationSample};

struct Sample {
    started: Instant,
    allocation_sample: AllocationSample,
}

impl Sample {
    fn start() -> Self {
        Self {
            started: Instant::now(),
            allocation_sample: AllocationSample::start(),
        }
    }

    fn finish(self, label: &str, operations: usize) -> usize {
        let elapsed = self.started.elapsed();
        let AllocationDelta {
            calls: allocations,
            bytes,
            live,
            peak,
            peak_delta,
        } = self.allocation_sample.finish();
        // A guard for this synthetic fixture, NOT a production capacity or rate-limit setting.
        assert!(
            peak < 64 * 1024 * 1024,
            "profile exceeded its 64 MiB Rust-heap budget"
        );
        println!(
            "{label}: operations={operations} us/op={:.3} allocs/op={:.2} requested_bytes/op={:.1} live_heap={} peak_heap={} peak_delta={}",
            elapsed.as_secs_f64() * 1e6 / operations as f64,
            allocations as f64 / operations as f64,
            bytes as f64 / operations as f64,
            live,
            peak,
            peak_delta
        );
        allocations
    }
}

fn profile_clones(queue: &MessageQueue, check: bool) {
    for count in [100, 1000, 5000] {
        let sample = Sample::start();
        let mut clones = Vec::with_capacity(count);
        for _ in 0..count {
            clones.push(black_box(queue.clone()));
        }
        let allocations = sample.finish("held queue clones", count);
        if check {
            assert_eq!(
                allocations, 1,
                "only the holder Vec may allocate; individual queue clones must not"
            );
        }
        black_box(clones);
    }
}

fn profile_hashes(check: bool) {
    let sample = Sample::start();
    for _ in 0..100_000 {
        black_box(log_safe_id(
            black_box("profile-account-id"),
            "profile-only-salt",
        ));
    }
    let allocations = sample.finish("log ID", 100_000);
    if check {
        assert_eq!(
            allocations, 100_000,
            "hash encoding must allocate only the output String"
        );
    }
}

fn profile_cursor(check: bool) {
    let cursor: MailboxCursor = "1763000000000-9".parse().expect("fixture cursor");
    let sample = Sample::start();
    for _ in 0..100_000 {
        black_box(black_box(cursor).encode());
    }
    let allocations = sample.finish("mailbox cursor", 100_000);
    if check {
        assert_eq!(
            allocations, 100_000,
            "cursor encoding must allocate only the output String"
        );
    }
}

async fn profile_mailboxes(queue: &MessageQueue, namespace: &str) -> Result<()> {
    const WORKERS: usize = 4;
    const SENDS: usize = 128;
    for device_count in [1, 3, 32] {
        let recipients: Vec<_> = (0..WORKERS)
            .map(|w| format!("{namespace}:d{device_count}:w{w}"))
            .collect();
        let devices: Vec<_> = (0..device_count).map(|d| format!("device-{d}")).collect();
        let sample = Sample::start();
        // Exactly four workers on one current-thread runtime: never one task per recipient.
        // This probes MessageQueue directly; it does not model auth/SQL/crypto, APNs or the
        // dispatch mutex, and 32 devices is a stress fixture, not a group implementation.
        let mut jobs = tokio::task::JoinSet::new();
        for recipient in &recipients {
            let (mut queue, recipient, devices) =
                (queue.clone(), recipient.clone(), devices.clone());
            jobs.spawn(async move {
                for n in 0..SENDS {
                    let message = MessageEnvelope::new_direct_message(
                        format!("message-{n}"),
                        "profile-sender".into(),
                        recipient.clone(),
                        vec![0; 32],
                        0,
                        vec![255; 1024],
                        String::new(),
                    );
                    let key = MessageDedupKey::new(
                        "profile-sender",
                        &recipient,
                        None,
                        &message.message_id,
                    );
                    let writes = queue
                        .write_message_to_device_streams(&recipient, &devices, &message)
                        .await?;
                    ensure!(
                        writes.user_stream == Some(true) && writes.device_streams == devices.len(),
                        "fan-out was incomplete"
                    );
                    queue.mark_message_dispatched(&key).await?;
                }
                Ok::<_, anyhow::Error>(())
            });
        }
        while let Some(done) = jobs.join_next().await {
            done??;
        }
        sample.finish(
            &format!("mailbox send, devices={device_count}"),
            WORKERS * SENDS,
        );

        // Prove the effect, outside the timed region: every addressed stream holds every send,
        // the real reader decodes all bytes, and cleanup is checked rather than assumed.
        let mut reader = queue.clone();
        let mut conn = queue.clone_redis_connection();
        for recipient in &recipients {
            for device in &devices {
                let key = format!("{namespace}:offline:{recipient}:{device}");
                let len: usize = redis::cmd("XLEN").arg(&key).query_async(&mut conn).await?;
                ensure!(len == SENDS, "mailbox length {len} != {SENDS}");
            }
            let page = reader
                .read_mailbox_messages(recipient, Some(&devices[0]), None, None, SENDS + 1)
                .await?;
            ensure!(
                page.entries.len() == SENDS && page.user_only() == 0 && !page.has_more,
                "reader lost or added entries"
            );
            for (_, envelope) in page.entries {
                let envelope =
                    envelope.ok_or_else(|| anyhow::anyhow!("unreadable profile envelope"))?;
                ensure!(
                    envelope.encrypted_payload == vec![255; 1024],
                    "payload changed"
                );
            }
            let removed = reader.delete_mailbox(recipient).await?;
            ensure!(
                removed == (device_count + 1) as u64,
                "mailbox cleanup incomplete"
            );
            let mut deleted_keys = vec![format!("{namespace}:offline:{recipient}")];
            deleted_keys.extend(
                devices
                    .iter()
                    .map(|d| format!("{namespace}:offline:{recipient}:{d}")),
            );
            let left: usize = redis::cmd("EXISTS")
                .arg(&deleted_keys)
                .query_async(&mut conn)
                .await?;
            ensure!(left == 0, "deleted mailbox keys still exist");
            for n in 0..SENDS {
                let key = MessageDedupKey::new(
                    "profile-sender",
                    recipient,
                    None,
                    &format!("message-{n}"),
                );
                reader.delete(key.as_str()).await?;
                let exists: bool = redis::cmd("EXISTS")
                    .arg(key.as_str())
                    .query_async(&mut conn)
                    .await?;
                ensure!(!exists, "dedup cleanup failed");
            }
            let remaining = reader
                .read_mailbox_messages(recipient, Some(&devices[0]), None, None, 1)
                .await?;
            ensure!(
                remaining.entries.is_empty(),
                "deleted mailbox still readable"
            );
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ensure!(
        std::env::var("PROFILE_LOCAL_REDIS").as_deref() == Ok("1"),
        "set PROFILE_LOCAL_REDIS=1 and use an isolated test Redis; never production"
    );
    let mode = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    let tail: Vec<_> = std::env::args().skip(2).collect();
    ensure!(
        tail.is_empty() || tail == ["--check"],
        "optional second argument: --check"
    );
    let check = !tail.is_empty();
    ensure!(
        ["all", "clone", "hash", "cursor", "mailbox"].contains(&mode.as_str()),
        "mode: all|clone|hash|cursor|mailbox"
    );
    if mode == "all" || mode == "hash" {
        profile_hashes(check);
    }
    if mode == "all" || mode == "cursor" {
        profile_cursor(check);
    }
    if mode == "hash" || mode == "cursor" {
        return Ok(());
    }
    let mut config = Config::from_env_for(SecretNeeds::MESSAGING)?;
    let namespace = format!(
        "profile:p6:{}:{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    config.delivery_queue_prefix = namespace.clone();
    config.messaging.mailbox_user_write = true;
    config.messaging.queue_maxlen_standard = 10_000;
    let queue = MessageQueue::new(&config).await?;
    if mode == "all" || mode == "clone" {
        profile_clones(&queue, check);
    }
    if mode == "all" || mode == "mailbox" {
        profile_mailboxes(&queue, &namespace).await?;
    }
    Ok(())
}
