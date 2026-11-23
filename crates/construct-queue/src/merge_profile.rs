//! Opt-in heap/time profile of the production mailbox merge. Run alone, in a fresh process:
//! `cargo test --release -p construct-queue --lib --features allocation-profile
//! profile_mailbox_merge -- --ignored --nocapture`. Latency is reported, never asserted.
use super::*;
use construct_message::types::{MessageEnvelope, MessageType};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[path = "../../../shared/test_support/allocations.rs"]
#[allow(dead_code)] // `peak`/`live` are read by the other profiles that share this file.
mod allocations;
use allocations::AllocationSample;

const COUNT: usize = 50; // STREAM_MAILBOX_PAGE
const PER_SOURCE: usize = 2 * COUNT; // read_mailbox_messages oversamples each source
const READER: &str = "0123456789abcdef0123456789abcdef";
const SIBLING: &str = "fedcba9876543210fedcba9876543210";

/// The budgets were measured on arm64. hashbrown pads its control bytes by one SIMD group, whose
/// width is the platform's: 8 bytes there, 16 on x86_64.
const TABLE_GROUP: usize = 16;

type Rows = Vec<(String, Option<MessageEnvelope>)>;

struct Case {
    name: &'static str,
    device: Rows,
    user: Rows,
    /// Entries, user-only, sibling skips, has_more.
    expect: (usize, usize, usize, bool),
    /// Allocations and requested bytes of the merge alone, inputs excluded. An upper bound.
    heap: (usize, usize),
}

/// A sealed copy as the mailbox holds it: UUID-length ids, ciphertext in `sealed_inner`.
fn sealed(n: usize, device: Option<&str>, payload: usize) -> MessageEnvelope {
    MessageEnvelope {
        message_id: format!("00000000-0000-4000-8000-{n:012}"),
        sender_id: String::new(),
        recipient_id: "11111111-1111-4111-8111-111111111111".into(),
        timestamp: 1,
        message_type: MessageType::DirectMessage,
        ephemeral_public_key: None,
        message_number: None,
        mls_payload: None,
        group_id: None,
        encrypted_payload: vec![],
        content_hash: String::new(),
        crypto_suite_id: 0,
        origin_server: None,
        federated: false,
        server_signature: None,
        is_sealed_sender: true,
        sealed_inner: Some(vec![0xA5; payload]),
        max_queue_len: None,
        proto_content_type: None,
        recipient_device: device.map(str::to_owned),
    }
}

fn row(ms: usize, env: MessageEnvelope) -> (String, Option<MessageEnvelope>) {
    (format!("{}-0", 1_700_000_000_000 + ms), Some(env))
}

fn cases(payload: usize) -> Vec<Case> {
    let own = |n| sealed(n, Some(READER), payload);
    let sib = |n| sealed(n, Some(SIBLING), payload);
    // Device copy at 2i+1, its user twin just before it at 2i.
    let device = |n: usize| -> Rows { (0..n).map(|i| row(2 * i + 1, own(i))).collect() };
    let twins = |n: usize| -> Rows { (0..n).map(|i| row(2 * i, own(i))).collect() };
    vec![
        Case {
            name: "short 5+5 twins",
            device: device(5),
            user: twins(5),
            expect: (5, 0, 0, false),
            heap: (9, 6_840),
        },
        Case {
            name: "full 100+100 twins",
            device: device(PER_SOURCE),
            user: twins(PER_SOURCE),
            expect: (COUNT, 0, 0, true),
            heap: (13, 114_520),
        },
        Case {
            name: "full device-only 100+0",
            device: device(PER_SOURCE),
            user: vec![],
            expect: (COUNT, 0, 0, true),
            heap: (12, 68_472),
        },
        Case {
            name: "full mixed 100+100 (1/2 sibling)",
            device: device(PER_SOURCE),
            user: (0..PER_SOURCE)
                .map(|i| row(2 * i, if i % 2 == 0 { own(i) } else { sib(1000 + i) }))
                .collect(),
            expect: (COUNT, 0, 50, true),
            heap: (13, 95_320),
        },
        Case {
            name: "retries 100+100 (10 ids)",
            device: (0..PER_SOURCE)
                .map(|i| row(2 * i + 1, own(i % 10)))
                .collect(),
            user: (0..PER_SOURCE).map(|i| row(2 * i, own(i % 10))).collect(),
            // The user read ends at 198; the last id's device copy at 199 waits behind it.
            expect: (9, 0, 0, true),
            heap: (10, 95_936),
        },
        Case {
            name: "sibling-only 0+100",
            device: vec![],
            user: (0..PER_SOURCE).map(|i| row(i, sib(i))).collect(),
            expect: (0, 0, PER_SOURCE, true),
            heap: (1, 2_400),
        },
        Case {
            name: "equal Redis ids 100+100",
            device: (0..PER_SOURCE).map(|i| row(i, own(i))).collect(),
            user: (0..PER_SOURCE).map(|i| row(i, own(1000 + i))).collect(),
            // Every id is in both sources, so either tie order makes half of the page user-only.
            expect: (COUNT, 25, 0, true),
            heap: (43, 119_708),
        },
    ]
}

fn median<T: Ord + Copy>(mut v: Vec<T>) -> T {
    v.sort_unstable();
    v[v.len() / 2]
}

#[test]
#[ignore = "run alone: the allocation counters are process-wide"]
fn profile_mailbox_merge() {
    // Unoptimized CI runs check the contract and the heap budget, not time.
    const BATCHES: usize = if cfg!(debug_assertions) { 1 } else { 9 };
    const PAGES: usize = if cfg!(debug_assertions) { 2 } else { 200 };
    for payload in [1024, 64 * 1024] {
        for case in cases(payload) {
            let rows = || case.device.iter().chain(&case.user);
            let encoded: Vec<_> = rows()
                .map(|(_, e)| rmp_serde::encode::to_vec_named(e.as_ref().unwrap()).unwrap())
                .collect();
            // Heap the envelopes themselves hold, the yardstick for the merge's working set.
            let held: usize = rows()
                .map(|(id, e)| {
                    let e = e.as_ref().unwrap();
                    size_of::<(String, Option<MessageEnvelope>)>()
                        + id.len()
                        + e.message_id.len()
                        + e.recipient_id.len()
                        + e.recipient_device.as_ref().map_or(0, String::len)
                        + e.sealed_inner.as_ref().map_or(0, Vec::len)
                })
                .sum();

            let (d, u) = (case.device.clone(), case.user.clone());
            let sample = AllocationSample::start();
            let page =
                merge_mailbox_pages(d, u, COUNT, PER_SOURCE, READER, MailboxCursor::default())
                    .unwrap();
            let heap = sample.finish();
            let (entries, user_only, skipped, more) = case.expect;
            assert_eq!(page.entries.len(), entries, "{}", case.name);
            assert_eq!(page.user_only(), user_only, "{}", case.name);
            assert_eq!(page.sibling_skipped, skipped, "{}", case.name);
            assert_eq!(page.has_more, more, "{}", case.name);
            assert!(
                heap.calls <= case.heap.0 && heap.bytes <= case.heap.1 + TABLE_GROUP,
                "{}: {} allocations / {} B, budget {:?}",
                case.name,
                heap.calls,
                heap.bytes,
                case.heap
            );
            for (_, e) in &page.entries {
                let e = e.as_ref().unwrap();
                assert_eq!(e.recipient_device.as_deref(), Some(READER), "{}", case.name);
                assert_eq!(e.sealed_inner.as_ref().unwrap().len(), payload);
            }
            drop(page);

            let (mut decode, mut scope, mut merge) = (vec![], vec![], vec![]);
            for _ in 0..BATCHES {
                let (mut t_dec, mut t_scope, mut t_merge) =
                    (Duration::ZERO, Duration::ZERO, Duration::ZERO);
                for _ in 0..PAGES {
                    let t = Instant::now();
                    let decoded: Vec<MessageEnvelope> = encoded
                        .iter()
                        .map(|b| rmp_serde::from_slice(black_box(b)).unwrap())
                        .collect();
                    t_dec += t.elapsed();
                    drop(black_box(decoded));

                    let t = Instant::now();
                    for (_, e) in rows() {
                        let e = e.as_ref().unwrap();
                        // Sibling rows of the user stream are skipped before they are hashed.
                        if e.recipient_device.as_deref() == Some(READER) {
                            black_box(MessageDedupKey::scope_for_envelope(black_box(e)));
                        }
                    }
                    t_scope += t.elapsed();

                    let (d, u) = (case.device.clone(), case.user.clone());
                    let t = Instant::now();
                    let page = black_box(
                        merge_mailbox_pages(
                            d,
                            u,
                            COUNT,
                            PER_SOURCE,
                            READER,
                            MailboxCursor::default(),
                        )
                        .unwrap(),
                    );
                    t_merge += t.elapsed();
                    drop(page);
                }
                decode.push(t_dec);
                scope.push(t_scope);
                merge.push(t_merge);
            }
            let us = |v: Vec<Duration>| median(v).as_secs_f64() * 1e6 / PAGES as f64;
            let (decode, scope, merge) = (us(decode), us(scope), us(merge));
            let rest = (merge - scope).max(0.0);
            eprintln!(
                "{payload:>6}B {:<33} decode={decode:8.2}us merge={merge:7.2}us scope_hash={scope:6.2}us rest={rest:6.2}us rest/(decode+merge)={:5.1}% | allocs={} bytes={} peak_delta={} held={held} bytes/held={:5.2}%",
                case.name,
                100.0 * rest / (decode + merge),
                heap.calls,
                heap.bytes,
                heap.peak_delta,
                100.0 * heap.bytes as f64 / held as f64,
            );
        }
    }
    eprintln!(
        "size_of: envelope={} row={}",
        size_of::<MessageEnvelope>(),
        size_of::<(String, Option<MessageEnvelope>)>()
    );
}

/// The whole `read_mailbox_messages` path on a loopback Redis, as the denominator.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a disposable loopback Redis, run alone"]
async fn profile_mailbox_read_path() {
    let url = std::env::var("PROFILE_REDIS_URL").expect("PROFILE_REDIS_URL");
    assert!(url.starts_with("redis://127.0.0.1:"), "loopback only");
    let cpu = || {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid writable timespec for the duration of the call.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) },
            0
        );
        ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9
    };
    let mut config = super::tests::get_test_config();
    config.redis_url = url;
    config.messaging.mailbox_user_write = true;
    let mut queue = MessageQueue::new(&config).await.unwrap();
    for payload in [1024, 64 * 1024] {
        let user = format!("merge-profile-{payload}-{}", std::process::id());
        for n in 0..PER_SOURCE {
            queue
                .write_message_to_device_streams(
                    &user,
                    &[READER.to_string()],
                    &sealed(n, Some(READER), payload),
                )
                .await
                .unwrap();
        }
        let mut us = vec![];
        let mut bytes = 0;
        for batch in 0..10 {
            let s = AllocationSample::start();
            let started = cpu();
            for _ in 0..50 {
                let page = queue
                    .read_mailbox_messages(&user, Some(READER), None, None, COUNT)
                    .await
                    .unwrap();
                assert_eq!(page.entries.len(), COUNT);
                assert_eq!(page.user_only(), 0);
            }
            // The first batch warms the connection buffers.
            if batch > 0 {
                us.push((cpu() - started) * 1e6 / 50.0);
                bytes = s.finish().bytes / 50;
            }
        }
        queue.delete_mailbox(&user).await.unwrap();
        us.sort_by(f64::total_cmp);
        eprintln!(
            "{payload:>6}B read path: process CPU {:.0}us/page [{:.0}..{:.0}] requested={bytes}B/page",
            us[us.len() / 2],
            us[0],
            us[us.len() - 1]
        );
    }
}
