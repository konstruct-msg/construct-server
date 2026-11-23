//! Opt-in profile of one cleanup pass against a disposable loopback Redis. Run alone.
use super::*;

#[path = "../../shared/test_support/allocations.rs"]
#[allow(dead_code)] // The other profiles that share this file read every field.
mod allocations;
use allocations::AllocationSample;

fn cpu() -> f64 {
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
}

async fn registry() -> (CallRegistry, String) {
    let url = std::env::var("PROFILE_REDIS_URL").expect("PROFILE_REDIS_URL");
    assert!(url.starts_with("redis://127.0.0.1:"), "loopback only");
    let r = CallRegistry::new(&url, "cleanup-profile".into())
        .await
        .unwrap();
    // The pass walks every active call in this Redis, so the profile owns it.
    assert!(
        r.list_active_call_ids().await.is_empty(),
        "disposable Redis"
    );
    (r, uuid::Uuid::new_v4().simple().to_string())
}

struct Call {
    id: String,
    caller: broadcast::Receiver<ForwardedSignal>,
    callee: broadcast::Receiver<ForwardedSignal>,
}

async fn call(r: &CallRegistry, p: &str, n: usize) -> Call {
    let name = |what: &str| format!("{p}-{what}-{n:04}");
    let (caller, callee) = (name("caller"), name("callee"));
    let caller_rx = r.register_user(&caller, &name("cd")).await.subscribe();
    let callee_rx = r.register_user(&callee, &name("ed")).await.subscribe();
    r.create_call(&name("call"), &caller, &name("cd"), &callee, unix_millis())
        .await;
    r.note_ringing(&name("call")).await;
    r.note_connected(&name("call"), Some(&name("ed"))).await;
    Call {
        id: name("call"),
        caller: caller_rx,
        callee: callee_rx,
    }
}

fn hangups(rx: &mut broadcast::Receiver<ForwardedSignal>) -> usize {
    let mut n = 0;
    while let Ok(signal) = rx.try_recv() {
        if let ForwardedSignal::Signal(WebRtcSignal {
            signal: Some(web_rtc_signal::Signal::Hangup(_)),
            ..
        }) = signal
        {
            n += 1;
        }
    }
    n
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a disposable loopback Redis, run alone"]
async fn profile_signaling_cleanup_pass() {
    for calls in [1, 2, 100] {
        let (r, p) = registry().await;
        let mut all = Vec::new();
        for n in 0..calls {
            all.push(call(&r, &p, n).await);
        }
        let now = unix_seconds();
        r.cleanup_pass(now, unix_millis()).await; // warms the connection buffers

        // Healthy calls: nothing is sent, nothing is removed.
        let (s, t) = (AllocationSample::start(), cpu());
        for _ in 0..20 {
            r.cleanup_pass(now, unix_millis()).await;
        }
        let (healthy_cpu, healthy) = (cpu() - t, s.finish());
        for c in &mut all {
            assert_eq!((hangups(&mut c.caller), hangups(&mut c.callee)), (0, 0));
            assert!(r.load_call_state(&c.id).await.is_some());
        }

        // One side goes on pinging: either side's silence alone ends the call.
        for (n, c) in all.iter().enumerate() {
            let mut states = r.calls.write().await;
            let state = states.get_mut(&c.id).unwrap();
            if n % 2 == 0 {
                state.caller_last_keepalive_at = now + 61;
            } else {
                state.callee_last_keepalive_at = now + 61;
            }
        }

        // The same calls 61 s after the other side's last keepalive: one hangup to each side, then removal.
        let (s, t) = (AllocationSample::start(), cpu());
        r.cleanup_pass(now + 61, unix_millis()).await;
        let (stale_cpu, stale) = (cpu() - t, s.finish());
        for c in &mut all {
            assert_eq!((hangups(&mut c.caller), hangups(&mut c.callee)), (1, 1));
            assert!(r.load_call_state(&c.id).await.is_none());
        }
        assert!(r.list_active_call_ids().await.is_empty());
        // Upper bounds measured on this fixture: a healthy call costs one state clone.
        assert!(
            healthy.calls <= 20 * (12 + 6 * calls + calls / 8),
            "healthy pass: {}",
            healthy.calls
        );
        assert!(stale.calls <= 120 * calls, "stale pass: {}", stale.calls);
        println!(
            "cleanup: calls={calls} healthy cpu_us/pass={:.0} allocs/pass={:.1} bytes/pass={} | stale cpu_us/pass={:.0} allocs={} bytes={} (per call {:.1} allocs, {:.0} B)",
            healthy_cpu * 1e6 / 20.0,
            healthy.calls as f64 / 20.0,
            healthy.bytes / 20,
            stale_cpu * 1e6,
            stale.calls,
            stale.bytes,
            stale.calls as f64 / calls as f64,
            stale.bytes as f64 / calls as f64,
        );
    }
}
