//! Per-IP sliding window for unauthenticated sealed-sender ingress.
//!
//! Shared by `SendSealedMessage` and MessageStream sealed frames so the stream
//! door cannot bypass the only IP gate on the unary RPC.

use std::sync::LazyLock;

use construct_rate_limit::{BreakerState, DegradedLimiter, client_rate_bucket};

use crate::context::MessagingServiceContext;

/// Per-instance fallback for the sealed-sender window, used only while Redis is
/// unreachable.
///
/// A process-wide static rather than a field on the context because that is what it is:
/// the whole point of a degraded counter is that it counts what *this process* saw, and
/// putting it behind a clonable context would invite one per clone. `SentinelCore` owns
/// its own because it is a struct with a lifetime; `check_sealed_ip_limit` is a free
/// function on the hot path and has nowhere else to keep state.
static SEALED_DOOR: LazyLock<DegradedLimiter> = LazyLock::new(DegradedLimiter::new);

/// Outcome of the sealed-sender per-IP window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealedIpDecision {
    /// Under the cap.
    Allow,
    /// Window exceeded; caller must refuse without dispatching.
    Limited,
}

/// Extract client IP from `x-forwarded-for` / `x-real-ip` gRPC metadata (set by
/// Caddy's `reverse_proxy`). Used for sealed-sender IP rate limits.
///
/// SECURITY: take the **rightmost** `X-Forwarded-For` entry, not the leftmost.
/// Caddy *appends* the real connecting peer after any client-supplied values, so
/// the leftmost hop is attacker-controlled and can rotate to dodge rate limits.
/// Matches `key-service` bundle rate-limit IP extraction.
pub(crate) fn extract_client_ip(metadata: &tonic::metadata::MetadataMap) -> String {
    if let Some(forwarded) = metadata
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let ip = forwarded.split(',').next_back().unwrap_or("").trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    if let Some(real_ip) = metadata.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return real_ip.trim().to_string();
    }
    "unknown".to_string()
}

/// Check-and-record the per-IP sealed send window.
///
/// On a Redis outage this does not give up. It trips a circuit breaker — so the cost of
/// the outage is not one timeout per send, which is what turns a blip into a latency
/// collapse — and keeps counting in a bounded in-process table for the duration. The
/// ceiling becomes approximate and per-instance (N processes means N × limit) instead of
/// exact and shared. That is the trade degraded mode is: a blast-radius cap during an
/// outage, not enforcement.
///
/// Until 2026-09-13 the Redis arm returned `Allow` unconditionally, which removed the
/// gate rather than degrading it — and the only sign was a counter on a panel with no
/// alert behind it.
pub(crate) async fn check_sealed_ip_limit(
    context: &MessagingServiceContext,
    client_ip: &str,
) -> SealedIpDecision {
    // Counted per /64 on IPv6, not per address. A /64 comes free with any rented machine,
    // so a window keyed on the exact address is a window the sender opens as many of as it
    // likes. `client_rate_bucket` is shared with key-service's bundle limit rather than
    // restated here — two limiters disagreeing about what an address is would be one
    // meaning on two carriers.
    let key = format!("sealed_ip:{}", client_rate_bucket(client_ip));
    let limit = context.config.messaging.sealed_ip_rate_limit_per_min;
    let now_ms = chrono::Utc::now().timestamp_millis();

    if SEALED_DOOR.should_skip_redis(now_ms) {
        return charge_locally(&key, limit);
    }

    let mut conn = context.redis_conn.clone();
    match construct_rate_limit::sliding_window_check_and_record(&mut conn, &key, limit, 60).await {
        Ok(allowed) => {
            if SEALED_DOOR.state(now_ms) != BreakerState::Closed {
                tracing::info!(
                    "sealed_ip Redis recovered — leaving degraded mode, Redis is authoritative again"
                );
                // Drop the outage's counters: keeping them would charge every sender
                // against both the local window and the Redis one.
                SEALED_DOOR.clear();
            }
            SEALED_DOOR.record_success();
            if allowed {
                SealedIpDecision::Allow
            } else {
                SealedIpDecision::Limited
            }
        }
        Err(e) => {
            if SEALED_DOOR.record_failure(now_ms) {
                tracing::error!(
                    error = %e,
                    "sealed_ip Redis unreachable — degrading to per-instance limits (sends continue)"
                );
            }
            charge_locally(&key, limit)
        }
    }
}

/// Count one send in the local fallback table and say whether it may proceed.
fn charge_locally(key: &str, limit: u32) -> SealedIpDecision {
    construct_metrics::record_abuse_fail_open("sealed_ip_degraded");
    let now_secs = chrono::Utc::now().timestamp();
    let out = SEALED_DOOR.charge(key, limit as i32, 60, now_secs);
    if !out.tracked {
        // The table is full, so this send passes uncounted. Allowed rather than denied —
        // denying at capacity would recreate the outage degraded mode exists to prevent —
        // but reported, because sustained non-zero means the fallback has stopped limiting.
        construct_metrics::record_abuse_fail_open("sealed_ip_untracked");
    }
    if out.allowed {
        SealedIpDecision::Allow
    } else {
        SealedIpDecision::Limited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta_with(key: &'static str, value: &str) -> tonic::metadata::MetadataMap {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(key, value.parse().expect("ascii metadata"));
        m
    }

    #[test]
    fn x_forwarded_for_takes_rightmost_hop() {
        let m = meta_with("x-forwarded-for", "1.1.1.1, 8.8.8.8, 203.0.113.9");
        assert_eq!(extract_client_ip(&m), "203.0.113.9");
    }

    #[test]
    fn x_real_ip_when_no_forwarded() {
        let m = meta_with("x-real-ip", "198.51.100.4");
        assert_eq!(extract_client_ip(&m), "198.51.100.4");
    }

    #[test]
    fn unknown_when_no_ip_headers() {
        let m = tonic::metadata::MetadataMap::new();
        assert_eq!(extract_client_ip(&m), "unknown");
    }

    #[test]
    fn the_window_counts_an_ipv6_prefix_not_an_address() {
        // The gate this gives a stranger is only as good as what it counts. Rotating
        // inside a rented /64 is free; rotating out of one is not.
        use construct_rate_limit::client_rate_bucket;
        let a = extract_client_ip(&meta_with("x-forwarded-for", "2001:db8:1:2::1"));
        let b = extract_client_ip(&meta_with("x-forwarded-for", "2001:db8:1:2::dead:beef"));
        assert_ne!(a, b, "the extractor must keep the full address");
        assert_eq!(
            client_rate_bucket(&a),
            client_rate_bucket(&b),
            "but the window must count them as one sender"
        );
    }

    #[test]
    fn forwarded_wins_over_x_real_ip() {
        let mut m = meta_with("x-forwarded-for", "203.0.113.1");
        m.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(extract_client_ip(&m), "203.0.113.1");
    }
}
