//! Per-IP sliding window for unauthenticated sealed-sender ingress.
//!
//! Shared by `SendSealedMessage` and MessageStream sealed frames so the stream
//! door cannot bypass the only IP gate on the unary RPC.

use crate::context::MessagingServiceContext;

/// Outcome of the sealed-sender per-IP window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealedIpDecision {
    /// Under the cap (or Redis failed — fail-open, same as unary).
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
/// Fail-open on Redis error: a Redis outage must not block delivery (same
/// policy as the delivery-tag cache). Increments `sealed_ip` fail-open metric.
pub(crate) async fn check_sealed_ip_limit(
    context: &MessagingServiceContext,
    client_ip: &str,
) -> SealedIpDecision {
    let mut conn = context.redis_conn.clone();
    match construct_rate_limit::sliding_window_check_and_record(
        &mut conn,
        &format!("sealed_ip:{client_ip}"),
        context.config.messaging.sealed_ip_rate_limit_per_min,
        60,
    )
    .await
    {
        Ok(true) => SealedIpDecision::Allow,
        Ok(false) => SealedIpDecision::Limited,
        Err(e) => {
            tracing::error!(error = %e, "sealed_ip rate limit check unavailable — proceeding");
            construct_metrics::record_abuse_fail_open("sealed_ip");
            SealedIpDecision::Allow
        }
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
    fn forwarded_wins_over_x_real_ip() {
        let mut m = meta_with("x-forwarded-for", "203.0.113.1");
        m.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(extract_client_ip(&m), "203.0.113.1");
    }
}
