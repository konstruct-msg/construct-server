//! Shared rate-limit primitives: sliding windows, account age/warmup lookups,
//! address buckets and the bounded degraded limiter for Redis outages.
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

/// Surviving a Redis outage without taking messaging down: a circuit breaker plus a
/// bounded in-process counter. Lived in `construct-sentinel-service` until 2026-09-13,
/// which made it reachable only by depending on another service's crate — so the sealed
/// door had no fallback and simply gave up. It is a limiting mechanism, so it belongs
/// with the limiter.
pub mod degraded;
pub use degraded::{BreakerState, DegradedLimiter, DegradedOutcome};

/// Check if user is in warmup period (<48 hours old)
pub async fn is_user_in_warmup(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query_scalar::<_, bool>("SELECT is_user_in_warmup($1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to check warmup status")?;

    Ok(result)
}

/// Get user account age in hours
pub async fn get_user_account_age_hours(pool: &PgPool, user_id: Uuid) -> Result<f64> {
    let age = sqlx::query_scalar::<_, Option<f64>>("SELECT get_user_account_age_hours($1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to get account age")?;

    Ok(age.unwrap_or(0.0))
}

// ── Redis sliding-window primitives ──────────────────────────────────────────

// TTL for the warmup cache key. 10 minutes is safe — warmup is a 48h window so
// a stale cache entry causes at most a brief mis-classification of the user.
const WARMUP_CACHE_TTL_SECS: u64 = 600;

/// Sliding-window rate limit backed by a Redis ZSet.
///
/// Scores = millisecond epoch timestamps; members = nanosecond strings (unique).
/// Each call: trims expired entries, counts remaining, records if below limit.
///
/// Returns `true` if the action is allowed (event recorded).
/// Returns `false` if the rate limit has been exceeded (nothing recorded).
pub async fn sliding_window_check_and_record(
    conn: &mut redis::aio::ConnectionManager,
    key: &str,
    max_events: u32,
    window_seconds: i64,
) -> anyhow::Result<bool> {
    use redis::AsyncCommands;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_start_ms = now_ms - window_seconds * 1000;

    // Remove entries older than the window.
    let _: i64 = conn
        .zrembyscore(key, f64::NEG_INFINITY, window_start_ms as f64)
        .await
        .map_err(|e| anyhow::anyhow!("zrembyscore failed: {e}"))?;

    // Count entries still in the window.
    let count: u32 = conn
        .zcount(key, (window_start_ms + 1) as f64, f64::INFINITY)
        .await
        .map_err(|e| anyhow::anyhow!("zcount failed: {e}"))?;

    if count >= max_events {
        return Ok(false);
    }

    // Record this event. Use nanosecond timestamp as a unique member; if
    // nanoseconds are unavailable, fall back to "ms-count" which is still unique
    // within the same process.
    let member = chrono::Utc::now()
        .timestamp_nanos_opt()
        .map(|n| n.to_string())
        .unwrap_or_else(|| format!("{}-{}", now_ms, count));

    // pow.rs pattern: zadd(key, member, score) — member before score.
    let _: i64 = conn
        .zadd(key, &member, now_ms)
        .await
        .map_err(|e| anyhow::anyhow!("zadd failed: {e}"))?;

    // Refresh TTL with a small buffer so keys clean themselves up.
    let _: bool = conn
        .expire(key, window_seconds + 60)
        .await
        .map_err(|e| anyhow::anyhow!("expire failed: {e}"))?;

    Ok(true)
}

/// `is_user_in_warmup` with a 10-minute Redis cache to avoid a PG round-trip
/// on every group/channel action.
///
/// On cache miss the result is fetched from PG via `is_user_in_warmup` and
/// written back to Redis. Cache write failures are silently ignored.
pub async fn is_user_in_warmup_cached(
    conn: &mut redis::aio::ConnectionManager,
    pool: &PgPool,
    user_id: Uuid,
) -> anyhow::Result<bool> {
    use redis::AsyncCommands;

    let key = format!("rl:warmup:{}", user_id);

    let cached: Option<u8> = conn.get(&key).await.unwrap_or(None);
    if let Some(v) = cached {
        return Ok(v == 1);
    }

    let in_warmup = is_user_in_warmup(pool, user_id).await?;

    let val: u8 = if in_warmup { 1 } else { 0 };
    let _: Result<(), _> = conn.set_ex(&key, val, WARMUP_CACHE_TTL_SECS).await;

    Ok(in_warmup)
}

/// Collapse a client address to the unit a per-address rate limit should count.
///
/// Keying a limit on the exact address counts something the sender changes for free.
/// Every VPS provider hands out an IPv6 /64 along with the machine — 2^64 addresses,
/// each its own bucket under a /128 key — so rotating inside it costs nothing and the
/// window stops being a limit. IPv6 is therefore counted per /64, the smallest block a
/// single customer is normally given.
///
/// IPv4 keeps its full address. There is no v4 prefix length that is both meaningful
/// and safe: allocations run from /32 to /8, and NAT already puts many people behind
/// one address, so shortening the key would widen an error that is already there.
///
/// An IPv4-mapped IPv6 address (`::ffff:203.0.113.9`) is counted as the IPv4 address it
/// carries. Without that, every v4 client that happened to arrive mapped would land in
/// one `::/64` bucket together.
///
/// What this deliberately does NOT fix: everyone behind a shared egress — a VEIL relay,
/// CGNAT, a VPN exit — still shares one bucket, and no prefix length fixes that, because
/// the address is not the sender. A network-shaped limit is wrong in both directions at
/// once, too tight for people behind one relay and too loose for anyone renting a /64;
/// this closes only the half that is free to exploit. The axis that survives both is the
/// credential, not the route.
///
/// Anything unparseable is returned trimmed and unchanged, so the `"unknown"` sentinel
/// stays one bucket rather than becoming an empty key suffix.
pub fn client_rate_bucket(client_ip: &str) -> String {
    use std::net::{IpAddr, Ipv6Addr};

    let raw = client_ip.trim();
    if raw.is_empty() {
        return "unknown".to_string();
    }

    // `[2001:db8::1]:443` — the bracketed form; anything after `]` is a port.
    let bare = if let Some(rest) = raw.strip_prefix('[') {
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return raw.to_string(),
        }
    } else {
        raw
    };

    // Zone id (`fe80::1%en0`) names a local interface and is not part of the address.
    let bare = bare.split('%').next().unwrap_or(bare);

    // Try the address as written first: a bare IPv6 is full of colons and must not be
    // mistaken for `host:port`. Only if that fails is a single colon a port separator.
    let parsed = bare
        .parse::<IpAddr>()
        .or_else(|_| match bare.rsplit_once(':') {
            Some((host, _port)) if !host.contains(':') => host.parse::<IpAddr>(),
            _ => bare.parse::<IpAddr>(),
        });

    match parsed {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                format!("{}/64", Ipv6Addr::from(octets))
            }
        },
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_addresses_in_one_slash_64_share_a_bucket() {
        // Free rotation inside a /64 is the evasion this exists to stop.
        let a = client_rate_bucket("2001:db8:85a3:8d3::1");
        let b = client_rate_bucket("2001:db8:85a3:8d3:ffff:ffff:ffff:ffff");
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:85a3:8d3::/64");
    }

    #[test]
    fn adjacent_slash_64s_stay_apart() {
        assert_ne!(
            client_rate_bucket("2001:db8:85a3:8d3::1"),
            client_rate_bucket("2001:db8:85a3:8d4::1")
        );
    }

    #[test]
    fn ipv4_keeps_its_whole_address() {
        assert_eq!(client_rate_bucket("203.0.113.9"), "203.0.113.9");
        assert_ne!(
            client_rate_bucket("203.0.113.9"),
            client_rate_bucket("203.0.113.10")
        );
    }

    #[test]
    fn an_ipv4_mapped_address_counts_as_its_ipv4() {
        // Otherwise every mapped v4 client shares one ::/64 bucket with the rest.
        assert_eq!(client_rate_bucket("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(
            client_rate_bucket("::ffff:203.0.113.9"),
            client_rate_bucket("203.0.113.9")
        );
    }

    #[test]
    fn ports_brackets_and_zones_are_not_part_of_the_address() {
        assert_eq!(client_rate_bucket("203.0.113.9:44310"), "203.0.113.9");
        assert_eq!(
            client_rate_bucket("[2001:db8:85a3:8d3::1]:44310"),
            "2001:db8:85a3:8d3::/64"
        );
        assert_eq!(client_rate_bucket("fe80::1%en0"), "fe80::/64");
    }

    #[test]
    fn unparseable_input_is_one_bucket_not_an_empty_key() {
        // `extract_client_ip` returns this when no address header is present, and a
        // Redis key ending in ":" would be shared by every such request anyway — the
        // point is that it never panics and never produces an empty suffix.
        assert_eq!(client_rate_bucket("unknown"), "unknown");
        assert_eq!(client_rate_bucket(""), "unknown");
        assert_eq!(client_rate_bucket("   "), "unknown");
        assert_eq!(client_rate_bucket("not-an-address"), "not-an-address");
    }
}
