// ============================================================================
// Sealed Sender — Two-Layer Delivery Tag Anti-Replay Cache
// ============================================================================
//
// Protects against replay attacks on SealedInner.delivery_tag.
//
// Layer 1 — exact cache (TTL = 5 min):
//   Redis key: sealed:exact:{sha256(tag)}
//   Guarantees: no false positives. Any tag seen in the last 5 minutes is
//   definitively identified as a replay.
//
// Layer 2 — long-term seen cache (TTL = 24 h):
//   Redis key: sealed:seen:{sha256(tag)}
//   Approximates a bloom filter without the probability-of-false-positive
//   problem: exact Redis keys scale fine for the expected message volume
//   (at 1 million ghost messages/day, 24h × 32-byte keys ≈ 32 MB in Redis).
//
// Decision tree:
//   exact hit  → confirmed replay (within 5 min)
//   seen hit   → presumed replay  (within 24 h, no false positives here either)
//   neither    → new tag → mark both caches → deliver
//
// The check-and-mark is a single atomic Lua round-trip to Redis.
// No queue Mutex is acquired; callers use the standalone `redis_conn`
// from `MessagingServiceContext` (lock-free clone).
//
// If Redis is unavailable, we fail-open (deliver the message) so that a
// Redis outage cannot cause a silent message loss.
// ============================================================================

use sha2::{Digest, Sha256};

/// TTL of the exact-match window (5 minutes).
const EXACT_TTL_SECS: u64 = 300;

/// TTL of the long-term seen cache (24 hours).
const SEEN_TTL_SECS: u64 = 86_400;

/// Result of a delivery_tag check.
#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryTagStatus {
    /// Tag not seen before — message should be delivered.
    New,
    /// Tag was seen within the exact window (5 min) — confirmed replay.
    ExactCacheHit,
    /// Tag was seen within the long-term window (24 h) — presumed replay.
    SeenCacheHit,
}

/// Atomic check-and-mark for `SealedInner.delivery_tag`.
///
/// Uses a single Lua round-trip so the check and the two SETEX calls are
/// atomic from Redis's perspective.
pub async fn check_and_mark_delivery_tag(
    conn: &mut redis::aio::ConnectionManager,
    delivery_tag: &[u8],
) -> anyhow::Result<DeliveryTagStatus> {
    let tag_hex = hex::encode(Sha256::digest(delivery_tag));
    let exact_key = format!("sealed:exact:{}", tag_hex);
    let seen_key = format!("sealed:seen:{}", tag_hex);

    // Lua script — runs atomically:
    //   0 → new tag (marked in both caches)
    //   1 → exact cache hit  (confirmed replay, within 5 min)
    //   2 → seen cache hit   (presumed replay, within 24 h)
    let script = redis::Script::new(
        r#"
local exact_key = KEYS[1]
local seen_key  = KEYS[2]
local exact_ttl = tonumber(ARGV[1])
local seen_ttl  = tonumber(ARGV[2])

if redis.call('EXISTS', exact_key) == 1 then
    return 1
end
if redis.call('EXISTS', seen_key) == 1 then
    return 2
end

redis.call('SETEX', exact_key, exact_ttl, '1')
redis.call('SETEX', seen_key,  seen_ttl,  '1')
return 0
"#,
    );

    let result: i64 = script
        .key(&exact_key)
        .key(&seen_key)
        .arg(EXACT_TTL_SECS)
        .arg(SEEN_TTL_SECS)
        .invoke_async(conn)
        .await?;

    Ok(match result {
        1 => DeliveryTagStatus::ExactCacheHit,
        2 => DeliveryTagStatus::SeenCacheHit,
        _ => DeliveryTagStatus::New,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_tag_status_variants() {
        assert_ne!(DeliveryTagStatus::New, DeliveryTagStatus::ExactCacheHit);
        assert_ne!(DeliveryTagStatus::New, DeliveryTagStatus::SeenCacheHit);
        assert_ne!(
            DeliveryTagStatus::ExactCacheHit,
            DeliveryTagStatus::SeenCacheHit
        );
    }

    #[test]
    fn test_tag_hex_is_deterministic() {
        let tag = b"some_32_byte_delivery_tag_value!";
        let hex1 = hex::encode(Sha256::digest(tag));
        let hex2 = hex::encode(Sha256::digest(tag));
        assert_eq!(hex1, hex2, "SHA-256 of the same tag must be deterministic");
        assert_eq!(hex1.len(), 64, "SHA-256 hex must be 64 chars");
    }

    #[test]
    fn test_different_tags_produce_different_keys() {
        let tag1 = b"tag_one_32_bytes________________";
        let tag2 = b"tag_two_32_bytes________________";
        let hex1 = hex::encode(Sha256::digest(tag1));
        let hex2 = hex::encode(Sha256::digest(tag2));
        assert_ne!(hex1, hex2, "Different tags must hash to different keys");
    }
}
