// ============================================================================
// Message Deduplication
// ============================================================================
//
// Deduplication logic for delivery worker messages.
// Prevents processing the same message multiple times.
//
// ARCHITECTURE: Multi-layer deduplication for Kafka as Source of Truth
// ============================================================================
//
// Layer 1: Message ID deduplication (processed_msg:{message_id})
//   - Prevents reprocessing of already-delivered messages
//   - Used when Kafka redelivers (user came online)
//
// Layer 2: Direct delivery check (delivered_direct:{message_id})
//   - Skips delivery-worker if message was delivered via tx.send()
//   - Reduces unnecessary work and network traffic
//
// Layer 3: Content hash deduplication (content_hash:{hash})
//   - Prevents duplicate messages with different IDs but same content
//   - Protects against client sending same message twice
//
// Key Principle:
//   For ONLINE users: mark as processed, commit Kafka offset
//   For OFFLINE users: do NOT mark as processed, Kafka will redeliver
//
// ============================================================================

use crate::delivery_worker::retry::execute_redis_with_retry;
use crate::delivery_worker::state::WorkerState;
use anyhow::{Context, Result};
use construct_config::{SECONDS_PER_DAY, SECONDS_PER_HOUR};
use redis::cmd;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Reason why a message was skipped
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Message was already processed by delivery worker
    AlreadyProcessed,
    /// Message was delivered directly via tx.send()
    DeliveredDirect,
    /// Message content hash already exists (duplicate content)
    DuplicateContent,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::AlreadyProcessed => write!(f, "already_processed"),
            SkipReason::DeliveredDirect => write!(f, "delivered_direct"),
            SkipReason::DuplicateContent => write!(f, "duplicate_content"),
        }
    }
}

/// Check if message was already processed
///
/// Checks Redis key: processed_msg:{message_id}
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
///
/// # Returns
/// `true` if message was already processed, `false` otherwise
pub async fn is_message_processed(state: &WorkerState, message_id: &str) -> Result<bool> {
    let dedup_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.processed_msg, message_id
    );

    let exists_result: i64 = execute_redis_with_retry(state, "check_deduplication", |conn| {
        let key = dedup_key.clone();
        Box::pin(async move { cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check deduplication after retries")?;

    Ok(exists_result > 0)
}

/// Check if message was already delivered directly via tx.send() (fast path)
///
/// SMART DEDUPLICATION:
/// If construct-server successfully delivered via tx.send(), it marks:
/// SET delivered_direct:{message_id} 1 EX 3600
///
/// We check this key and skip delivery to avoid duplicates.
/// This reduces server and network load.
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
///
/// # Returns
/// `true` if message was delivered directly, `false` otherwise
pub async fn was_delivered_direct(state: &WorkerState, message_id: &str) -> Result<bool> {
    let delivered_direct_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.delivered_direct, message_id
    );

    let was_delivered: i64 = execute_redis_with_retry(state, "check_delivered_direct", |conn| {
        let key = delivered_direct_key.clone();
        Box::pin(async move { cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check delivered_direct after retries")?;

    Ok(was_delivered > 0)
}

/// Check if content hash already exists (duplicate content detection)
///
/// Calculates SHA-256 hash of message content and checks if it was already delivered.
/// This prevents duplicate messages with different IDs but same content.
///
/// Key format: content_hash:{recipient_id}:{sha256_hash}
/// TTL: Short (1 hour) to allow intentional resends while catching accidental duplicates
///
/// # Arguments
/// * `state` - Worker state
/// * `recipient_id` - Recipient user ID
/// * `content` - Message content (ciphertext)
///
/// # Returns
/// `true` if content hash exists, `false` otherwise
pub async fn is_content_duplicate(
    state: &WorkerState,
    recipient_id: &str,
    content: &[u8],
) -> Result<bool> {
    // Calculate SHA-256 hash of content
    let mut hasher = Sha256::new();
    hasher.update(content);
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);

    // Key format: content_hash:{recipient_id}:{hash}
    // Include recipient_id to allow same content to different recipients
    let content_hash_key = format!(
        "{}content_hash:{}:{}",
        state.config.redis_key_prefixes.processed_msg,
        recipient_id,
        &hash_hex[..16] // Use first 16 chars of hash (64 bits, collision-safe for dedup)
    );

    let exists: i64 = execute_redis_with_retry(state, "check_content_hash", |conn| {
        let key = content_hash_key.clone();
        Box::pin(async move { cmd("EXISTS").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to check content hash")?;

    Ok(exists > 0)
}

/// Mark content hash as processed
///
/// # Arguments
/// * `state` - Worker state
/// * `recipient_id` - Recipient user ID
/// * `content` - Message content (ciphertext)
/// * `ttl_seconds` - TTL for the hash key (usually 1 hour for content dedup)
pub async fn mark_content_hash_processed(
    state: &WorkerState,
    recipient_id: &str,
    content: &[u8],
    ttl_seconds: i64,
) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);

    let content_hash_key = format!(
        "{}content_hash:{}:{}",
        state.config.redis_key_prefixes.processed_msg,
        recipient_id,
        &hash_hex[..16]
    );

    let _: String = execute_redis_with_retry(state, "mark_content_hash", |conn| {
        let key = content_hash_key.clone();
        let ttl = ttl_seconds;
        Box::pin(async move {
            cmd("SETEX")
                .arg(&key)
                .arg(ttl)
                .arg("1")
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to mark content hash as processed")?;

    Ok(())
}

/// Mark message as processed (for deduplication)
///
/// Sets Redis key: processed_msg:{message_id} with TTL
///
/// IMPORTANT: Only call this for ONLINE users!
/// For offline users, do NOT mark as processed - Kafka should redeliver.
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to mark as processed
/// * `ttl_seconds` - TTL in seconds
///   Should be: Kafka retention + safety_margin
///   Example: (7 days * 86400) + (2 hours * 3600) = 612,000s
pub async fn mark_message_processed(
    state: &WorkerState,
    message_id: &str,
    ttl_seconds: i64,
) -> Result<()> {
    let dedup_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.processed_msg, message_id
    );

    let _: String = execute_redis_with_retry(state, "mark_message_processed", |conn| {
        let key = dedup_key.clone();
        let ttl = ttl_seconds;
        Box::pin(async move {
            cmd("SETEX")
                .arg(&key)
                .arg(ttl)
                .arg("1")
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to mark message as processed after retries")?;

    debug!(
        message_id = %message_id,
        ttl_seconds = ttl_seconds,
        "Message marked as processed"
    );

    Ok(())
}

/// Check if message should be skipped (multi-layer deduplication)
///
/// Checks all deduplication layers in order of efficiency:
/// 1. Message ID (fastest - single key lookup)
/// 2. Direct delivery flag (fast - single key lookup)
///
/// Note: Content hash check is optional and done separately in processor
/// because it requires message content which may not be available yet.
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
///
/// # Returns
/// `Some(SkipReason)` if message should be skipped, `None` if it should be processed
pub async fn should_skip_message(
    state: &WorkerState,
    message_id: &str,
) -> Result<Option<&'static str>> {
    // Layer 1: Check if already processed by delivery worker
    if is_message_processed(state, message_id).await? {
        info!(
            message_id = %message_id,
            reason = "already_processed",
            "Message skipped (deduplication layer 1: processed_msg)"
        );
        return Ok(Some("already_processed"));
    }

    // Layer 2: Check if delivered directly via tx.send()
    if was_delivered_direct(state, message_id).await? {
        debug!(
            message_id = %message_id,
            reason = "delivered_direct",
            "Message skipped (deduplication layer 2: delivered_direct)"
        );

        // Mark as processed so we don't check again on next Kafka redeliver
        // Use TTL with safety margin (Kafka retention + 2h)
        let ttl_seconds = (state.config.message_ttl_days * SECONDS_PER_DAY)
            + (state.config.dedup_safety_margin_hours * SECONDS_PER_HOUR);
        if let Err(e) = mark_message_processed(state, message_id, ttl_seconds).await {
            warn!(
                message_id = %message_id,
                error = %e,
                "Failed to mark delivered_direct message as processed"
            );
        }

        return Ok(Some("delivered_direct"));
    }

    Ok(None)
}

/// Extended skip check including content hash
///
/// Use this for full deduplication including content-based detection.
/// More expensive than basic should_skip_message but catches duplicate content.
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID to check
/// * `recipient_id` - Recipient user ID
/// * `content` - Message content (ciphertext)
///
/// # Returns
/// `Some(SkipReason)` if message should be skipped, `None` if it should be processed
pub async fn should_skip_message_with_content(
    state: &WorkerState,
    message_id: &str,
    recipient_id: &str,
    content: &[u8],
) -> Result<Option<SkipReason>> {
    // Layer 1 & 2: Basic deduplication
    if let Some(reason) = should_skip_message(state, message_id).await? {
        return Ok(Some(match reason {
            "already_processed" => SkipReason::AlreadyProcessed,
            "delivered_direct" => SkipReason::DeliveredDirect,
            _ => SkipReason::AlreadyProcessed,
        }));
    }

    // Layer 3: Content hash deduplication
    if is_content_duplicate(state, recipient_id, content).await? {
        info!(
            message_id = %message_id,
            reason = "duplicate_content",
            "Message skipped (deduplication layer 3: content_hash)"
        );

        // Mark as processed
        // Use TTL with safety margin (Kafka retention + 2h)
        let ttl_seconds = (state.config.message_ttl_days * SECONDS_PER_DAY)
            + (state.config.dedup_safety_margin_hours * SECONDS_PER_HOUR);
        if let Err(e) = mark_message_processed(state, message_id, ttl_seconds).await {
            warn!(
                message_id = %message_id,
                error = %e,
                "Failed to mark duplicate content message as processed"
            );
        }

        return Ok(Some(SkipReason::DuplicateContent));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_reason_display() {
        assert_eq!(
            SkipReason::AlreadyProcessed.to_string(),
            "already_processed"
        );
        assert_eq!(SkipReason::DeliveredDirect.to_string(), "delivered_direct");
        assert_eq!(
            SkipReason::DuplicateContent.to_string(),
            "duplicate_content"
        );
    }
}
