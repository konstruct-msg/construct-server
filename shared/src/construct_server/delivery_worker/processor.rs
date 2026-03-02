// ============================================================================
// Message Processor
// ============================================================================
//
// Main message processing logic for delivery worker.
// Handles Kafka messages and routes them to appropriate Redis streams.
//
// ARCHITECTURE: Kafka as Single Source of Truth (Hybrid Approach)
// ============================================================================
//
// Key Principle: Kafka offset is committed ONLY when message is successfully
// delivered to an ONLINE user. For offline users, offset is NOT committed,
// so Kafka will redeliver the message when the user comes online.
//
// Flow:
// 1. Check deduplication (processed_msg, delivered_direct)
// 2. Check if recipient is online
// 3. If ONLINE:
//    - Push to delivery_stream:{server_instance_id}
//    - Mark as processed
//    - Return Success -> commit offset
// 4. If OFFLINE:
//    - Optionally cache in Redis for fast delivery (optimization only)
//    - Return UserOffline -> DO NOT commit offset
//    - Message stays in Kafka for redelivery
//
// Guarantees:
// - Kafka remains the single source of truth
// - Messages are never lost (even if Redis fails)
// - At-least-once delivery with deduplication
//
// ============================================================================

use crate::delivery_worker::deduplication::should_skip_message;
use crate::delivery_worker::redis_streams::push_to_offline_stream_atomic;
use crate::delivery_worker::state::WorkerState;
use crate::kafka::KafkaMessageEnvelope;
use crate::utils::log_safe_id;
use anyhow::{Context, Result};
use construct_config::{SECONDS_PER_DAY, SECONDS_PER_HOUR};
use redis::cmd;
use tracing::{debug, info};

/// Result of processing a Kafka message
///
/// This enum controls whether the Kafka offset should be committed.
/// CRITICAL: Only commit offset for Success and Skipped - never for UserOffline!
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessResult {
    /// Message successfully delivered to online user - COMMIT offset
    Success,
    /// User is offline - DO NOT commit offset, Kafka will redeliver
    UserOffline,
    /// Message was skipped (already processed/delivered) - COMMIT offset
    Skipped,
}

// Note: This module uses Redis Streams (XADD) instead of Lists (RPUSH).
// The stream keys use the same prefix format as Lists for compatibility:
// - delivery_queue:{server_instance_id} → delivery_stream:{server_instance_id}
// - delivery_queue:offline:{user_id} → delivery_stream:offline:{user_id}
//
// Future migration: Update stream key prefixes when fully migrating to Streams.

/// Process a single Kafka message
///
/// This function handles the complete lifecycle of a message:
/// - Deduplication checks
/// - Online/offline routing
/// - Stream storage (Redis Streams) for online users
/// - Optional Redis caching for offline users (optimization only)
///
/// CRITICAL: Returns ProcessResult to control offset commit behavior:
/// - Success/Skipped -> commit offset (message handled)
/// - UserOffline -> DO NOT commit offset (Kafka will redeliver)
///
/// # Arguments
/// * `state` - Worker state
/// * `envelope` - Kafka message envelope
///
/// # Returns
/// ProcessResult indicating how the message was handled
pub async fn process_kafka_message(
    state: &WorkerState,
    envelope: &KafkaMessageEnvelope,
) -> Result<ProcessResult> {
    let message_id = &envelope.message_id;
    let recipient_id = &envelope.recipient_id;

    // SECURITY: Even in debug logs, hash recipient_id for privacy
    let salt = &state.config.logging.hash_salt;
    debug!(
        message_id = %message_id,
        recipient_hash = %log_safe_id(recipient_id, salt),
        "Processing Kafka message"
    );

    // 1. Check if message should be skipped (deduplication)
    if let Some(skip_reason) = should_skip_message(state, message_id).await? {
        // Message was already processed or delivered directly
        debug!(
            message_id = %message_id,
            reason = skip_reason,
            "Message skipped (deduplication)"
        );
        return Ok(ProcessResult::Skipped);
    }

    // 2. Serialize envelope to MessagePack for Redis storage
    let message_bytes = rmp_serde::encode::to_vec_named(envelope)
        .context("Failed to serialize Kafka envelope to MessagePack")?;

    // 3. Calculate deduplication TTL with safety margin
    // ========================================================================
    // RELIABILITY FIX: Dedup TTL must exceed Kafka retention to prevent edge case
    //
    // Problem: If message is at end of Kafka retention (e.g., 6d 23h 59m) and worker
    // crashes after creating dedup key but before committing offset:
    // - Kafka deletes message (retention expired) → NO redelivery possible
    // - Dedup key remains for full retention period → wasted memory
    //
    // Solution: TTL = Kafka retention + safety_margin (2h)
    // - Covers network delays, worker restart time, offset commit lag
    // - Kafka can still redeliver within safety window
    // - Dedup prevents duplicates if redelivery happens
    //
    // Example: 7 days retention + 2h margin = 604,800s + 7,200s = 612,000s
    // ========================================================================
    let ttl_seconds = ((state.config.message_ttl_days * SECONDS_PER_DAY)
        + (state.config.dedup_safety_margin_hours * SECONDS_PER_HOUR)) as u64;

    // 4. Route message to user-based stream
    // ========================================================================
    // ARCHITECTURE FIX: Always use user-based stream (delivery_queue:offline:{user_id})
    //
    // Previous approach used server_instance_id-based streams, which broke in
    // multi-instance deployments where requests can hit different API instances.
    // The message would be written to delivery_queue:{instance_A} but the user's
    // next request might hit instance_B, reading from delivery_queue:{instance_B}.
    //
    // User-based streams are stable regardless of which API instance handles
    // the request, solving the message delivery problem in multi-instance setups.
    // ========================================================================

    // CRITICAL: Use atomic transaction to prevent race condition
    // If we do XADD then SET separately, worker could crash between operations:
    // - XADD succeeds, SET fails → message delivered but not marked as processed
    // - Kafka redelivers → duplicate delivery
    // Solution: MULTI/EXEC transaction - both succeed or both fail
    let stream_key = format!(
        "{}:offline:{}",
        state.config.delivery_queue_prefix, recipient_id
    );

    push_to_offline_stream_atomic(
        state,
        &stream_key,
        recipient_id,
        message_id,
        &message_bytes,
        ttl_seconds,
    )
    .await
    .context("Failed to atomically push message and mark as processed")?;

    // Publish notification for long polling endpoints
    if let Err(e) = publish_message_notification(state, recipient_id).await {
        debug!(
            message_id = %message_id,
            recipient_hash = %log_safe_id(recipient_id, salt),
            error = %e,
            "Failed to publish message notification (not critical)"
        );
    }

    let stream_key = format!(
        "{}:offline:{}",
        state.config.delivery_queue_prefix, recipient_id
    );

    info!(
        message_id = %message_id,
        recipient_hash = %log_safe_id(recipient_id, salt),
        stream_key = %stream_key,
        "Message pushed to user delivery stream atomically - offset will NOT be committed immediately"
    );

    // Do not commit offset immediately.
    // Let Kafka redeliver. On redelivery, deduplication will find the 'processed' flag,
    // return 'Skipped', and then the offset will be committed.
    // This ensures at-least-once processing in case of worker failure.
    Ok(ProcessResult::UserOffline)
}

/// Publish notification to Redis Pub/Sub for long polling endpoints
///
/// When a message is delivered to a user, this function publishes a notification
/// to the channel `message_notifications:{user_id}` so that long polling endpoints
/// can be notified and return messages immediately.
///
/// # Arguments
/// * `state` - Worker state
/// * `user_id` - User ID to notify
async fn publish_message_notification(state: &WorkerState, user_id: &str) -> Result<()> {
    use crate::delivery_worker::retry::execute_redis_with_retry;

    let channel = format!("message_notifications:{}", user_id);

    execute_redis_with_retry(state, "publish_message_notification", |conn| {
        let ch = channel.clone();
        Box::pin(async move {
            // PUBLISH returns the number of subscribers that received the message
            let _subscriber_count: i64 = cmd("PUBLISH")
                .arg(&ch)
                .arg("1") // Simple notification payload
                .query_async(conn)
                .await?;
            Ok(())
        })
    })
    .await
    .context("Failed to publish message notification")?;

    debug!(
        user_id = %user_id,
        channel = %channel,
        "Published message notification for long polling"
    );

    Ok(())
}
