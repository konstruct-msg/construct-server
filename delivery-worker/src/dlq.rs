// lint: some pub fns used only in integration tests
#![allow(dead_code)]
// ============================================================================
// Dead Letter Queue (DLQ) for Delivery Worker
// ============================================================================
//
// Prevents infinite retry loops for permanently failing messages.
//
// Problem:
// - If process_kafka_message returns Err(), offset is NOT committed
// - Kafka redelivers the same message forever
// - Bad message (e.g., corrupted payload) blocks consumer indefinitely
//
// Solution:
// - Track retry count per message in Redis (retry_count:{message_id})
// - After MAX_RETRIES (default: 5), send to DLQ topic and commit offset
// - DLQ messages can be inspected, replayed, or discarded manually
//
// Redis key: retry_count:{message_id} → u32, TTL = Kafka retention + 2h
//
// Kafka DLQ topic: {topic}-dlq (e.g., "messages-dlq")
// DLQ message includes: original envelope + error reason + retry count
//
// ============================================================================

use crate::retry::execute_redis_with_retry;
use crate::state::WorkerState;
use anyhow::{Context, Result};
use construct_broker::{KafkaMessageEnvelope, MessageProducer};
use construct_config::{SECONDS_PER_DAY, SECONDS_PER_HOUR};
use redis::cmd;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

/// Maximum retries before sending to DLQ
pub const MAX_RETRIES: u32 = 5;

/// A message that failed processing and was moved to the DLQ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterMessage {
    /// Original message envelope
    pub envelope: KafkaMessageEnvelope,
    /// Number of times processing was attempted
    pub retry_count: u32,
    /// Reason for failure (last error message)
    pub failure_reason: String,
    /// Unix timestamp when message was moved to DLQ
    pub dead_lettered_at: i64,
}

/// Increment retry counter for a message and return the new count
///
/// # Arguments
/// * `state` - Worker state
/// * `message_id` - Message ID
///
/// # Returns
/// New retry count after increment
pub async fn increment_retry_count(state: &WorkerState, message_id: &str) -> Result<u32> {
    let retry_key = format!("retry_count:{}", message_id);
    let ttl_seconds = ((state.config.message_ttl_days * SECONDS_PER_DAY)
        + (state.config.dedup_safety_margin_hours * SECONDS_PER_HOUR))
        as usize;

    let count: u32 = execute_redis_with_retry(state, "increment_retry_count", |conn| {
        let key = retry_key.clone();
        let ttl = ttl_seconds;
        Box::pin(async move {
            // INCR atomically increments and creates key if not exists
            let count: u32 = cmd("INCR").arg(&key).query_async(conn).await?;
            // Set TTL on first increment (count == 1) and refresh on each retry
            let _: () = cmd("EXPIRE").arg(&key).arg(ttl).query_async(conn).await?;
            Ok(count)
        })
    })
    .await
    .context("Failed to increment retry count")?;

    Ok(count)
}

/// Get current retry count for a message (without incrementing)
pub async fn get_retry_count(state: &WorkerState, message_id: &str) -> Result<u32> {
    let retry_key = format!("retry_count:{}", message_id);

    let count: Option<u32> = execute_redis_with_retry(state, "get_retry_count", |conn| {
        let key = retry_key.clone();
        Box::pin(async move { cmd("GET").arg(&key).query_async(conn).await })
    })
    .await
    .context("Failed to get retry count")?;

    Ok(count.unwrap_or(0))
}

/// Send a message to the Dead Letter Queue topic in Kafka
///
/// This is called after MAX_RETRIES failures. The message is serialized
/// with failure metadata and sent to `{topic}-dlq`.
///
/// # Arguments
/// * `producer` - Kafka producer (shared from messaging service)
/// * `envelope` - Original message envelope that failed
/// * `retry_count` - Number of times processing was attempted
/// * `failure_reason` - Description of the last failure
pub async fn send_to_dlq(
    producer: &MessageProducer,
    envelope: &KafkaMessageEnvelope,
    retry_count: u32,
    failure_reason: &str,
) -> Result<()> {
    let dlq_message = DeadLetterMessage {
        envelope: envelope.clone(),
        retry_count,
        failure_reason: failure_reason.to_string(),
        dead_lettered_at: chrono::Utc::now().timestamp(),
    };

    let dlq_topic = format!("{}-dlq", producer.topic());
    let payload = serde_json::to_vec(&dlq_message).context("Failed to serialize DLQ message")?;
    let key = envelope.recipient_id.as_bytes();

    if !producer.is_enabled() {
        warn!(
            message_id = %envelope.message_id,
            retry_count = retry_count,
            reason = failure_reason,
            "Kafka disabled — DLQ message logged only (would be sent to '{}' in production)",
            dlq_topic
        );
        error!(
            target: "dlq",
            message_id = %envelope.message_id,
            recipient_id = %envelope.recipient_id,
            retry_count = retry_count,
            failure_reason = failure_reason,
            dlq_topic = %dlq_topic,
            payload = %serde_json::to_string(&dlq_message).unwrap_or_default(),
            "DLQ_MESSAGE: Message moved to dead letter queue after max retries"
        );
        return Ok(());
    }

    match producer.send_raw_to_topic(&dlq_topic, key, &payload).await {
        Ok((partition, offset)) => {
            info!(
                message_id = %envelope.message_id,
                retry_count = retry_count,
                dlq_topic = %dlq_topic,
                partition,
                offset,
                "Message dead-lettered: written to Kafka DLQ topic"
            );
        }
        Err(e) => {
            // DLQ send failed — log as structured error so ops can recover manually.
            // We do NOT propagate the error: the caller must still commit the Kafka
            // offset to prevent an infinite retry loop.
            error!(
                target: "dlq",
                message_id = %envelope.message_id,
                recipient_id = %envelope.recipient_id,
                retry_count = retry_count,
                failure_reason = failure_reason,
                dlq_topic = %dlq_topic,
                kafka_error = %e,
                payload = %serde_json::to_string(&dlq_message).unwrap_or_default(),
                "DLQ_MESSAGE: Failed to write to Kafka DLQ — message logged for manual recovery"
            );
        }
    }

    Ok(())
}

/// Check if a message has exceeded retry limit
///
/// Returns (should_dlq, retry_count) where:
/// - should_dlq = true means: send to DLQ, commit offset, stop retrying
/// - should_dlq = false means: normal retry (don't commit offset)
pub async fn check_and_increment_retry(
    state: &WorkerState,
    message_id: &str,
) -> Result<(bool, u32)> {
    let count = increment_retry_count(state, message_id).await?;
    let should_dlq = count >= MAX_RETRIES;

    if should_dlq {
        error!(
            message_id = %message_id,
            retry_count = count,
            max_retries = MAX_RETRIES,
            "Message exceeded max retries - will be dead-lettered"
        );
    } else {
        warn!(
            message_id = %message_id,
            retry_count = count,
            max_retries = MAX_RETRIES,
            "Message processing failed, will retry"
        );
    }

    Ok((should_dlq, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlq_message_serialization() {
        use construct_broker::KafkaMessageEnvelope;

        let envelope = KafkaMessageEnvelope::new_direct_message(
            "msg-123".to_string(),
            "sender-456".to_string(),
            "recipient-789".to_string(),
            vec![0u8; 32],
            1,
            "encrypted".to_string(),
            "hash123".to_string(),
        );

        let dlq_msg = DeadLetterMessage {
            envelope,
            retry_count: 5,
            failure_reason: "Redis connection failed".to_string(),
            dead_lettered_at: 1234567890,
        };

        let json = serde_json::to_string(&dlq_msg).unwrap();
        assert!(json.contains("msg-123"));
        assert!(json.contains("Redis connection failed"));
        assert!(json.contains("\"retry_count\":5"));
    }

    #[test]
    fn test_max_retries_constant() {
        assert_eq!(MAX_RETRIES, 5);
    }
}
