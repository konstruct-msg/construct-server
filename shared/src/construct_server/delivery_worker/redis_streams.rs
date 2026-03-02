// ============================================================================
// Redis Streams Operations
// ============================================================================
//
// Redis Streams operations for delivery worker.
// Provides optimized message delivery using XADD, XREADGROUP, etc.
//
// Key Benefits over Lists:
// - XADD = 1 command (vs RPUSH + EXPIRE = 2 commands)
// - Blocking read = 0 commands when no messages (vs polling)
// - Automatic trimming via MAXLEN
// - Consumer groups for distribution
//
// ============================================================================

use crate::delivery_worker::retry::execute_redis_with_retry;
use crate::delivery_worker::state::WorkerState;
use anyhow::{Context, Result};
use redis::cmd;
use tracing::debug;

/// Push message to delivery stream using XADD
///
/// Uses XADD with MAXLEN for automatic trimming:
/// XADD stream_key MAXLEN ~ max_len * message_id payload message_bytes
///
/// # Arguments
/// * `state` - Worker state
/// * `stream_key` - Redis stream key (e.g., "delivery_stream:{server_instance_id}")
/// * `message_id` - Unique message ID for deduplication
/// * `message_bytes` - Serialized message payload
/// * `max_len` - Maximum stream length (automatic trim), if None uses config default
///
/// # Returns
/// Stream message ID (e.g., "1234567890-0")
pub async fn push_to_delivery_stream(
    state: &WorkerState,
    stream_key: &str,
    message_id: &str,
    message_bytes: &[u8],
    max_len: Option<usize>,
) -> Result<String> {
    // Use config default if not specified
    // For now, use a reasonable default (10000 messages)
    // TODO: Add delivery_stream_max_len to Config when migrating to Streams
    let max_len = max_len.unwrap_or(10000);

    let stream_id: String = execute_redis_with_retry(state, "push_to_delivery_stream", |conn| {
        let key = stream_key.to_string();
        let msg_id = message_id.to_string();
        let payload = message_bytes.to_vec();

        Box::pin(async move {
            // XADD stream_key MAXLEN ~ max_len * message_id payload message_bytes
            // Using ~ for approximate trimming (faster than exact)
            cmd("XADD")
                .arg(&key)
                .arg("MAXLEN")
                .arg("~") // Approximate trimming
                .arg(max_len as i64)
                .arg("*") // Auto-generate message ID (timestamp-sequence)
                .arg("message_id")
                .arg(&msg_id)
                .arg("payload")
                .arg(&payload)
                .query_async(conn)
                .await
        })
    })
    .await
    .context("Failed to push message to delivery stream")?;

    debug!(
        stream_key = %stream_key,
        message_id = %message_id,
        stream_id = %stream_id,
        "Pushed message to delivery stream"
    );

    Ok(stream_id)
}

/// Push message to offline stream and mark as processed ATOMICALLY
///
/// Uses Redis MULTI/EXEC transaction to ensure both operations succeed or fail together.
/// This prevents race conditions where:
/// - XADD succeeds but SET fails → message delivered but not marked as processed
/// - Worker crashes between operations → Kafka redelivers → duplicate
///
/// # Arguments
/// * `state` - Worker state
/// * `stream_key` - Redis stream key (e.g., "delivery_queue:offline:{user_id}")
/// * `user_id` - Recipient user ID (for logging)
/// * `message_id` - Unique message ID
/// * `message_bytes` - Serialized message payload
/// * `ttl_seconds` - TTL for deduplication key
///
/// # Returns
/// Stream message ID (e.g., "1234567890-0")
///
/// # Transaction
/// ```redis
/// MULTI
/// XADD delivery_queue:offline:{user_id} MAXLEN ~ 10000 * message_id {id} payload {bytes}
/// SETEX processed_msg:{message_id} {ttl} 1
/// EXEC
/// ```
pub async fn push_to_offline_stream_atomic(
    state: &WorkerState,
    stream_key: &str,
    user_id: &str,
    message_id: &str,
    message_bytes: &[u8],
    ttl_seconds: u64,
) -> Result<String> {
    use redis::pipe;

    let dedup_key = format!(
        "{}{}",
        state.config.redis_key_prefixes.processed_msg, message_id
    );

    let max_len = 10000; // Default stream max length

    let stream_id: String =
        execute_redis_with_retry(state, "push_to_offline_stream_atomic", |conn| {
            let key = stream_key.to_string();
            let msg_id = message_id.to_string();
            let payload = message_bytes.to_vec();
            let dedup = dedup_key.clone();
            let ttl = ttl_seconds;

            Box::pin(async move {
                // Build atomic transaction using pipeline
                let mut pipe = pipe();
                pipe.atomic(); // Enable MULTI/EXEC

                // Command 1: XADD to stream
                pipe.cmd("XADD")
                    .arg(&key)
                    .arg("MAXLEN")
                    .arg("~")
                    .arg(max_len as i64)
                    .arg("*") // Auto-generate stream ID
                    .arg("message_id")
                    .arg(&msg_id)
                    .arg("payload")
                    .arg(&payload);

                // Command 2: SETEX dedup key
                pipe.cmd("SETEX").arg(&dedup).arg(ttl as i64).arg("1");

                // Execute transaction - returns (stream_id, set_result)
                let results: (String, String) = pipe.query_async(conn).await?;

                // Return stream ID from XADD
                Ok::<String, redis::RedisError>(results.0)
            })
        })
        .await
        .context("Failed to atomically push message and mark as processed")?;

    debug!(
        stream_key = %stream_key,
        message_id = %message_id,
        user_id = %user_id,
        stream_id = %stream_id,
        dedup_key = %dedup_key,
        ttl_seconds = ttl_seconds,
        "Atomically pushed message to stream and marked as processed"
    );

    Ok(stream_id)
}

/// Push message to offline stream
///
/// Similar to push_to_delivery_stream but for offline users.
/// Format: delivery_stream:offline:{user_id}
///
/// # Arguments
/// * `state` - Worker state
/// * `user_id` - Recipient user ID
/// * `message_id` - Unique message ID
/// * `message_bytes` - Serialized message payload
/// * `max_len` - Maximum stream length, if None uses config default
///
/// # Returns
/// Stream message ID
pub async fn push_to_offline_stream(
    state: &WorkerState,
    user_id: &str,
    message_id: &str,
    message_bytes: &[u8],
    max_len: Option<usize>,
) -> Result<String> {
    let stream_key = format!("{}:offline:{}", state.config.delivery_queue_prefix, user_id);

    push_to_delivery_stream(state, &stream_key, message_id, message_bytes, max_len).await
}

/// Check if user is online by looking up server instance ID
///
/// Checks Redis key: user:{user_id}:server_instance_id
///
/// # Arguments
/// * `state` - Worker state
/// * `user_id` - User ID to check
///
/// # Returns
/// Server instance ID if user is online, None if offline
pub async fn check_user_online(state: &WorkerState, user_id: &str) -> Result<Option<String>> {
    let user_server_key = format!(
        "{}{}:server_instance_id",
        state.config.redis_key_prefixes.user, user_id
    );

    let server_instance_id: Option<String> =
        execute_redis_with_retry(state, "check_user_online", |conn| {
            let key = user_server_key.clone();
            Box::pin(async move { cmd("GET").arg(&key).query_async(conn).await })
        })
        .await
        .context("Failed to check user online status")?;

    Ok(server_instance_id)
}
