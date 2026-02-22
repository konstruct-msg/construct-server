// ============================================================================
// Redis Retry Logic
// ============================================================================
//
// Execute Redis operations with retry logic and auto-reconnection.
// Extracted from bin/delivery_worker.rs for reuse across modules.
//
// ============================================================================

use crate::delivery_worker::state::WorkerState;
use anyhow::Result;
use tracing::{error, info, warn};

/// Execute a Redis operation with retry logic and auto-reconnection
///
/// This function provides:
/// - Automatic retry with exponential backoff
/// - Connection reconnection on failure
/// - Detailed error logging
///
/// # Arguments
/// * `state` - Worker state containing Redis connection
/// * `operation_name` - Name of the operation for logging
/// * `operation` - Async closure that performs the Redis operation
///
/// # Returns
/// Result with the operation result or error after all retries exhausted
pub async fn execute_redis_with_retry<F, T>(
    state: &WorkerState,
    operation_name: &str,
    mut operation: F,
) -> Result<T>
where
    F: FnMut(
        &mut redis::aio::MultiplexedConnection,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, redis::RedisError>> + Send + '_>,
    >,
{
    const MAX_RETRIES: u32 = 3;
    const INITIAL_BACKOFF_MS: u64 = 100;

    for attempt in 1..=MAX_RETRIES {
        let mut conn = state.redis_conn.write().await;

        match operation(&mut conn).await {
            Ok(result) => {
                if attempt > 1 {
                    info!(
                        operation = operation_name,
                        attempt = attempt,
                        "Redis operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                drop(conn); // Release lock before potentially reconnecting

                warn!(
                    operation = operation_name,
                    attempt = attempt,
                    max_retries = MAX_RETRIES,
                    error = %e,
                    "Redis operation failed, will retry"
                );

                if attempt < MAX_RETRIES {
                    // Exponential backoff
                    let backoff_ms = INITIAL_BACKOFF_MS * 2_u64.pow(attempt - 1);
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;

                    // Try to reconnect on last retry before final attempt
                    if attempt == MAX_RETRIES - 1 {
                        info!("Attempting to reconnect to Redis...");
                        match state.redis_client.get_multiplexed_async_connection().await {
                            Ok(new_conn) => {
                                let mut conn = state.redis_conn.write().await;
                                *conn = new_conn;
                                info!("Successfully reconnected to Redis");
                            }
                            Err(reconnect_err) => {
                                error!(error = %reconnect_err, "Failed to reconnect to Redis");
                            }
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "Redis operation '{}' failed after {} retries: {}",
                        operation_name,
                        MAX_RETRIES,
                        e
                    ));
                }
            }
        }
    }

    unreachable!()
}
