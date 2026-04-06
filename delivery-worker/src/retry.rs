// ============================================================================
// Redis Retry Logic
// ============================================================================
//
// Execute Redis operations with retry logic and auto-reconnection.
// Extracted from bin/delivery_worker.rs for reuse across modules.
//
// ============================================================================

use crate::state::WorkerState;
use anyhow::Result;
use tracing::{info, warn};

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
        &mut redis::aio::ConnectionManager,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, redis::RedisError>> + Send + '_>,
    >,
{
    const MAX_RETRIES: u32 = 3;
    const INITIAL_BACKOFF_MS: u64 = 100;

    for attempt in 1..=MAX_RETRIES {
        // ConnectionManager is Clone and handles reconnects internally.
        let mut conn = state.redis_conn.clone();

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
                warn!(
                    operation = operation_name,
                    attempt = attempt,
                    max_retries = MAX_RETRIES,
                    error = %e,
                    "Redis operation failed, will retry"
                );

                if attempt < MAX_RETRIES {
                    let backoff_ms = INITIAL_BACKOFF_MS * 2_u64.pow(attempt - 1);
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
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
