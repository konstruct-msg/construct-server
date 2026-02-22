use super::storage::DeliveryPendingStorage;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Background task that periodically cleans up expired delivery pending records
///
/// Runs every `cleanup_interval` and removes records where expires_at < NOW()
///
/// # Privacy Note
/// Automatic cleanup ensures we don't retain delivery metadata longer than necessary
pub struct DeliveryCleanupTask<S: DeliveryPendingStorage> {
    storage: Arc<S>,
    cleanup_interval: Duration,
}

impl<S: DeliveryPendingStorage> DeliveryCleanupTask<S> {
    /// Create a new cleanup task
    ///
    /// # Arguments
    /// * `storage` - Storage implementation to use for cleanup
    /// * `cleanup_interval` - How often to run cleanup (e.g., every 1 hour)
    pub fn new(storage: Arc<S>, cleanup_interval: Duration) -> Self {
        Self {
            storage,
            cleanup_interval,
        }
    }

    /// Start the cleanup task
    ///
    /// This runs indefinitely in the background, cleaning up expired records
    /// at the specified interval.
    ///
    /// # Example
    /// ```ignore
    /// use std::sync::Arc;
    /// use std::time::Duration;
    /// use construct_server::delivery_ack::{DeliveryCleanupTask, PostgresDeliveryStorage};
    /// use sqlx::PgPool;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let pool = PgPool::connect("postgres://...").await.unwrap();
    ///     let storage = Arc::new(PostgresDeliveryStorage::new(pool));
    ///     let cleanup_task = DeliveryCleanupTask::new(storage, Duration::from_secs(3600));
    ///
    ///     tokio::spawn(async move {
    ///         cleanup_task.run().await;
    ///     });
    /// }
    /// ```
    pub async fn run(self) {
        tracing::info!(
            interval_secs = self.cleanup_interval.as_secs(),
            "Starting delivery ACK cleanup task"
        );

        let mut interval = time::interval(self.cleanup_interval);

        loop {
            interval.tick().await;

            match self.storage.delete_expired().await {
                Ok(deleted_count) => {
                    if deleted_count > 0 {
                        tracing::info!(
                            deleted_count = deleted_count,
                            "Cleaned up expired delivery pending records"
                        );

                        // Update metrics (prometheus is always available)
                        // Note: Delivery pending metrics may not be defined in metrics.rs
                        // This code is left for future metrics implementation
                    } else {
                        tracing::debug!("No expired delivery pending records to clean up");
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to clean up expired delivery pending records"
                    );
                }
            }

            // Log current pending count for monitoring
            match self.storage.count().await {
                Ok(count) => {
                    tracing::debug!(pending_count = count, "Current delivery pending records");

                    // Update metrics (prometheus is always available)
                    // Note: Delivery pending metrics may not be defined in metrics.rs
                    // This code is left for future metrics implementation
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Failed to get delivery pending count"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct MockStorage {
        delete_count: AtomicU64,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                delete_count: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl DeliveryPendingStorage for MockStorage {
        async fn save(
            &self,
            _record: &crate::delivery_ack::models::DeliveryPending,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn find_by_hash(
            &self,
            _message_hash: &str,
        ) -> anyhow::Result<Option<crate::delivery_ack::models::DeliveryPending>> {
            Ok(None)
        }

        async fn delete_by_hash(&self, _message_hash: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn delete_expired(&self) -> anyhow::Result<u64> {
            let count = self.delete_count.fetch_add(1, Ordering::SeqCst);
            Ok(count)
        }

        async fn count(&self) -> anyhow::Result<i64> {
            Ok(0)
        }

        async fn delete_by_user_id(&self, _user_id: &str) -> anyhow::Result<u64> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn test_cleanup_task_runs() {
        let storage = Arc::new(MockStorage::new());
        let task = DeliveryCleanupTask::new(storage.clone(), Duration::from_millis(100));

        // Run task for a short time
        let handle = tokio::spawn(async move {
            task.run().await;
        });

        // Let it run for 350ms (should trigger 3 cleanups)
        tokio::time::sleep(Duration::from_millis(350)).await;
        handle.abort();

        // Verify cleanup was called (at least once)
        let count = storage.delete_count.load(Ordering::SeqCst);
        assert!(count >= 1, "Cleanup should have been called at least once");
    }
}
