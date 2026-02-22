// ============================================================================
// Pending Messages Storage (Redis)
// ============================================================================

use super::types::PendingMessageData;
use anyhow::{Context, Result};
use redis::AsyncCommands;
use serde_json;

/// Redis keys for pending messages
const PENDING_MSG_PREFIX: &str = "pending_msg:";
const PENDING_INDEX_KEY: &str = "pending_messages_index";

/// TTL for pending messages in Redis (1 hour = 3600 seconds)
const PENDING_MSG_TTL_SECONDS: i64 = 3600;

/// Metrics for pending message operations
#[derive(Debug, Default, Clone)]
pub struct PendingMessageMetrics {
    /// Number of currently pending messages
    pub pending_count: u64,

    /// Number of confirmed messages
    pub confirmed_count: u64,

    /// Number of auto-confirmed messages
    pub auto_confirmed_count: u64,

    /// Number of expired/deleted messages
    pub deleted_count: u64,
}

/// Pending message storage in Redis
pub struct PendingMessageStorage {
    redis_client: redis::Client,
}

impl PendingMessageStorage {
    pub fn new(redis_client: redis::Client) -> Self {
        Self { redis_client }
    }

    /// Store a pending message (Phase 1)
    /// Returns Ok(None) if stored successfully
    /// Returns Ok(Some(existing_data)) if temp_id already exists (idempotency)
    pub async fn store_pending(
        &self,
        data: &PendingMessageData,
    ) -> Result<Option<PendingMessageData>> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let key = format!("{}{}", PENDING_MSG_PREFIX, data.temp_id);

        // Check if temp_id already exists (idempotency)
        let exists: bool = conn
            .exists(&key)
            .await
            .context("Failed to check if pending message exists")?;

        if exists {
            // Return existing data (idempotent operation)
            let existing = self.get_pending(&data.temp_id).await?;
            return Ok(existing);
        }

        // Store new pending message as Redis Hash
        let json_data =
            serde_json::to_string(data).context("Failed to serialize pending message")?;

        // Use Redis transaction for atomicity
        let _: () = redis::pipe()
            .atomic()
            // Store message data
            .set(&key, &json_data)
            .ignore()
            // Set TTL
            .expire(&key, PENDING_MSG_TTL_SECONDS)
            .ignore()
            // Add to index (sorted set by timestamp)
            .zadd(PENDING_INDEX_KEY, &data.temp_id, data.created_at)
            .ignore()
            .query_async(&mut conn)
            .await
            .context("Failed to store pending message")?;

        tracing::debug!(
            temp_id = %data.temp_id,
            message_id = %data.message_id,
            "Stored pending message"
        );

        Ok(None)
    }

    /// Get a pending message by temp_id
    pub async fn get_pending(&self, temp_id: &str) -> Result<Option<PendingMessageData>> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let key = format!("{}{}", PENDING_MSG_PREFIX, temp_id);

        let json_data: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to get pending message")?;

        match json_data {
            Some(data) => {
                let pending =
                    serde_json::from_str(&data).context("Failed to deserialize pending message")?;
                Ok(Some(pending))
            }
            None => Ok(None),
        }
    }

    /// Confirm a pending message (Phase 2)
    pub async fn confirm_pending(&self, temp_id: &str) -> Result<bool> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let key = format!("{}{}", PENDING_MSG_PREFIX, temp_id);

        // Get existing data
        let mut data = match self.get_pending(temp_id).await? {
            Some(d) => d,
            None => {
                tracing::warn!(temp_id = %temp_id, "Attempted to confirm non-existent pending message");
                return Ok(false);
            }
        };

        // Update status
        data.confirm();

        // Store updated data
        let json_data =
            serde_json::to_string(&data).context("Failed to serialize pending message")?;

        let _: () = conn
            .set(&key, &json_data)
            .await
            .context("Failed to update pending message")?;

        tracing::debug!(
            temp_id = %temp_id,
            message_id = %data.message_id,
            "Confirmed pending message"
        );

        Ok(true)
    }

    /// Delete a pending message (cleanup)
    pub async fn delete_pending(&self, temp_id: &str) -> Result<bool> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let key = format!("{}{}", PENDING_MSG_PREFIX, temp_id);

        // Use transaction to delete both key and index entry
        let (deleted, _): (i32, i32) = redis::pipe()
            .atomic()
            .del(&key)
            .zrem(PENDING_INDEX_KEY, temp_id)
            .query_async(&mut conn)
            .await
            .context("Failed to delete pending message")?;

        Ok(deleted > 0)
    }

    /// Get all pending messages older than the specified age (for cleanup worker)
    pub async fn get_old_pending_messages(
        &self,
        min_age_seconds: i64,
    ) -> Result<Vec<PendingMessageData>> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let max_timestamp = chrono::Utc::now().timestamp() - min_age_seconds;

        // Get temp_ids from sorted set (scores = timestamps)
        let temp_ids: Vec<String> = conn
            .zrangebyscore(PENDING_INDEX_KEY, "-inf", max_timestamp)
            .await
            .context("Failed to query pending messages index")?;

        let mut messages = Vec::new();

        for temp_id in temp_ids {
            if let Some(data) = self.get_pending(&temp_id).await? {
                messages.push(data);
            }
        }

        Ok(messages)
    }

    /// Update Kafka partition/offset for a pending message
    pub async fn update_kafka_info(
        &self,
        temp_id: &str,
        partition: i32,
        offset: i64,
    ) -> Result<bool> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let key = format!("{}{}", PENDING_MSG_PREFIX, temp_id);

        // Get existing data
        let mut data = match self.get_pending(temp_id).await? {
            Some(d) => d,
            None => return Ok(false),
        };

        // Update Kafka info
        data.kafka_partition = Some(partition);
        data.kafka_offset = Some(offset);

        // Store updated data
        let json_data =
            serde_json::to_string(&data).context("Failed to serialize pending message")?;

        let _: () = conn
            .set(&key, &json_data)
            .await
            .context("Failed to update pending message")?;

        Ok(true)
    }

    /// Get metrics (for monitoring)
    pub async fn get_metrics(&self) -> Result<PendingMessageMetrics> {
        let mut conn = self
            .redis_client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        // Count all pending messages in index
        let total_count: u64 = conn
            .zcard(PENDING_INDEX_KEY)
            .await
            .context("Failed to count pending messages")?;

        // To get detailed breakdown, we'd need to scan all messages
        // For now, return total count
        Ok(PendingMessageMetrics {
            pending_count: total_count,
            confirmed_count: 0, // TODO: track separately if needed
            auto_confirmed_count: 0,
            deleted_count: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::MessageStatus;
    use super::*;

    // Note: These tests require Redis to be running
    // Run with: cargo test --features integration-tests

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_store_and_get_pending() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let storage = PendingMessageStorage::new(client);

        let data = PendingMessageData::new(
            "test-temp-123".to_string(),
            "test-msg-456".to_string(),
            "user-a".to_string(),
            "user-b".to_string(),
        );

        // Store should return None (new message)
        let result = storage.store_pending(&data).await.unwrap();
        assert!(result.is_none());

        // Second store with same temp_id should return existing data (idempotency)
        let result = storage.store_pending(&data).await.unwrap();
        assert!(result.is_some());
        let existing = result.unwrap();
        assert_eq!(existing.temp_id, data.temp_id);
        assert_eq!(existing.message_id, data.message_id);

        // Get should return the data
        let retrieved = storage.get_pending("test-temp-123").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.temp_id, "test-temp-123");
        assert_eq!(retrieved.status, MessageStatus::Pending);

        // Cleanup
        storage.delete_pending("test-temp-123").await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_confirm_pending() {
        let client = redis::Client::open("redis://127.0.0.1:6379").unwrap();
        let storage = PendingMessageStorage::new(client);

        let data = PendingMessageData::new(
            "test-temp-confirm".to_string(),
            "test-msg-confirm".to_string(),
            "user-a".to_string(),
            "user-b".to_string(),
        );

        storage.store_pending(&data).await.unwrap();

        // Confirm
        let confirmed = storage.confirm_pending("test-temp-confirm").await.unwrap();
        assert!(confirmed);

        // Verify status changed
        let retrieved = storage
            .get_pending("test-temp-confirm")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.status, MessageStatus::Confirmed);
        assert!(retrieved.confirmed_at.is_some());

        // Cleanup
        storage.delete_pending("test-temp-confirm").await.unwrap();
    }
}
