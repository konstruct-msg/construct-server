use super::models::DeliveryPending;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Storage interface for delivery pending records
///
/// This trait allows for multiple implementations:
/// - PostgreSQL (current)
/// - Redis (for better performance)
/// - Kafka (for event sourcing and auto-expiry)
#[async_trait::async_trait]
pub trait DeliveryPendingStorage: Send + Sync {
    /// Save a new delivery pending record
    async fn save(&self, record: &DeliveryPending) -> Result<()>;

    /// Find a delivery pending record by message hash
    async fn find_by_hash(&self, message_hash: &str) -> Result<Option<DeliveryPending>>;

    /// Delete a delivery pending record by message hash
    async fn delete_by_hash(&self, message_hash: &str) -> Result<()>;

    /// Delete all expired delivery pending records
    /// Returns the number of deleted records
    async fn delete_expired(&self) -> Result<u64>;

    /// Get count of pending records (for metrics)
    async fn count(&self) -> Result<i64>;

    /// Delete all delivery pending records for a specific user (GDPR compliance)
    ///
    /// This implements the GDPR "Right to Erasure" (Article 17).
    /// Removes all delivery ACK records where the user is the sender.
    ///
    /// # Arguments
    /// * `user_id` - The user ID whose data should be deleted
    ///
    /// # Returns
    /// Number of deleted records
    async fn delete_by_user_id(&self, user_id: &str) -> Result<u64>;
}

/// PostgreSQL implementation of DeliveryPendingStorage
pub struct PostgresDeliveryStorage {
    pool: PgPool,
}

impl PostgresDeliveryStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl DeliveryPendingStorage for PostgresDeliveryStorage {
    async fn save(&self, record: &DeliveryPending) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO delivery_pending (message_hash, sender_id, expires_at, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (message_hash) DO NOTHING
            "#,
        )
        .bind(&record.message_hash)
        .bind(&record.sender_id)
        .bind(record.expires_at)
        .bind(record.created_at)
        .execute(&self.pool)
        .await
        .context("Failed to save delivery pending record")?;

        Ok(())
    }

    async fn find_by_hash(&self, message_hash: &str) -> Result<Option<DeliveryPending>> {
        let record = sqlx::query_as::<_, (String, String, DateTime<Utc>, DateTime<Utc>)>(
            r#"
            SELECT message_hash, sender_id, expires_at, created_at
            FROM delivery_pending
            WHERE message_hash = $1
            "#,
        )
        .bind(message_hash)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to find delivery pending record")?;

        Ok(record.map(
            |(message_hash, sender_id, expires_at, created_at)| DeliveryPending {
                message_hash,
                sender_id,
                expires_at,
                created_at,
            },
        ))
    }

    async fn delete_by_hash(&self, message_hash: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM delivery_pending
            WHERE message_hash = $1
            "#,
        )
        .bind(message_hash)
        .execute(&self.pool)
        .await
        .context("Failed to delete delivery pending record")?;

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM delivery_pending
            WHERE expires_at < NOW()
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to delete expired delivery pending records")?;

        Ok(result.rows_affected())
    }

    async fn count(&self) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM delivery_pending
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to count delivery pending records")?;

        Ok(count)
    }

    async fn delete_by_user_id(&self, user_id: &str) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM delivery_pending
            WHERE sender_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .context("Failed to delete delivery pending records by user_id")?;

        let deleted_count = result.rows_affected();

        tracing::info!(
            user_id = %user_id,
            deleted_count = deleted_count,
            "GDPR: Deleted delivery ACK records for user"
        );

        Ok(deleted_count)
    }
}

// ============================================================================
// Kafka-Based Delivery Storage (Solution 1D - Privacy-First)
// ============================================================================

/// Kafka-based delivery ACK storage with ephemeral Redis mappings
///
/// **SECURITY DESIGN (Solution 1D)**:
/// - Kafka events contain ONLY hashed IDs (HMAC-SHA256)
/// - Redis stores ephemeral mappings: message_hash → {sender_id, recipient_id}
/// - Automatic TTL expiry (7 days) in Redis
/// - Requires Kafka + Redis + SECRET_KEY to reconstruct sender info
///
/// Flow:
/// 1. record_pending_delivery:
///    - Save to Redis: `delivery_ack:{message_hash}` → JSON
///    - Set TTL on Redis key
/// 2. process_acknowledgment:
///    - Look up sender_id from Redis using message_hash
///    - Delete Redis key (one-time use)
///    - Kafka consumer sends "delivered" ACK to sender
///
/// Privacy properties:
/// - ✅ Kafka logs reveal nothing (only hashes)
/// - ✅ Redis data is ephemeral (auto-expires)
/// - ✅ Requires 3 components to correlate: Kafka + Redis + SECRET_KEY
pub struct KafkaDeliveryStorage {
    redis_client: redis::aio::ConnectionManager,
    ttl_seconds: i64,
}

impl KafkaDeliveryStorage {
    /// Create a new KafkaDeliveryStorage
    ///
    /// # Arguments
    /// * `redis_client` - Redis connection manager
    /// * `ttl_days` - Number of days before ephemeral mappings expire
    pub fn new(redis_client: redis::aio::ConnectionManager, ttl_days: i64) -> Self {
        Self {
            redis_client,
            ttl_seconds: ttl_days * 86400, // Convert days to seconds
        }
    }

    /// Build Redis key for delivery ACK mapping
    fn redis_key(&self, message_hash: &str) -> String {
        format!("delivery_ack:{}", message_hash)
    }
}

#[async_trait::async_trait]
impl DeliveryPendingStorage for KafkaDeliveryStorage {
    async fn save(&self, record: &DeliveryPending) -> Result<()> {
        use redis::AsyncCommands;

        // Serialize record to JSON
        let json = serde_json::json!({
            "sender_id": record.sender_id,
            "expires_at": record.expires_at.timestamp(),
            "created_at": record.created_at.timestamp(),
        });
        let json_str = serde_json::to_string(&json)?;

        let key = self.redis_key(&record.message_hash);

        // Save to Redis with TTL
        let mut conn = self.redis_client.clone();
        let _: () = conn
            .set_ex(&key, json_str, self.ttl_seconds as u64)
            .await
            .context("Failed to save delivery ACK mapping to Redis")?;

        tracing::debug!(
            message_hash = %record.message_hash,
            ttl_seconds = %self.ttl_seconds,
            "Saved delivery ACK mapping to Redis"
        );

        Ok(())
    }

    async fn find_by_hash(&self, message_hash: &str) -> Result<Option<DeliveryPending>> {
        use redis::AsyncCommands;

        let key = self.redis_key(message_hash);
        let mut conn = self.redis_client.clone();

        let json_str: Option<String> = conn
            .get(&key)
            .await
            .context("Failed to get delivery ACK mapping from Redis")?;

        match json_str {
            Some(json) => {
                let data: serde_json::Value = serde_json::from_str(&json)?;

                let sender_id = data["sender_id"]
                    .as_str()
                    .context("Missing sender_id in Redis data")?
                    .to_string();

                let expires_at_ts = data["expires_at"]
                    .as_i64()
                    .context("Missing expires_at in Redis data")?;

                let created_at_ts = data["created_at"]
                    .as_i64()
                    .context("Missing created_at in Redis data")?;

                use chrono::TimeZone;
                let expires_at = Utc
                    .timestamp_opt(expires_at_ts, 0)
                    .single()
                    .context("Invalid expires_at timestamp")?;

                let created_at = Utc
                    .timestamp_opt(created_at_ts, 0)
                    .single()
                    .context("Invalid created_at timestamp")?;

                Ok(Some(DeliveryPending {
                    message_hash: message_hash.to_string(),
                    sender_id,
                    expires_at,
                    created_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn delete_by_hash(&self, message_hash: &str) -> Result<()> {
        use redis::AsyncCommands;

        let key = self.redis_key(message_hash);
        let mut conn = self.redis_client.clone();

        let _: () = conn
            .del(&key)
            .await
            .context("Failed to delete delivery ACK mapping from Redis")?;

        tracing::debug!(
            message_hash = %message_hash,
            "Deleted delivery ACK mapping from Redis"
        );

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        // Redis automatically deletes expired keys via TTL
        // No manual cleanup needed
        Ok(0)
    }

    async fn count(&self) -> Result<i64> {
        use redis::AsyncCommands;

        let pattern = "delivery_ack:*";
        let mut conn = self.redis_client.clone();

        // Count keys matching pattern
        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .context("Failed to count delivery ACK keys in Redis")?;

        Ok(keys.len() as i64)
    }

    async fn delete_by_user_id(&self, user_id: &str) -> Result<u64> {
        use redis::AsyncCommands;

        // Scan all delivery_ack:* keys
        let pattern = "delivery_ack:*";
        let mut conn = self.redis_client.clone();

        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .context("Failed to scan delivery ACK keys in Redis")?;

        let mut deleted_count = 0;

        // Check each key's sender_id and delete if matches
        for key in keys {
            let mapping_json: Option<String> =
                conn.get(&key).await.context("Failed to get ACK mapping")?;

            if let Some(json) = mapping_json
                && let Ok(data) = serde_json::from_str::<serde_json::Value>(&json)
                && let Some(sender_id) = data["sender_id"].as_str()
                && sender_id == user_id
            {
                // Delete this key
                let _: i64 = conn
                    .del(&key)
                    .await
                    .context("Failed to delete ACK mapping")?;
                deleted_count += 1;
            }
        }

        tracing::info!(
            user_id = %user_id,
            deleted_count = deleted_count,
            "GDPR: Deleted delivery ACK records from Redis for user"
        );

        Ok(deleted_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // Note: These tests require a running PostgreSQL database
    // Run with: cargo test --features test-db

    #[tokio::test]
    #[ignore] // Requires database
    async fn test_save_and_find() {
        let pool = setup_test_db().await;
        let storage = PostgresDeliveryStorage::new(pool);

        let record = DeliveryPending {
            message_hash: "test_hash_123".to_string(),
            sender_id: "user_123".to_string(),
            expires_at: Utc::now() + Duration::days(7),
            created_at: Utc::now(),
        };

        storage.save(&record).await.unwrap();

        let found = storage
            .find_by_hash("test_hash_123")
            .await
            .unwrap()
            .expect("Record should exist");

        assert_eq!(found.message_hash, record.message_hash);
        assert_eq!(found.sender_id, record.sender_id);
    }

    #[tokio::test]
    #[ignore] // Requires database
    async fn test_delete_by_hash() {
        let pool = setup_test_db().await;
        let storage = PostgresDeliveryStorage::new(pool);

        let record = DeliveryPending {
            message_hash: "test_hash_456".to_string(),
            sender_id: "user_456".to_string(),
            expires_at: Utc::now() + Duration::days(7),
            created_at: Utc::now(),
        };

        storage.save(&record).await.unwrap();
        storage.delete_by_hash("test_hash_456").await.unwrap();

        let found = storage.find_by_hash("test_hash_456").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    #[ignore] // Requires database
    async fn test_delete_expired() {
        let pool = setup_test_db().await;
        let storage = PostgresDeliveryStorage::new(pool);

        // Create an expired record
        let expired_record = DeliveryPending {
            message_hash: "expired_hash".to_string(),
            sender_id: "user_789".to_string(),
            expires_at: Utc::now() - Duration::hours(1), // Already expired
            created_at: Utc::now() - Duration::days(8),
        };

        storage.save(&expired_record).await.unwrap();

        let deleted_count = storage.delete_expired().await.unwrap();
        assert!(deleted_count >= 1);

        let found = storage.find_by_hash("expired_hash").await.unwrap();
        assert!(found.is_none());
    }

    async fn setup_test_db() -> PgPool {
        // This is a placeholder - in real tests you'd set up a test database
        todo!("Set up test database connection")
    }
}
