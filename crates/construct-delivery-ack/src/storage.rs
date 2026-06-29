use super::models::DeliveryPending;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Storage interface for delivery pending records
///
/// This trait allows for multiple implementations:
/// - PostgreSQL (current)
/// - Redis (for better performance)
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
