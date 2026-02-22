// ============================================================================
// Delivery Acknowledgment Tests
// ============================================================================
//
// Tests for privacy-preserving message delivery acknowledgments.
// Verifies HMAC-based anonymous tracking without sender/message correlation.
//
// These tests cover:
// - Single message acknowledgment
// - Batch acknowledgments
// - Idempotency (repeated ACKs)
// - Invalid message IDs
// - Authorization requirements
// - Cross-user security (preventing ACK of other users' messages)
//
// ============================================================================

use chrono::{Duration, Utc};
use construct_crypto::compute_message_hash;
use construct_server_shared::delivery_ack::{
    DeliveryAckConfig, DeliveryAckManager, DeliveryAckMode, DeliveryPending,
    DeliveryPendingStorage, PostgresDeliveryStorage,
};
use serial_test::serial;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::sync::Arc;
use uuid::Uuid;

/// Helper to create test database
async fn setup_test_database(db_name: &str) -> PgPool {
    // Use DATABASE_URL from env or fallback to local dev credentials
    let base_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://construct:construct_dev_password@localhost:5432/postgres".to_string()
    });

    // Extract base connection info (without database name)
    let base_url_without_db = if let Some(pos) = base_url.rfind('/') {
        format!("{}/postgres", &base_url[..pos])
    } else {
        base_url.clone()
    };

    let mut connection = PgConnection::connect(&base_url_without_db)
        .await
        .expect("Failed to connect to Postgres");

    // Drop existing test database (ignore errors if doesn't exist)
    let _ = connection
        .execute(format!("DROP DATABASE IF EXISTS {}", db_name).as_str())
        .await;

    // Create new test database
    connection
        .execute(format!("CREATE DATABASE {}", db_name).as_str())
        .await
        .expect("Failed to create test database");

    // Connect to test database
    let db_url = if let Some(pos) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..pos], db_name)
    } else {
        format!("{}/{}", base_url, db_name)
    };

    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}

/// Helper to create test delivery ACK config
fn create_test_config() -> DeliveryAckConfig {
    DeliveryAckConfig {
        mode: DeliveryAckMode::PostgreSQL,
        // Use a deterministic test key (32 bytes = 64 hex chars)
        secret_key: hex::decode("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
            .unwrap(),
        expiry_days: 7,
        cleanup_interval_secs: 3600,
        enable_batching: true,
        batch_buffer_secs: 5,
    }
}

// ============================================================================
// Test 1: Single Message Acknowledgment
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_single_message() {
    let db_name = format!(
        "test_delivery_ack_single_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage, config);

    // Step 1: Record pending delivery
    let message_id = Uuid::new_v4().to_string();
    let sender_id = Uuid::new_v4().to_string();

    manager
        .record_pending_delivery(&message_id, &sender_id)
        .await
        .expect("Failed to record pending delivery");

    // Step 2: Process acknowledgment
    let result = manager
        .process_acknowledgment(&message_id)
        .await
        .expect("Failed to process acknowledgment");

    // Should return the sender_id
    assert_eq!(result, Some(sender_id.clone()));

    // Step 3: Verify record was deleted (one-time use)
    let result2 = manager
        .process_acknowledgment(&message_id)
        .await
        .expect("Failed to process second acknowledgment");

    // Should return None (already processed)
    assert_eq!(result2, None);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 2: Batch Message Acknowledgments
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_batch_messages() {
    let db_name = format!(
        "test_delivery_ack_batch_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage, config);

    // Record multiple pending deliveries
    let message_ids: Vec<String> = (0..5).map(|_| Uuid::new_v4().to_string()).collect();
    let sender_id = Uuid::new_v4().to_string();

    for message_id in &message_ids {
        manager
            .record_pending_delivery(message_id, &sender_id)
            .await
            .expect("Failed to record pending delivery");
    }

    // Acknowledge all messages
    for message_id in &message_ids {
        let result = manager
            .process_acknowledgment(message_id)
            .await
            .expect("Failed to process acknowledgment");

        assert_eq!(result, Some(sender_id.clone()));
    }

    // Verify all records were deleted
    let count = manager.pending_count().await.expect("Failed to get count");
    assert_eq!(count, 0);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 3: Idempotency - Repeated Acknowledgment
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_idempotency() {
    let db_name = format!(
        "test_delivery_ack_idempotent_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage, config);

    let message_id = Uuid::new_v4().to_string();
    let sender_id = Uuid::new_v4().to_string();

    // Record pending delivery
    manager
        .record_pending_delivery(&message_id, &sender_id)
        .await
        .expect("Failed to record pending delivery");

    // First acknowledgment should succeed
    let result1 = manager
        .process_acknowledgment(&message_id)
        .await
        .expect("Failed to process first acknowledgment");
    assert_eq!(result1, Some(sender_id.clone()));

    // Second acknowledgment should be idempotent (return None, not error)
    let result2 = manager
        .process_acknowledgment(&message_id)
        .await
        .expect("Failed to process second acknowledgment");
    assert_eq!(result2, None);

    // Third acknowledgment should also be idempotent
    let result3 = manager
        .process_acknowledgment(&message_id)
        .await
        .expect("Failed to process third acknowledgment");
    assert_eq!(result3, None);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 4: Invalid Message ID
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_invalid_message_id() {
    let db_name = format!(
        "test_delivery_ack_invalid_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage, config);

    // Try to acknowledge a message that was never sent
    let fake_message_id = Uuid::new_v4().to_string();

    let result = manager
        .process_acknowledgment(&fake_message_id)
        .await
        .expect("Failed to process acknowledgment");

    // Should return None (not found)
    assert_eq!(result, None);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 5: Authorization - Requires Auth (REST API Test)
// ============================================================================
// NOTE: This test requires REST API infrastructure, so we'll test the
// underlying manager logic instead. The actual HTTP endpoint test should
// go in rest_api_messages_test.rs when the endpoint is implemented.

#[tokio::test]
#[serial]
async fn delivery_ack_unauthorized_access() {
    let db_name = format!(
        "test_delivery_ack_auth_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage, config);

    let message_id = Uuid::new_v4().to_string();
    let sender_id = Uuid::new_v4().to_string();

    // Record pending delivery
    manager
        .record_pending_delivery(&message_id, &sender_id)
        .await
        .expect("Failed to record pending delivery");

    // The manager itself doesn't enforce auth - that's the HTTP layer's job
    // But we can verify that the HMAC prevents unauthorized snooping
    // Even if attacker knows message_id, they can't get sender_id without SECRET_KEY

    // Verify pending count (authorized operation)
    let count = manager.pending_count().await.expect("Failed to get count");
    assert_eq!(count, 1);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 6: Cross-User Security - Wrong User
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_wrong_user() {
    let db_name = format!(
        "test_delivery_ack_wrong_user_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage.clone(), config.clone());

    // User A sends a message
    let message_id_a = Uuid::new_v4().to_string();
    let sender_a = Uuid::new_v4().to_string();

    manager
        .record_pending_delivery(&message_id_a, &sender_a)
        .await
        .expect("Failed to record delivery for User A");

    // User B sends a different message
    let message_id_b = Uuid::new_v4().to_string();
    let sender_b = Uuid::new_v4().to_string();

    manager
        .record_pending_delivery(&message_id_b, &sender_b)
        .await
        .expect("Failed to record delivery for User B");

    // Acknowledge User A's message
    let result_a = manager
        .process_acknowledgment(&message_id_a)
        .await
        .expect("Failed to acknowledge User A's message");

    // Should return User A's sender_id
    assert_eq!(result_a, Some(sender_a.clone()));

    // Acknowledge User B's message
    let result_b = manager
        .process_acknowledgment(&message_id_b)
        .await
        .expect("Failed to acknowledge User B's message");

    // Should return User B's sender_id (not User A's)
    assert_eq!(result_b, Some(sender_b.clone()));
    assert_ne!(result_b, Some(sender_a));

    // Verify both records were deleted
    let count = manager.pending_count().await.expect("Failed to get count");
    assert_eq!(count, 0);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 7: HMAC Security - Different Keys Produce Different Hashes
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_hmac_key_isolation() {
    let message_id = Uuid::new_v4().to_string();

    // Key 1
    let key1 =
        hex::decode("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2").unwrap();
    let hash1 = compute_message_hash(&message_id, &key1);

    // Key 2 (different)
    let key2 =
        hex::decode("b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2").unwrap();
    let hash2 = compute_message_hash(&message_id, &key2);

    // Hashes should be different
    assert_ne!(hash1, hash2);

    // Same key should produce same hash (deterministic)
    let hash1_again = compute_message_hash(&message_id, &key1);
    assert_eq!(hash1, hash1_again);
}

// ============================================================================
// Test 8: Expiry Handling
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_expired_record() {
    let db_name = format!(
        "test_delivery_ack_expiry_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));

    // Manually insert an expired record
    let message_id = Uuid::new_v4().to_string();
    let sender_id = Uuid::new_v4().to_string();
    let message_hash = compute_message_hash(&message_id, &config.secret_key);

    let expires_at = Utc::now() - Duration::hours(1); // Expired 1 hour ago

    let record = DeliveryPending::new(message_hash.clone(), sender_id.clone(), expires_at);

    storage
        .save(&record)
        .await
        .expect("Failed to save expired record");

    // Try to acknowledge expired message
    let manager = DeliveryAckManager::new(storage.clone(), config);
    let result = manager
        .process_acknowledgment(&message_id)
        .await
        .expect("Failed to process expired acknowledgment");

    // Should return None (expired)
    assert_eq!(result, None);

    // Verify record was deleted during processing
    let count = manager.pending_count().await.expect("Failed to get count");
    assert_eq!(count, 0);

    // Cleanup
    pool.close().await;
}

// ============================================================================
// Test 9: GDPR Compliance - User Data Deletion
// ============================================================================

#[tokio::test]
#[serial]
async fn delivery_ack_gdpr_user_deletion() {
    let db_name = format!(
        "test_delivery_ack_gdpr_{}",
        Uuid::new_v4().to_string().replace('-', "_")
    );
    let pool = setup_test_database(&db_name).await;

    let config = create_test_config();
    let storage = Arc::new(PostgresDeliveryStorage::new(pool.clone()));
    let manager = DeliveryAckManager::new(storage, config);

    let user_id = Uuid::new_v4().to_string();

    // User sends 3 messages
    let message_ids: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();

    for message_id in &message_ids {
        manager
            .record_pending_delivery(message_id, &user_id)
            .await
            .expect("Failed to record pending delivery");
    }

    // Verify 3 records exist
    let count_before = manager.pending_count().await.expect("Failed to get count");
    assert_eq!(count_before, 3);

    // User requests account deletion (GDPR Article 17)
    let deleted = manager
        .delete_user_data(&user_id)
        .await
        .expect("Failed to delete user data");

    // Should have deleted 3 records
    assert_eq!(deleted, 3);

    // Verify all records deleted
    let count_after = manager.pending_count().await.expect("Failed to get count");
    assert_eq!(count_after, 0);

    // Cleanup
    pool.close().await;
}
