// ============================================================================
// Delivery Worker Integration Tests
// ============================================================================
//
// Integration tests for delivery worker modules.
// These tests require a Redis instance (local or test container).
//
// Run with: cargo test --test delivery_worker_test -- --ignored
// (Tests are marked with #[ignore] to skip unless Redis is available)
//
// ============================================================================

use construct_config::{Config, RedisKeyPrefixes};
use construct_server_shared::delivery_worker::{deduplication, redis_streams, state::WorkerState};
use redis::cmd;
use serial_test::serial;
use std::env;
use std::sync::Arc;

/// Helper to create test WorkerState with test prefixes
/// Uses same pattern as queue_test.rs for consistency
async fn create_test_state() -> WorkerState {
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client =
        redis::Client::open(redis_url.as_str()).expect("Failed to create Redis client for tests");

    let conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to create Redis connection for tests");

    // Create config similar to queue_test.rs
    let config = Config {
        database_url: "".to_string(), // Not needed for these tests
        redis_url: redis_url.clone(),
        jwt_secret: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0".to_string(),
        bind_address: "127.0.0.1".to_string(),
        port: 8080,
        health_port: 8081,
        heartbeat_interval_secs: 180,
        server_registry_ttl_secs: 270,
        message_ttl_days: 7,
        dedup_safety_margin_hours: 24,
        access_token_ttl_hours: 1,
        session_ttl_days: 30,
        refresh_token_ttl_days: 90,
        jwt_issuer: "construct-test".to_string(),
        online_channel: "test-online-channel".to_string(),
        offline_queue_prefix: "test_queue:".to_string(),
        delivery_queue_prefix: "test_delivery_queue".to_string(),
        delivery_poll_interval_ms: 30000,
        rust_log: "info".to_string(),
        logging: construct_config::LoggingConfig {
            enable_message_metadata: false,
            enable_user_identifiers: false,
            hash_salt: "test-salt-that-is-super-secret".to_string(),
        },
        security: construct_config::SecurityConfig {
            prekey_ttl_days: 30,
            prekey_min_ttl_days: 7,
            prekey_max_ttl_days: 90,
            max_messages_per_hour: 1000,
            max_messages_per_ip_per_hour: 1000,
            max_key_rotations_per_day: 10,
            max_password_changes_per_day: 5,
            max_failed_login_attempts: 5,
            max_connections_per_user: 5,
            key_bundle_cache_hours: 1,
            rate_limit_block_duration_seconds: 3600,
            ip_rate_limiting_enabled: true,
            max_requests_per_ip_per_hour: 1000,
            combined_rate_limiting_enabled: true,
            max_requests_per_user_ip_per_hour: 500,
            max_long_poll_requests_per_window: 100,
            long_poll_rate_limit_window_secs: 60,
            request_signing_required: false,
            metrics_auth_enabled: false,
            metrics_ip_whitelist: vec![],
            metrics_bearer_token: None,
            max_pow_challenges_per_hour: 5,
            max_registrations_per_hour: 3,
            pow_difficulty: 1, // Low difficulty for tests
        },
        kafka: construct_config::KafkaConfig {
            enabled: false,
            brokers: "".to_string(),
            topic: "".to_string(),
            consumer_group: "".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            producer_compression: "none".to_string(),
            producer_acks: "1".to_string(),
            producer_linger_ms: 0,
            producer_batch_size: 0,
            producer_max_in_flight: 0,
            producer_retries: 0,
            producer_request_timeout_ms: 0,
            producer_delivery_timeout_ms: 0,
            producer_enable_idempotence: false,
        },
        apns: construct_config::ApnsConfig {
            enabled: false,
            environment: construct_config::ApnsEnvironment::Development,
            key_path: "".to_string(),
            key_id: "".to_string(),
            team_id: "".to_string(),
            bundle_id: "".to_string(),
            topic: "".to_string(),
            device_token_encryption_key:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        },
        federation: construct_config::FederationConfig {
            instance_domain: "test.local".to_string(),
            base_domain: "test.local".to_string(),
            enabled: false,
            signing_key_seed: None,
            mtls: construct_config::MtlsConfig {
                required: false,
                client_cert_path: None,
                client_key_path: None,
                verify_server_cert: true,
                pinned_certs: std::collections::HashMap::new(),
            },
        },
        db: construct_config::DbConfig {
            max_connections: 10,
            acquire_timeout_secs: 30,
            idle_timeout_secs: 600,
        },
        deeplinks: construct_config::DeepLinksConfig {
            apple_team_id: "".to_string(),
            android_package_name: "".to_string(),
            android_cert_fingerprint: "".to_string(),
        },
        worker: construct_config::WorkerConfig {
            shadow_read_enabled: false,
        },
        redis_key_prefixes: RedisKeyPrefixes {
            processed_msg: "test_processed_msg:".to_string(),
            user: "test_user:".to_string(),
            session: "test_session:".to_string(),
            user_sessions: "test_user_sessions:".to_string(),
            msg_hash: "test_msg_hash:".to_string(),
            rate: "test_rate:".to_string(),
            blocked: "test_blocked:".to_string(),
            key_bundle: "test_key_bundle:".to_string(),
            connections: "test_connections:".to_string(),
            delivered_direct: "test_delivered_direct:".to_string(),
        },
        redis_channels: construct_config::RedisChannels {
            dead_letter_queue: "test_dlq".to_string(),
            delivery_message: "test_delivery_message".to_string(),
            delivery_notification: "test_delivery_notification".to_string(),
        },
        media: construct_config::MediaConfig {
            enabled: false,
            base_url: "".to_string(),
            upload_token_secret: "".to_string(),
            max_file_size: 100 * 1024 * 1024,
            rate_limit_per_hour: 50,
        },
        microservices: construct_config::MicroservicesConfig {
            enabled: false,
            auth_service_url: "http://localhost:8001".to_string(),
            messaging_service_url: "http://localhost:8002".to_string(),
            user_service_url: "http://localhost:8003".to_string(),
            notification_service_url: "http://localhost:8004".to_string(),
            discovery_mode: "static".to_string(),
            service_timeout_secs: 30,
            circuit_breaker: construct_config::CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 2,
                timeout_secs: 60,
            },
        },
        csrf: construct_config::CsrfConfig {
            enabled: false, // Disabled for tests
            secret: "test-csrf-secret-at-least-32-characters".to_string(),
            token_ttl_secs: 3600,
            allowed_origins: vec![],
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
        },
        instance_domain: "test.local".to_string(),
        federation_base_domain: "test.local".to_string(),
        federation_enabled: false,
        deep_link_base_url: "https://test.local".to_string(),
        jwt_private_key: None,
        jwt_public_key: None,
    };

    WorkerState::new(Arc::new(config), client, conn)
}

/// Cleanup test keys from Redis
async fn cleanup_test_keys(state: &WorkerState, pattern: &str) {
    let mut conn = state.redis_conn.write().await;
    let keys: Vec<String> = cmd("KEYS")
        .arg(pattern)
        .query_async(&mut *conn)
        .await
        .unwrap_or_default();

    if !keys.is_empty() {
        let _: () = cmd("DEL")
            .arg(&keys)
            .query_async(&mut *conn)
            .await
            .unwrap_or_default();
    }
}

#[tokio::test]
#[serial]
#[ignore] // Requires Redis - run with: cargo test --test delivery_worker_test -- --ignored
async fn test_deduplication_mark_and_check() {
    let state = create_test_state().await;
    let message_id = "test-dedup-001";

    // Cleanup before test
    cleanup_test_keys(&state, "test_processed_msg:*").await;

    // Message should not be processed initially
    assert!(
        !deduplication::is_message_processed(&state, message_id)
            .await
            .unwrap()
    );

    // Mark as processed
    deduplication::mark_message_processed(&state, message_id, 3600)
        .await
        .unwrap();

    // Message should now be processed
    assert!(
        deduplication::is_message_processed(&state, message_id)
            .await
            .unwrap()
    );

    // Cleanup after test
    cleanup_test_keys(&state, "test_processed_msg:*").await;
}

#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_deduplication_should_skip() {
    let state = create_test_state().await;
    let message_id = "test-dedup-002";

    // Cleanup before test
    cleanup_test_keys(&state, "test_processed_msg:*").await;
    cleanup_test_keys(&state, "test_delivered_direct:*").await;

    // New message should not be skipped
    assert!(
        deduplication::should_skip_message(&state, message_id)
            .await
            .unwrap()
            .is_none()
    );

    // Mark as processed
    deduplication::mark_message_processed(&state, message_id, 3600)
        .await
        .unwrap();

    // Message should now be skipped
    assert_eq!(
        deduplication::should_skip_message(&state, message_id)
            .await
            .unwrap(),
        Some("already_processed")
    );

    // Cleanup after test
    cleanup_test_keys(&state, "test_processed_msg:*").await;
}

#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_redis_streams_push_to_delivery_stream() {
    let state = create_test_state().await;
    let stream_key = "test_delivery_queue:test-server-001";
    let message_id = "test-msg-001";
    let message_bytes = b"test message payload";

    // Cleanup before test
    cleanup_test_keys(&state, "test_delivery_queue:*").await;

    // Push message to stream
    let stream_id = redis_streams::push_to_delivery_stream(
        &state,
        stream_key,
        message_id,
        message_bytes,
        Some(1000), // max_len
    )
    .await
    .unwrap();

    // Stream ID should be returned (format: timestamp-sequence)
    assert!(!stream_id.is_empty());
    assert!(stream_id.contains('-'));

    // Verify message is in stream (check stream length)
    let mut conn = state.redis_conn.write().await;
    let length: i64 = cmd("XLEN")
        .arg(stream_key)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(length, 1);

    // Cleanup after test
    cleanup_test_keys(&state, "test_delivery_queue:*").await;
}

#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_redis_streams_check_user_online() {
    let state = create_test_state().await;
    let user_id = "test-user-001";
    let server_instance_id = "test-server-001";
    let user_server_key = format!("test_user:{}:server_instance_id", user_id);

    // Cleanup before test
    cleanup_test_keys(&state, "test_user:*").await;

    // User should be offline initially
    assert!(
        redis_streams::check_user_online(&state, user_id)
            .await
            .unwrap()
            .is_none()
    );

    // Set user online
    let mut conn = state.redis_conn.write().await;
    let _: () = cmd("SETEX")
        .arg(&user_server_key)
        .arg(3600)
        .arg(server_instance_id)
        .query_async(&mut *conn)
        .await
        .unwrap();

    // User should now be online
    let online_server = redis_streams::check_user_online(&state, user_id)
        .await
        .unwrap();
    assert_eq!(online_server, Some(server_instance_id.to_string()));

    // Cleanup after test
    cleanup_test_keys(&state, "test_user:*").await;
}

// ============================================================================
// Extended Tests for Phase 4 - Приоритет 1
// ============================================================================

// Test 5: Message Delivery to Online User
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_message_delivery_to_online_user() {
    let state = create_test_state().await;
    let user_id = "test-user-online-001";
    let server_instance_id = "test-server-001";
    let message_id = "test-msg-online-001";
    let message_bytes = b"test online message";
    let user_server_key = format!("test_user:{}:server_instance_id", user_id);

    // Cleanup before test
    cleanup_test_keys(&state, "test_user:*").await;
    cleanup_test_keys(&state, "test_delivery_queue:*").await;

    // Mark user as online
    let mut conn = state.redis_conn.write().await;
    let _: () = cmd("SETEX")
        .arg(&user_server_key)
        .arg(3600)
        .arg(server_instance_id)
        .query_async(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    // Check if user is online
    let online_server = redis_streams::check_user_online(&state, user_id)
        .await
        .unwrap();

    assert_eq!(online_server, Some(server_instance_id.to_string()));

    // Push message to the user's delivery stream
    let stream_key = format!("test_delivery_queue:{}", server_instance_id);
    let stream_id = redis_streams::push_to_delivery_stream(
        &state,
        &stream_key,
        message_id,
        message_bytes,
        Some(1000),
    )
    .await
    .unwrap();

    assert!(!stream_id.is_empty());

    // Verify message in stream
    let mut conn = state.redis_conn.write().await;
    let length: i64 = cmd("XLEN")
        .arg(&stream_key)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(length, 1);

    // Cleanup
    cleanup_test_keys(&state, "test_user:*").await;
    cleanup_test_keys(&state, "test_delivery_queue:*").await;
}

// Test 6: Message Delivery to Offline User (Save to Redis Streams)
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_message_delivery_to_offline_user() {
    let state = create_test_state().await;
    let user_id = "test-user-offline-001";
    let message_id = "test-msg-offline-001";

    // Cleanup before test
    cleanup_test_keys(&state, "test_user:*").await;
    cleanup_test_keys(&state, "test_queue:*").await;

    // User should be offline
    let online_server = redis_streams::check_user_online(&state, user_id)
        .await
        .unwrap();
    assert_eq!(online_server, None);

    // Message should be saved to offline queue (not delivery stream)
    // Simulate saving to offline queue
    let offline_queue_key = format!("test_queue:{}", user_id);
    let mut conn = state.redis_conn.write().await;
    let _: () = cmd("LPUSH")
        .arg(&offline_queue_key)
        .arg(message_id)
        .query_async(&mut *conn)
        .await
        .unwrap();

    // Verify message in offline queue
    let queue_length: i64 = cmd("LLEN")
        .arg(&offline_queue_key)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(queue_length, 1);

    // Cleanup
    cleanup_test_keys(&state, "test_queue:*").await;
}

// Test 7: Delivery Retry on Failure
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_delivery_retry_on_failure() {
    let state = create_test_state().await;
    let message_id = "test-msg-retry-001";

    // Cleanup before test
    cleanup_test_keys(&state, "test_processed_msg:*").await;
    cleanup_test_keys(&state, "test_retry:*").await;

    // Simulate retry counter in Redis
    let retry_key = format!("test_retry:{}", message_id);
    let mut conn = state.redis_conn.write().await;

    // First attempt (retry count = 0)
    let retry_count: i64 = cmd("INCR")
        .arg(&retry_key)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(retry_count, 1);

    // Second attempt (retry count = 1)
    let retry_count: i64 = cmd("INCR")
        .arg(&retry_key)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert_eq!(retry_count, 2);

    // Set TTL for retry counter (expires after 1 hour)
    let _: () = cmd("EXPIRE")
        .arg(&retry_key)
        .arg(3600)
        .query_async(&mut *conn)
        .await
        .unwrap();

    // Verify TTL is set
    let ttl: i64 = cmd("TTL")
        .arg(&retry_key)
        .query_async(&mut *conn)
        .await
        .unwrap();
    assert!(ttl > 0 && ttl <= 3600);

    // Cleanup
    cleanup_test_keys(&state, "test_retry:*").await;
}

// Test 8: Dead Letter Handling (Max Retries Exceeded)
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_dead_letter_handling() {
    let state = create_test_state().await;
    let message_id = "test-msg-dead-001";
    let max_retries = 3;

    // Cleanup before test
    cleanup_test_keys(&state, "test_retry:*").await;
    cleanup_test_keys(&state, "dead_letter_queue").await;

    let retry_key = format!("test_retry:{}", message_id);
    let mut conn = state.redis_conn.write().await;

    // Simulate max retries exceeded
    for _ in 0..max_retries {
        let _: i64 = cmd("INCR")
            .arg(&retry_key)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    let retry_count: i64 = cmd("GET")
        .arg(&retry_key)
        .query_async(&mut *conn)
        .await
        .unwrap();

    assert_eq!(retry_count, max_retries);

    // If retries exceeded, push to dead letter queue
    if retry_count >= max_retries {
        let dlq_payload = serde_json::json!({
            "message_id": message_id,
            "retry_count": retry_count,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let _: () = cmd("PUBLISH")
            .arg("dead_letter_queue")
            .arg(dlq_payload.to_string())
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    // Cleanup
    cleanup_test_keys(&state, "test_retry:*").await;
}

// Test 9: Batch Processing Multiple Messages
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_batch_processing_multiple_messages() {
    let state = create_test_state().await;
    let stream_key = "test_delivery_queue:batch-server-001";

    // Cleanup before test
    cleanup_test_keys(&state, "test_delivery_queue:*").await;

    // Push multiple messages in batch
    let message_ids: Vec<&str> = vec![
        "batch-msg-001",
        "batch-msg-002",
        "batch-msg-003",
        "batch-msg-004",
        "batch-msg-005",
    ];

    for (idx, message_id) in message_ids.iter().enumerate() {
        let message_bytes = format!("batch message {}", idx + 1);
        redis_streams::push_to_delivery_stream(
            &state,
            stream_key,
            message_id,
            message_bytes.as_bytes(),
            Some(1000),
        )
        .await
        .unwrap();
    }

    // Verify all messages in stream
    let mut conn = state.redis_conn.write().await;
    let length: i64 = cmd("XLEN")
        .arg(stream_key)
        .query_async(&mut *conn)
        .await
        .unwrap();

    assert_eq!(length, 5);

    // Cleanup
    cleanup_test_keys(&state, "test_delivery_queue:*").await;
}

// Test 10: Deduplication Window Expiry
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_deduplication_window_expiry() {
    let state = create_test_state().await;
    let message_id = "test-dedup-expiry-001";
    let ttl_seconds: i64 = 2; // Short TTL for testing

    // Cleanup before test
    cleanup_test_keys(&state, "test_processed_msg:*").await;

    // Mark as processed with short TTL
    deduplication::mark_message_processed(&state, message_id, ttl_seconds)
        .await
        .unwrap();

    // Should be processed immediately
    assert!(
        deduplication::is_message_processed(&state, message_id)
            .await
            .unwrap()
    );

    // Wait for expiry
    tokio::time::sleep(tokio::time::Duration::from_secs(ttl_seconds as u64 + 1)).await;

    // Should no longer be processed (expired)
    assert!(
        !deduplication::is_message_processed(&state, message_id)
            .await
            .unwrap()
    );

    // Cleanup
    cleanup_test_keys(&state, "test_processed_msg:*").await;
}

// Test 11: Concurrent Delivery to Same Recipient
#[tokio::test]
#[serial]
#[ignore] // Requires Redis
async fn test_concurrent_delivery_same_recipient() {
    let state = Arc::new(create_test_state().await);
    let stream_key = "test_delivery_queue:concurrent-server-001";

    // Cleanup before test
    cleanup_test_keys(&state, "test_delivery_queue:*").await;

    // Simulate concurrent message sends
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let state_clone = Arc::clone(&state);
            let stream_key = stream_key.to_string();
            tokio::spawn(async move {
                let message_id = format!("concurrent-msg-{:03}", i);
                let message_bytes = format!("concurrent payload {}", i);

                redis_streams::push_to_delivery_stream(
                    &state_clone,
                    &stream_key,
                    &message_id,
                    message_bytes.as_bytes(),
                    Some(1000),
                )
                .await
                .unwrap()
            })
        })
        .collect();

    // Wait for all concurrent sends
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all 10 messages in stream
    let mut conn = state.redis_conn.write().await;
    let length: i64 = cmd("XLEN")
        .arg(stream_key)
        .query_async(&mut *conn)
        .await
        .unwrap();

    assert_eq!(length, 10);

    // Cleanup
    cleanup_test_keys(&state, "test_delivery_queue:*").await;
}

// Test 12: Kafka Consumer Receives Message (Placeholder)
// NOTE: This test requires Kafka infrastructure
// For now, we'll create a placeholder that can be implemented when Kafka is available
#[tokio::test]
#[serial]
#[ignore] // Requires Kafka
async fn test_kafka_consumer_receives_message() {
    // This test should:
    // 1. Start a test Kafka consumer
    // 2. Produce a message to the test topic
    // 3. Verify consumer receives the message
    // 4. Verify message format (MessageEnvelope)

    // TODO: Implement when Kafka integration is ready
    // For now, we'll skip this test
    println!("Kafka integration test - to be implemented in Phase 5+");
}
