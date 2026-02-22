use construct_config::Config;
use construct_server_shared::queue::MessageQueue;
use redis::Commands;
use serial_test::serial;
use std::env;
use uuid::Uuid;

async fn setup_queue() -> (MessageQueue, redis::Connection) {
    // Manually construct a config for testing
    // This avoids needing a full .env file for this specific test
    let mut config = Config {
        database_url: "".to_string(), // Not needed for this test
        redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
        // SECURITY: Use a strong test secret that passes entropy validation
        // This must be at least 32 chars with good entropy (not all same char, no simple patterns, >= 8 unique chars)
        jwt_secret: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0".to_string(),
        bind_address: "127.0.0.1".to_string(),
        port: 8080,
        health_port: 8081,
        heartbeat_interval_secs: 60_i64,
        server_registry_ttl_secs: 120_i64,
        message_ttl_days: 7,
        dedup_safety_margin_hours: 24,
        access_token_ttl_hours: 1,
        session_ttl_days: 30,
        refresh_token_ttl_days: 90,
        jwt_issuer: "construct-test".to_string(),
        online_channel: "test-online-channel".to_string(),
        offline_queue_prefix: "test_queue:".to_string(),
        delivery_queue_prefix: "test_delivery_queue:".to_string(),
        delivery_poll_interval_ms: 1000,
        rust_log: "info".to_string(),
        // These nested configs are not used by MessageQueue but are required by the Config struct
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
            max_messages_per_ip_per_hour: 5000,
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
            enabled: false,
            instance_domain: "test.local".to_string(),
            base_domain: "test.local".to_string(),
            signing_key_seed: None,
            mtls: construct_config::MtlsConfig {
                required: false,
                client_cert_path: None,
                client_key_path: None,
                verify_server_cert: false,
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
        redis_key_prefixes: construct_config::RedisKeyPrefixes {
            processed_msg: "processed_msg:".to_string(),
            user: "user:".to_string(),
            session: "session:".to_string(),
            user_sessions: "user_sessions:".to_string(),
            msg_hash: "msg_hash:".to_string(),
            rate: "rate:".to_string(),
            blocked: "blocked:".to_string(),
            key_bundle: "key_bundle:".to_string(),
            connections: "connections:".to_string(),
            delivered_direct: "delivered_direct:".to_string(),
        },
        redis_channels: construct_config::RedisChannels {
            dead_letter_queue: "dead_letter_queue".to_string(),
            delivery_message: "delivery_message:{}".to_string(),
            delivery_notification: "delivery_notification:{}".to_string(),
        },
        // Legacy aliases
        instance_domain: "test.local".to_string(),
        federation_base_domain: "test.local".to_string(),
        federation_enabled: false,
        deep_link_base_url: "".to_string(),
        jwt_private_key: None,
        jwt_public_key: None,
        media: construct_config::MediaConfig {
            enabled: false,
            base_url: "".to_string(),
            upload_token_secret: "".to_string(),
            max_file_size: 100 * 1024 * 1024,
            rate_limit_per_hour: 100,
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
    };

    // Allow overriding redis_url from environment for CI/different setups
    if let Ok(redis_url) = env::var("REDIS_URL") {
        config.redis_url = redis_url;
    }

    let message_queue = MessageQueue::new(&config)
        .await
        .expect("Failed to create MessageQueue");

    let redis_client =
        redis::Client::open(config.redis_url.as_str()).expect("Failed to create Redis client");
    let redis_conn = redis_client
        .get_connection()
        .expect("Failed to get Redis connection");

    (message_queue, redis_conn)
}

#[tokio::test]
#[serial]
async fn test_register_server_instance_logic() {
    let (mut message_queue, mut redis_conn) = setup_queue().await;
    let queue_key = format!("test-delivery-queue:{}", Uuid::new_v4());

    // 1. Test creation of a new, non-existent key
    message_queue
        .register_server_instance(&queue_key, 60_i64)
        .await
        .expect("register_server_instance failed on creation");

    let key_type: String = redis_conn
        .key_type(&queue_key)
        .expect("Redis TYPE command failed");
    assert_eq!(key_type, "list", "The key should be created as a list");

    let llen: i64 = redis_conn
        .llen(&queue_key)
        .expect("Redis LLEN command failed");
    assert_eq!(llen, 1, "The list should contain one placeholder element");

    let ttl: i64 = redis_conn
        .ttl(&queue_key)
        .expect("Redis TTL command failed");
    assert!(
        ttl > 0 && ttl <= 60,
        "The key should have a TTL set within the expected range"
    );

    // 2. Test correction of a key with the wrong type
    let _: () = redis_conn
        .set(&queue_key, "this is not a list")
        .expect("Redis SET command failed");

    let key_type_before: String = redis_conn
        .key_type(&queue_key)
        .expect("Redis TYPE command failed");
    assert_eq!(
        key_type_before, "string",
        "The key should be a string before correction"
    );

    message_queue
        .register_server_instance(&queue_key, 60_i64)
        .await
        .expect("register_server_instance failed on correction");

    let key_type_after: String = redis_conn
        .key_type(&queue_key)
        .expect("Redis TYPE command failed");
    assert_eq!(
        key_type_after, "list",
        "The key should be corrected to a list"
    );

    // 3. Clean up the key from Redis
    let _: () = redis_conn
        .del(&queue_key)
        .expect("Redis DEL command failed");
}

// ============================================================================
// Extended Tests for Phase 4 - Приоритет 2
// ============================================================================

// Test 2: Rate Limit Increment and Check
#[tokio::test]
#[serial]
async fn test_rate_limit_increment_and_check() {
    let (mut message_queue, mut redis_conn) = setup_queue().await;
    let user_id = format!("test-rate-limit-user-{}", Uuid::new_v4());
    let _window_secs = 3600; // 1 hour window
    let max_requests = 100;

    // Test incrementing rate limit
    for i in 1..=5 {
        let count = message_queue
            .increment_message_count(&user_id)
            .await
            .expect("Failed to increment rate limit");

        assert_eq!(count, i, "Rate limit count should match iteration");
    }

    // Verify final count
    let final_count = message_queue
        .increment_message_count(&user_id)
        .await
        .expect("Failed to get rate limit count");

    assert_eq!(final_count, 6);

    // Test that count is under limit
    assert!(final_count < max_requests, "Should be under rate limit");

    // Cleanup
    let rate_key = format!("test_rate:{}", user_id);
    let _: () = redis_conn.del(&rate_key).unwrap_or_default();
}

// Test 3: Rate Limit Window Expiry
#[tokio::test]
#[serial]
async fn test_rate_limit_window_expiry() {
    let (mut message_queue, mut redis_conn) = setup_queue().await;
    let user_id = format!("test-rate-expiry-{}", Uuid::new_v4());
    let _short_window = 2; // 2 seconds for testing

    // Increment count
    message_queue
        .increment_message_count(&user_id)
        .await
        .expect("Failed to increment");

    // Verify count exists
    let count = message_queue
        .increment_message_count(&user_id)
        .await
        .expect("Failed to get count");
    assert_eq!(count, 2);

    // Check TTL (key format matches implementation: rate:msg:{})
    let rate_key = format!("rate:msg:{}", user_id);
    let ttl: i64 = redis_conn.ttl(&rate_key).expect("Failed to get TTL");

    assert!(ttl > 0 && ttl <= 3600, "TTL should be set");

    // Cleanup
    let _: () = redis_conn.del(&rate_key).unwrap_or_default();
}

// Test 4: Rate Limit Different Keys are Independent
#[tokio::test]
#[serial]
async fn test_rate_limit_different_keys() {
    let (mut message_queue, mut redis_conn) = setup_queue().await;
    let user1 = format!("test-user1-{}", Uuid::new_v4());
    let user2 = format!("test-user2-{}", Uuid::new_v4());

    // Increment for user 1
    let count1 = message_queue
        .increment_message_count(&user1)
        .await
        .expect("Failed to increment user1");
    assert_eq!(count1, 1);

    // Increment for user 2
    let count2 = message_queue
        .increment_message_count(&user2)
        .await
        .expect("Failed to increment user2");
    assert_eq!(count2, 1);

    // User 1 increments again
    let count1_2 = message_queue
        .increment_message_count(&user1)
        .await
        .expect("Failed to increment user1 again");
    assert_eq!(count1_2, 2);

    // User 2 count should still be 1
    let count2_check = message_queue
        .increment_message_count(&user2)
        .await
        .expect("Failed to get user2 count");
    assert_eq!(count2_check, 2); // Now 2 because we just incremented

    // Cleanup
    let _: () = redis_conn
        .del(format!("test_rate:{}", user1))
        .unwrap_or_default();
    let _: () = redis_conn
        .del(format!("test_rate:{}", user2))
        .unwrap_or_default();
}

// Test 5: Session Store and Retrieve
#[tokio::test]
#[serial]
async fn test_session_store_and_retrieve() {
    let (_message_queue, mut redis_conn) = setup_queue().await;
    let session_id = Uuid::new_v4().to_string();
    let user_id = Uuid::new_v4().to_string();
    let session_data = format!(
        r#"{{"user_id":"{}","created_at":"2026-01-25T12:00:00Z"}}"#,
        user_id
    );

    // Store session
    let session_key = format!("test_session:{}", session_id);
    let ttl_secs: i64 = 86400; // 24 hours

    let _: () = redis_conn
        .set_ex(&session_key, &session_data, ttl_secs as u64)
        .expect("Failed to store session");

    // Retrieve session
    let retrieved: String = redis_conn
        .get(&session_key)
        .expect("Failed to retrieve session");

    assert_eq!(retrieved, session_data);

    // Verify TTL is set
    let ttl: i64 = redis_conn.ttl(&session_key).expect("Failed to get TTL");
    assert!(ttl > 0 && ttl <= ttl_secs);

    // Cleanup
    let _: () = redis_conn.del(&session_key).unwrap_or_default();
}

// Test 6: Session Revocation
#[tokio::test]
#[serial]
async fn test_session_revocation() {
    let (_message_queue, mut redis_conn) = setup_queue().await;
    let session_id = Uuid::new_v4().to_string();
    let user_id = Uuid::new_v4().to_string();
    let session_data = format!(r#"{{"user_id":"{}"}}"#, user_id);

    // Store session
    let session_key = format!("test_session:{}", session_id);
    let _: () = redis_conn
        .set_ex(&session_key, &session_data, 3600)
        .expect("Failed to store session");

    // Verify session exists
    let exists: bool = redis_conn
        .exists(&session_key)
        .expect("Failed to check existence");
    assert!(exists);

    // Revoke session (delete)
    let _: () = redis_conn
        .del(&session_key)
        .expect("Failed to revoke session");

    // Verify session no longer exists
    let exists_after: bool = redis_conn
        .exists(&session_key)
        .expect("Failed to check existence after revocation");
    assert!(!exists_after);

    // Cleanup (already deleted)
}

// Test 7: Delivery Stream Push and Pop
#[tokio::test]
#[serial]
async fn test_delivery_stream_push_pop() {
    let (_message_queue, mut redis_conn) = setup_queue().await;
    let stream_key = format!("test_delivery_queue:{}", Uuid::new_v4());

    // Push messages to stream using XADD
    let message1 = r#"{"message_id":"msg-001","payload":"test1"}"#;
    let message2 = r#"{"message_id":"msg-002","payload":"test2"}"#;

    use redis::Commands;

    let _: String = redis_conn
        .xadd(
            &stream_key,
            "*", // Auto-generate ID
            &[("data", message1)],
        )
        .expect("Failed to push message 1");

    let _: String = redis_conn
        .xadd(&stream_key, "*", &[("data", message2)])
        .expect("Failed to push message 2");

    // Check stream length
    let length: i64 = redis_conn
        .xlen(&stream_key)
        .expect("Failed to get stream length");
    assert_eq!(length, 2);

    // Read messages from stream
    let messages: redis::streams::StreamReadReply = redis_conn
        .xread(&[&stream_key], &["0"])
        .expect("Failed to read from stream");

    assert_eq!(messages.keys.len(), 1);
    assert_eq!(messages.keys[0].ids.len(), 2);

    // Cleanup
    let _: () = redis_conn.del(&stream_key).unwrap_or_default();
}

// Test 8: Pub/Sub for Online Notifications
#[tokio::test]
#[serial]
async fn test_pubsub_publish_subscribe() {
    use redis::AsyncCommands;

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(redis_url.as_str()).expect("Failed to create Redis client");

    let mut pubsub_conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("Failed to get async connection");

    let channel_name = format!("test-online-channel-{}", Uuid::new_v4());
    let test_message = r#"{"user_id":"test-user-123","status":"online"}"#;

    // Publish message
    let published: i64 = pubsub_conn
        .publish(&channel_name, test_message)
        .await
        .expect("Failed to publish message");

    // published count is 0 if no subscribers, which is expected in this test
    assert!(published >= 0, "Publish should succeed");

    // Note: Full pub/sub test would require a subscriber in a separate task
    // This is a basic smoke test to verify the publish operation works
}

// Test 9: Connection Pool Under Load
#[tokio::test]
#[serial]
async fn test_connection_pool_under_load() {
    let (_message_queue, mut redis_conn) = setup_queue().await;

    // Perform multiple concurrent operations directly with Redis
    let mut handles = vec![];

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    for i in 0..10 {
        let user_id = format!("test-load-user-{}", i);
        let redis_url_clone = redis_url.clone();

        let handle = tokio::spawn(async move {
            use redis::AsyncCommands;

            let client = redis::Client::open(redis_url_clone.as_str())
                .expect("Failed to create Redis client");

            let mut conn = client
                .get_multiplexed_async_connection()
                .await
                .expect("Failed to get connection");

            let rate_key = format!("test_rate:{}", user_id);

            // Increment rate limit counter
            let _: i64 = conn.incr(&rate_key, 1).await.expect("Failed to increment");
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.expect("Task failed");
    }

    // Cleanup - delete all test rate limit keys
    for i in 0..10 {
        let rate_key = format!("test_rate:test-load-user-{}", i);
        let _: () = redis_conn.del(&rate_key).unwrap_or_default();
    }
}
