// ============================================================================
// Redis Queue Module Tests
// ============================================================================
// Priority 2 tests for DeliveryManager, SessionManager, and RateLimiter
// These tests ensure the Redis migration is complete and working

use super::*;
use construct_config::Config;
use construct_redis::RedisClient;

// ============================================================================
// Test Helpers
// ============================================================================

async fn get_test_redis_client() -> RedisClient {
    RedisClient::connect("redis://localhost:6379")
        .await
        .expect("Failed to connect to Redis")
}

fn get_test_config() -> Config {
    // Create minimal test config - unsafe block required for env vars in tests
    unsafe {
        std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
        std::env::set_var("REDIS_URL", "redis://localhost:6379");
        std::env::set_var("JWT_SECRET", "test_secret_key_for_testing_only_32bytes!");
    }

    Config::from_env().expect("Failed to create test config")
}

// ============================================================================
// DeliveryManager Tests
// ============================================================================

#[tokio::test]
#[ignore] // Requires Redis
async fn test_delivery_track_user_online() {
    let mut client = get_test_redis_client().await;
    let config = get_test_config();

    let user_id = "test_delivery_user_001";
    let server_id = "test_server_001";

    let mut manager =
        delivery::DeliveryManager::new(&mut client, &config, "test:delivery:".to_string());

    // Track user online
    manager
        .track_user_online(user_id, server_id)
        .await
        .expect("Failed to track user online");

    // Verify tracking
    let instance = manager
        .get_user_server_instance(user_id)
        .await
        .expect("Failed to get server instance");

    assert_eq!(instance, Some(server_id.to_string()));

    // Untrack
    manager
        .untrack_user_online(user_id)
        .await
        .expect("Failed to untrack user");

    // Verify untracked
    let instance_after = manager
        .get_user_server_instance(user_id)
        .await
        .expect("Failed to get instance after untrack");

    assert_eq!(instance_after, None);
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_delivery_mark_delivered() {
    let mut client = get_test_redis_client().await;
    let config = get_test_config();

    // Use timestamp to ensure unique message ID
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let message_id = format!("test_msg_delivery_{}", timestamp);

    let mut manager =
        delivery::DeliveryManager::new(&mut client, &config, "test:delivery:".to_string());

    // Initially not delivered
    let is_delivered = manager
        .is_delivered_direct(&message_id)
        .await
        .expect("Failed to check delivery");

    assert!(!is_delivered, "Message should not be delivered initially");

    // Mark delivered
    manager
        .mark_delivered_direct(&message_id)
        .await
        .expect("Failed to mark delivered");

    // Verify delivered
    let is_delivered_after = manager
        .is_delivered_direct(&message_id)
        .await
        .expect("Failed to check delivery after mark");

    assert!(
        is_delivered_after,
        "Message should be delivered after marking"
    );

    // Cleanup
    let key = format!("delivered:direct:{}", message_id);
    client.del(&key).await.ok();
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_delivery_register_server_instance() {
    let mut client = get_test_redis_client().await;
    let config = get_test_config();

    let queue_key = "test:server:instance:001";

    let mut manager =
        delivery::DeliveryManager::new(&mut client, &config, "test:delivery:".to_string());

    // Register server instance
    manager
        .register_server_instance(queue_key, 60)
        .await
        .expect("Failed to register server instance");

    // Verify key exists with TTL
    use redis::AsyncCommands; // Needed for exists() method
    let exists: bool = client
        .connection_mut()
        .exists(queue_key)
        .await
        .expect("Failed to check key existence");

    assert!(exists);

    // Cleanup
    client.del(queue_key).await.ok();
}

// ============================================================================
// SessionManager Tests
// ============================================================================

#[tokio::test]
#[ignore] // Requires Redis
async fn test_session_create_and_validate() {
    let mut client = get_test_redis_client().await;

    let jti = "test_session_jti_001";
    let user_id = "test_user_001";
    let ttl = 3600;

    let mut manager = sessions::SessionManager::new(&mut client);

    // Create session
    manager
        .create_session(jti, user_id, ttl)
        .await
        .expect("Failed to create session");

    // Validate session
    let validated_user = manager
        .validate_session(jti)
        .await
        .expect("Failed to validate session");

    assert_eq!(validated_user, Some(user_id.to_string()));

    // Cleanup
    manager.revoke_session(jti, user_id).await.ok();
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_session_revoke() {
    let mut client = get_test_redis_client().await;

    let jti = "test_session_jti_002";
    let user_id = "test_user_002";
    let ttl = 3600;

    let mut manager = sessions::SessionManager::new(&mut client);

    // Create session
    manager
        .create_session(jti, user_id, ttl)
        .await
        .expect("Failed to create session");

    // Revoke session
    manager
        .revoke_session(jti, user_id)
        .await
        .expect("Failed to revoke session");

    // Verify revoked
    let validated_user = manager
        .validate_session(jti)
        .await
        .expect("Failed to validate after revoke");

    assert_eq!(validated_user, None);
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_session_revoke_all() {
    let mut client = get_test_redis_client().await;

    let user_id = "test_user_003";
    let jti1 = "test_session_jti_003_1";
    let jti2 = "test_session_jti_003_2";
    let jti3 = "test_session_jti_003_3";
    let ttl = 3600;

    let mut manager = sessions::SessionManager::new(&mut client);

    // Create multiple sessions
    manager
        .create_session(jti1, user_id, ttl)
        .await
        .expect("Failed to create session 1");
    manager
        .create_session(jti2, user_id, ttl)
        .await
        .expect("Failed to create session 2");
    manager
        .create_session(jti3, user_id, ttl)
        .await
        .expect("Failed to create session 3");

    // Verify all exist
    assert_eq!(
        manager.validate_session(jti1).await.unwrap(),
        Some(user_id.to_string())
    );
    assert_eq!(
        manager.validate_session(jti2).await.unwrap(),
        Some(user_id.to_string())
    );
    assert_eq!(
        manager.validate_session(jti3).await.unwrap(),
        Some(user_id.to_string())
    );

    // Revoke all
    manager
        .revoke_all_sessions(user_id)
        .await
        .expect("Failed to revoke all sessions");

    // Verify all revoked
    assert_eq!(manager.validate_session(jti1).await.unwrap(), None);
    assert_eq!(manager.validate_session(jti2).await.unwrap(), None);
    assert_eq!(manager.validate_session(jti3).await.unwrap(), None);
}

// ============================================================================
// RateLimiter Tests
// ============================================================================

#[tokio::test]
#[ignore] // Requires Redis
async fn test_rate_limit_check() {
    let mut client = get_test_redis_client().await;

    let key = "test_rate_limit_001";
    let max_requests = 5;
    let window_seconds = 10;

    let mut manager = rate_limiting::RateLimiter::new(&mut client);

    // First requests should succeed
    for i in 1..=max_requests {
        let count = manager
            .increment_rate_limit(key, window_seconds)
            .await
            .expect("Failed to increment rate limit");

        assert_eq!(count, i as i64, "Count should be {}", i);
    }

    // Next request should exceed limit
    let count = manager
        .increment_rate_limit(key, window_seconds)
        .await
        .expect("Failed to increment rate limit");

    assert_eq!(count, (max_requests + 1) as i64);

    // Cleanup
    let full_key = format!("rate:{}", key);
    client.del(&full_key).await.ok();
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_rate_limit_message_count() {
    let mut client = get_test_redis_client().await;

    let user_id = "test_user_rate_002";
    let max_per_hour = 10;

    let mut manager = rate_limiting::RateLimiter::new(&mut client);

    // Send messages up to limit
    for i in 1..=max_per_hour {
        let count = manager
            .increment_message_count(user_id)
            .await
            .expect("Failed to increment message count");

        assert_eq!(count, i, "Message count should be {}", i);
    }

    // Verify count
    let final_count = manager
        .get_message_count_last_hour(user_id)
        .await
        .expect("Failed to get message count");

    assert_eq!(final_count, max_per_hour);

    // Cleanup
    let key = format!("rate:msg:{}", user_id);
    client.del(&key).await.ok();
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_rate_limit_failed_login() {
    let mut client = get_test_redis_client().await;

    let username = "test_user_login_003";
    let max_attempts = 5;

    let mut manager = rate_limiting::RateLimiter::new(&mut client);

    // Simulate failed logins
    for i in 1..=max_attempts {
        let count = manager
            .increment_failed_login_count(username)
            .await
            .expect("Failed to increment login count");

        assert_eq!(count, i, "Login attempt count should be {}", i);
    }

    // Reset after successful login
    manager
        .reset_failed_login_count(username)
        .await
        .expect("Failed to reset login count");

    // Next attempt should be 1 again
    let count = manager
        .increment_failed_login_count(username)
        .await
        .expect("Failed to increment after reset");

    assert_eq!(count, 1);

    // Cleanup
    let key = format!("rate:login:{}", username);
    client.del(&key).await.ok();
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_rate_limit_ip_blocking() {
    let mut client = get_test_redis_client().await;

    let ip = "192.168.1.100";

    let mut manager = rate_limiting::RateLimiter::new(&mut client);

    // Increment IP counter
    for i in 1..=5 {
        let count = manager
            .increment_ip_message_count(ip)
            .await
            .expect("Failed to increment IP count");

        assert_eq!(count, i, "IP count should be {}", i);
    }

    // Cleanup
    let key = format!("rate:ip:{}", ip);
    client.del(&key).await.ok();
}

#[tokio::test]
#[ignore] // Requires Redis
async fn test_user_blocking() {
    let mut client = get_test_redis_client().await;

    let user_id = "test_blocked_user_004";
    let reason = "Too many failed login attempts";
    let duration = 60;

    let mut manager = rate_limiting::RateLimiter::new(&mut client);

    // Block user
    manager
        .block_user_temporarily(user_id, duration, reason)
        .await
        .expect("Failed to block user");

    // Verify blocked
    let blocked_reason = manager
        .is_user_blocked(user_id)
        .await
        .expect("Failed to check if user is blocked");

    assert_eq!(blocked_reason, Some(reason.to_string()));

    // Cleanup
    let key = format!("blocked:{}", user_id);
    client.del(&key).await.ok();
}
