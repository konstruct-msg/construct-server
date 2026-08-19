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
        // INSTANCE_DOMAIN is required by FederationConfig::from_env (no silent default).
        std::env::set_var("INSTANCE_DOMAIN", "test.local");
        // Valid throwaway crypto keys so the secret-hygiene fail-fast doesn't inherit a
        // malformed ambient value (e.g. hex SERVER_SIGNING_KEY → 48 bytes). Zeros are a
        // valid base64-32 seed / 64-hex issuer scalar; unused cryptographically here.
        std::env::set_var(
            "SERVER_SIGNING_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        std::env::set_var("TOKEN_ISSUER_KEY", "0".repeat(64));
        std::env::set_var("APNS_DEVICE_TOKEN_ENCRYPTION_KEY", "0".repeat(64));
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

// ============================================================================
// MessagePack envelope roundtrip (no Redis required)
// ============================================================================

#[test]
fn test_msg_envelope_msgpack_roundtrip() {
    use construct_message::types::{MessageEnvelope, ProtoEnvelopeContext};

    let ctx = ProtoEnvelopeContext {
        sender_id: "0a1c609f-b37d-4d67-b7b2-b0f8ec16d167".to_string(),
        recipient_id: "6f423adb-d731-4979-8a99-01a670b0df2c".to_string(),
        message_id: "2860d048-cca3-437f-9392-3d070846de94".to_string(),
        encrypted_payload: vec![0xAB; 200],
        content_type: 0,
    };
    let env = MessageEnvelope::from_proto_envelope(&ctx);

    // rmp_serde::to_vec uses the legacy serializer and cannot be read back by
    // from_slice for MessageEnvelope (wrong msgpack marker Str8).
    // delivery-worker and the read path both require encode::to_vec_named.
    let bytes = rmp_serde::encode::to_vec_named(&env).expect("to_vec_named");
    let back: MessageEnvelope = rmp_serde::from_slice(&bytes).expect("to_vec_named deserialize");
    assert_eq!(back.message_id, env.message_id);
    assert_eq!(back.recipient_id, env.recipient_id);

    // Document the broken path so nobody reintroduces it.
    let broken = rmp_serde::to_vec(&env).unwrap();
    assert!(
        rmp_serde::from_slice::<MessageEnvelope>(&broken).is_err(),
        "to_vec must remain incompatible — use to_vec_named for Redis streams"
    );
}

// ============================================================================
// Mailbox: the 2026-08-18 offline-loss incident, and the step-4 cutover
// ============================================================================
//
// These run against a real Redis because the thing that failed on 2026-08-18 was not
// a formula — every formula checked out. Two messages were written to an offline
// recipient, a client resumed from a cursor *below* both, and the read returned
// nothing. Deciding whether the entries had ever existed took hours, because no test
// ever put a message into Redis and asked for it back.
//
//   docker exec construct-redis-local redis-cli ping   # PONG
//   cargo test -p construct-queue --lib -- --ignored mailbox

/// A queue whose config is built in-process, so `mailbox_user_write` can be flipped
/// without touching `MSG_MAILBOX_USER_WRITE` — an env var is global to the test binary
/// and would race every other test running in parallel.
async fn mailbox_queue(user_write: bool) -> MessageQueue {
    let mut config = get_test_config();
    config.messaging.mailbox_user_write = user_write;
    MessageQueue::new(&config)
        .await
        .expect("Failed to build MessageQueue")
}

async fn clear_mailbox(queue: &mut MessageQueue, user_id: &str, device_ids: &[&str]) {
    let prefix = queue.delivery_queue_prefix.clone();
    let mut keys = vec![format!("{prefix}:offline:{user_id}")];
    keys.extend(
        device_ids
            .iter()
            .map(|d| format!("{prefix}:offline:{user_id}:{d}")),
    );
    for key in keys {
        let _: std::result::Result<i64, _> = redis::cmd("DEL")
            .arg(&key)
            .query_async(queue.client.connection_mut())
            .await;
    }
}

async fn stream_len(queue: &mut MessageQueue, key: &str) -> i64 {
    redis::cmd("XLEN")
        .arg(key)
        .query_async(queue.client.connection_mut())
        .await
        .expect("XLEN failed")
}

/// The incident, replayed. Recipient offline, two messages dispatched, client resumes
/// from a cursor below both.
///
/// Two assertions, and the second is the one that was missing. It is not enough that
/// the read returns both messages: a read that *also* deleted them would pass that,
/// and deleting them is precisely what the server used to do. So the stream is
/// measured afterwards. Reads are side-effect free or this test is red.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_offline_backlog_survives_a_read_from_a_lower_cursor() {
    let user = "test_mailbox_incident_recipient";
    let device = "test_mailbox_incident_device";
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[device]).await;

    let devices = vec![device.to_string()];
    let first =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    let second =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    queue
        .write_message_to_device_streams(user, &devices, &first)
        .await
        .expect("first dispatch");
    queue
        .write_message_to_device_streams(user, &devices, &second)
        .await
        .expect("second dispatch");

    // "0" is every cursor below the two entries at once — the resume position of a
    // client that has persisted nothing.
    let page = queue
        .read_mailbox_messages(user, Some(device), Some("0"), 50)
        .await
        .expect("read after resume");

    let ids: Vec<String> = page
        .entries
        .iter()
        .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.clone()))
        .collect();
    assert!(
        ids.contains(&first.message_id) && ids.contains(&second.message_id),
        "resume from a lower cursor must return both messages, got {ids:?}"
    );

    let device_key = format!(
        "{}:offline:{}:{}",
        queue.delivery_queue_prefix, user, device
    );
    let user_key = format!("{}:offline:{}", queue.delivery_queue_prefix, user);
    assert_eq!(
        stream_len(&mut queue, &device_key).await,
        2,
        "reading the mailbox must not delete from it"
    );
    assert_eq!(stream_len(&mut queue, &user_key).await, 2);

    clear_mailbox(&mut queue, user, &[device]).await;
}

/// Every device gets its own copy, and neither read empties the other's box — the
/// shared-mailbox loss that the per-device streams exist to remove.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_two_devices_each_receive_every_message() {
    let user = "test_mailbox_two_devices_user";
    let (d1, d2) = ("test_mbx_dev_a", "test_mbx_dev_b");
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[d1, d2]).await;

    let devices = vec![d1.to_string(), d2.to_string()];
    let mut sent = Vec::new();
    for _ in 0..3 {
        let env =
            construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
        queue
            .write_message_to_device_streams(user, &devices, &env)
            .await
            .expect("dispatch");
        sent.push(env.message_id);
    }

    for device in [d1, d2] {
        let page = queue
            .read_mailbox_messages(user, Some(device), Some("0"), 50)
            .await
            .expect("read");
        let ids: Vec<String> = page
            .entries
            .iter()
            .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.clone()))
            .collect();
        for id in &sent {
            assert!(ids.contains(id), "{device} missing {id}");
        }
        assert_eq!(
            page.user_only, 0,
            "{device}: full fan-out must leave nothing that only the user stream had"
        );
    }

    clear_mailbox(&mut queue, user, &[d1, d2]).await;
}

/// The cutover gate, shown failing. A message written while the device list was empty
/// reaches only the user stream; `user_only` is what makes that visible, and it is the
/// number that must be zero before `MSG_MAILBOX_USER_WRITE=0`.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_gate_counts_a_message_the_device_stream_never_got() {
    let user = "test_mailbox_gate_user";
    let device = "test_mbx_gate_dev";
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[device]).await;

    // Device list empty — the shape of a failed `fetch_recipient_device_ids`, or of a
    // device that registered after this message was sent.
    let missed =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    queue
        .write_message_to_device_streams(user, &[], &missed)
        .await
        .expect("dispatch with no devices still lands in the user stream");

    let page = queue
        .read_mailbox_messages(user, Some(device), Some("0"), 50)
        .await
        .expect("read");

    assert_eq!(
        page.user_only, 1,
        "the gate must see a delivered entry the device stream did not have"
    );

    clear_mailbox(&mut queue, user, &[device]).await;
}

/// After the cutover there is no user stream to fall back on, so a message with nowhere
/// to go must fail loudly. Returning `Ok` here is the silent loss the whole decision
/// exists to remove, arriving from the write side instead of the read side.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_cutover_refuses_a_message_with_nowhere_to_land() {
    let user = "test_mailbox_cutover_user";
    let mut queue = mailbox_queue(false).await;
    clear_mailbox(&mut queue, user, &[]).await;

    let env = construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    let result = queue.write_message_to_device_streams(user, &[], &env).await;

    assert!(
        result.is_err(),
        "no user stream and no devices must be an error, not a delivered message"
    );

    let user_key = format!("{}:offline:{}", queue.delivery_queue_prefix, user);
    assert_eq!(
        stream_len(&mut queue, &user_key).await,
        0,
        "cutover must not write the user stream"
    );
}

/// With the flag off the device streams are the whole mailbox, and they must still work.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_cutover_delivers_through_device_streams_only() {
    let user = "test_mailbox_cutover_ok_user";
    let device = "test_mbx_cutover_dev";
    let mut queue = mailbox_queue(false).await;
    clear_mailbox(&mut queue, user, &[device]).await;

    let env = construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    queue
        .write_message_to_device_streams(user, &[device.to_string()], &env)
        .await
        .expect("dispatch to a known device");

    let page = queue
        .read_mailbox_messages(user, Some(device), Some("0"), 50)
        .await
        .expect("read");
    let ids: Vec<String> = page
        .entries
        .iter()
        .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.clone()))
        .collect();
    assert!(ids.contains(&env.message_id), "device-only delivery failed");
    assert_eq!(page.user_only, 0);

    let user_key = format!("{}:offline:{}", queue.delivery_queue_prefix, user);
    assert_eq!(stream_len(&mut queue, &user_key).await, 0);

    clear_mailbox(&mut queue, user, &[device]).await;
}
