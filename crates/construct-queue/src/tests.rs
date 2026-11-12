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
        // Required since the secret-hygiene check covers it; without it no Redis test here ran.
        std::env::set_var("LOG_HASH_SALT", "test_log_hash_salt_unique_for_tests_only");
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

    let mut manager = delivery::DeliveryManager::new(&mut client, &config, "test:delivery:");

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

// ============================================================================
// SessionManager Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires Redis"]
async fn test_session_revoke_all() {
    use redis::AsyncCommands;
    let mut client = get_test_redis_client().await;
    let tag = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let uid = format!("session-revoke-{tag}");
    let other = format!("session-other-{tag}");
    let keys = [
        format!("session:{uid}:a"),
        format!("session:{uid}:b"),
        format!("session:{other}:a"),
    ];
    let index = format!("user_sessions:{uid}");
    let other_index = format!("user_sessions:{other}");
    for key in &keys {
        client.set_ex(key, "user", 300).await.unwrap();
    }
    let _: i64 = client
        .connection_mut()
        .sadd(&index, &[format!("{uid}:a"), format!("{uid}:b")])
        .await
        .unwrap();
    let _: i64 = client
        .connection_mut()
        .sadd(&other_index, format!("{other}:a"))
        .await
        .unwrap();
    let _: bool = client.connection_mut().expire(&index, 300).await.unwrap();
    let _: bool = client
        .connection_mut()
        .expire(&other_index, 300)
        .await
        .unwrap();
    sessions::SessionManager::new(&mut client)
        .revoke_all_sessions(&uid)
        .await
        .unwrap();
    let all_keys = [&keys[0], &keys[1], &index, &keys[2], &other_index];
    let mut present = [false; 5];
    for (i, key) in all_keys.iter().enumerate() {
        present[i] = client.exists(key).await.unwrap();
    }
    for key in all_keys {
        client.del(key).await.unwrap();
    }
    assert_eq!(present, [false, false, false, true, true]);
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
        recipient_device: None,
    };
    let env = MessageEnvelope::from_proto_envelope(&ctx);

    // rmp_serde::to_vec uses the legacy serializer and cannot be read back by
    // from_slice for MessageEnvelope (wrong msgpack marker Str8).
    // write and read paths both require encode::to_vec_named.
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

/// Cloning a queue must keep its boot-time config and shared Redis namespace, even after the
/// caller changes/drops its source Config or drops the original queue. Exercise the consumer,
/// not just the pointer representation: custom prefix, cutover flag, presence TTL and payload.
#[tokio::test]
#[ignore = "requires Redis"]
async fn mailbox_clone_preserves_config_snapshot_and_namespace() {
    let mut config = get_test_config();
    let prefix = format!("test:p6:clone:{}", std::process::id());
    config.delivery_queue_prefix = prefix.clone();
    config.redis_key_prefixes.user = format!("{prefix}:presence:");
    config.messaging.mailbox_user_write = false;
    config.session_ttl_days = 2;
    let presence_key = format!(
        "{}account:server_instance_id",
        config.redis_key_prefixes.user
    );
    let mut original = MessageQueue::new(&config).await.unwrap();
    let mut cloned = original.clone();
    assert!(
        Arc::ptr_eq(&original.config, &cloned.config),
        "queue clones must not deep-copy Config"
    );
    assert!(
        Arc::ptr_eq(
            &original.delivery_queue_prefix,
            &cloned.delivery_queue_prefix
        ),
        "queue clones must share the immutable prefix"
    );
    config.delivery_queue_prefix = "unused".into();
    config.redis_key_prefixes.user = "unused".into();
    config.messaging.mailbox_user_write = true;
    drop(config);

    original.delete_mailbox("account").await.unwrap();
    original
        .track_user_online("account", "instance")
        .await
        .unwrap();
    assert_eq!(
        cloned
            .get_user_server_instance("account")
            .await
            .unwrap()
            .as_deref(),
        Some("instance")
    );
    let mut conn = cloned.clone_redis_connection();
    let ttl: i64 = redis::cmd("TTL")
        .arg(&presence_key)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!((172_790..=172_800).contains(&ttl));
    let message = construct_message::MessageEnvelope::new_direct_message(
        "message".into(),
        "alice".into(),
        "account".into(),
        vec![0; 32],
        0,
        vec![0, 255, 128],
        String::new(),
    );
    let writes = cloned
        .write_message_to_device_streams("account", &["device".into()], &message)
        .await
        .unwrap();
    assert_eq!(
        writes.user_stream, None,
        "the source config mutation must not enable legacy writes"
    );
    assert_eq!(writes.device_streams, 1);
    assert!(writes.recipient_online);
    let page = original
        .read_mailbox_messages("account", Some("device"), None, None, 10)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(
        page.entries[0].1.as_ref().unwrap().encrypted_payload,
        [0, 255, 128]
    );
    assert_eq!(page.user_only(), 0);
    drop(original);
    assert!(!cloned.mailbox_user_write_enabled());
    let remaining = cloned
        .read_mailbox_messages("account", Some("device"), None, None, 10)
        .await
        .unwrap();
    assert_eq!(
        remaining.entries.len(),
        1,
        "a reader outlives the original handle"
    );
    cloned.untrack_user_online("account").await.unwrap();
    assert_eq!(
        cloned.get_user_server_instance("account").await.unwrap(),
        None
    );
    assert_eq!(cloned.delete_mailbox("account").await.unwrap(), 1);
    let keys = [
        presence_key,
        format!("{prefix}:offline:account"),
        format!("{prefix}:offline:account:device"),
    ];
    let left: usize = redis::cmd("EXISTS")
        .arg(&keys)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(left, 0);
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
        .read_mailbox_messages(user, Some(device), Some("0"), Some("0"), 50)
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

fn mailbox_page_snapshot(page: &MailboxPage) -> Vec<u8> {
    rmp_serde::encode::to_vec_named(&(
        &page.entries,
        &page.user_only_ids,
        page.sibling_skipped,
        &page.user_examined_through,
        page.has_more,
        page.resume_after(Some("0")),
    ))
    .unwrap()
}

/// Reference the old two-read transport while sharing the production parser and pure merge.
/// Explicit merge/UTF-8 assertions below and the pure merge tests remain independent oracles.
async fn sequential_mailbox_page(
    queue: &mut MessageQueue,
    user: &str,
    device: &str,
    since: Option<&str>,
    user_since: Option<&str>,
    count: usize,
) -> MailboxPage {
    let mut delivery = delivery::DeliveryManager::new(
        &mut queue.client,
        &queue.config,
        &queue.delivery_queue_prefix,
    );
    let device_entries = delivery
        .read_device_messages_from_stream(user, device, since, count.saturating_mul(2))
        .await
        .unwrap();
    let user_entries = delivery
        .read_user_messages_from_stream(user, user_since, count.saturating_mul(2))
        .await
        .unwrap();
    merge_mailbox_pages(
        device_entries,
        user_entries,
        count,
        count.saturating_mul(2),
        device,
    )
}

/// One actual XREAD must carry both independent offsets (or just the legacy offset for a
/// device-less reader). A scripted RESP server rejects the old single-source request shape.
#[tokio::test]
#[ignore = "scripted Redis exchange; run with mailbox integration tests"]
async fn mailbox_read_uses_one_xread_with_independent_source_offsets() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    async fn command(reader: &mut (impl tokio::io::AsyncBufRead + Unpin)) -> Vec<Vec<u8>> {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let count: usize = line.strip_prefix('*').unwrap().trim().parse().unwrap();
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let len: usize = line.strip_prefix('$').unwrap().trim().parse().unwrap();
            let mut arg = vec![0; len + 2];
            reader.read_exact(&mut arg).await.unwrap();
            assert_eq!(&arg[len..], b"\r\n");
            arg.truncate(len);
            args.push(arg);
        }
        args
    }
    for (device, fail) in [Some("reader"), None, Some("")]
        .into_iter()
        .flat_map(|device| [(device, false), (device, true)])
    {
        let expected: &[&str] = if device == Some("reader") {
            &[
                "XREAD",
                "COUNT",
                "4",
                "STREAMS",
                "delivery:offline:user:reader",
                "delivery:offline:user",
                "150-0",
                "300-0",
            ]
        } else {
            &[
                "XREAD",
                "COUNT",
                "2",
                "STREAMS",
                "delivery:offline:user",
                "150-0",
            ]
        };
        let expected: Vec<Vec<u8>> = expected.iter().map(|s| s.as_bytes().to_vec()).collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            loop {
                let args = command(&mut read).await;
                match args[0].as_slice() {
                    b"CLIENT" => write.write_all(b"+OK\r\n").await.unwrap(),
                    b"PING" => write.write_all(b"+PONG\r\n").await.unwrap(),
                    b"XREAD" => {
                        if args != expected {
                            write
                                .write_all(b"-ERR expected one correctly addressed XREAD\r\n")
                                .await
                                .unwrap();
                            panic!("XREAD arguments {args:?} != {expected:?}");
                        }
                        let reply: &[u8] = if fail {
                            b"-ERR injected mailbox read failure\r\n"
                        } else {
                            b"$-1\r\n"
                        };
                        write.write_all(reply).await.unwrap();
                        return;
                    }
                    other => panic!("unexpected command {other:?}"),
                }
            }
        });
        let mut config = get_test_config();
        config.redis_url = url;
        let mut queue = MessageQueue::new(&config).await.unwrap();
        let result = queue
            .read_mailbox_messages("user", device, Some("150"), Some("300-0"), 2)
            .await;
        if fail {
            let error = result.err().expect("a failed read is not an empty mailbox");
            assert!(error.to_string().contains("injected mailbox read failure"));
        } else {
            let page = result.unwrap();
            assert!(page.entries.is_empty());
            assert!(!page.has_more);
        }
        server.await.unwrap();
    }
}

/// Static mailboxes must give byte-for-byte identical pages, including both cursor positions,
/// corrupt-entry placeholders, sibling counts, coverage and has_more. Reads never alter XRANGE.
#[tokio::test]
#[ignore = "requires Redis"]
async fn mailbox_read_matches_separate_reads_with_independent_cursors() {
    use construct_message::MessageEnvelope;
    let user = format!("test_mailbox_read_equivalence_{}", std::process::id());
    let device = "reader";
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, &user, &[device]).await;
    let user_key = format!("{}:offline:{user}", queue.delivery_queue_prefix);
    let device_key = format!("{user_key}:{device}");
    let env = |id: &str| {
        let mut e = MessageEnvelope::new_key_sync("alice".into(), user.clone());
        e.message_id = id.to_string();
        e.encrypted_payload = vec![0, 255, 128];
        e
    };
    let mut sibling = env("sibling");
    sibling.recipient_device = Some("sibling-device".into());
    let mut wrong_recipient = env("wrong-recipient");
    wrong_recipient.recipient_id = "someone-else".into();
    for (key, rows) in [
        (
            &user_key,
            vec![
                ("100-0", env("shared")),
                ("200-0", env("user-only")),
                ("300-0", sibling),
                ("400-0", env("bad-utf8")),
                ("500-0", wrong_recipient),
            ],
        ),
        (
            &device_key,
            vec![
                ("150-0", env("shared")),
                ("250-0", env("device-only")),
                ("450-0", env("bad-payload")),
            ],
        ),
    ] {
        for (id, envelope) in rows {
            let message_id = if envelope.message_id == "bad-utf8" {
                vec![255u8]
            } else {
                envelope.message_id.as_bytes().to_vec()
            };
            let payload = if envelope.message_id == "bad-payload" {
                vec![255u8]
            } else {
                rmp_serde::encode::to_vec_named(&envelope).unwrap()
            };
            let _: String = redis::cmd("XADD")
                .arg(key)
                .arg(id)
                .arg("message_id")
                .arg(message_id)
                .arg("payload")
                .arg(payload)
                .query_async(queue.client.connection_mut())
                .await
                .unwrap();
        }
    }
    let before: redis::Value = redis::cmd("XRANGE")
        .arg(&user_key)
        .arg("-")
        .arg("+")
        .query_async(queue.client.connection_mut())
        .await
        .unwrap();
    for user_write in [true, false] {
        Arc::make_mut(&mut queue.config)
            .messaging
            .mailbox_user_write = user_write;
        for count in [0, 1, 2, 3, 20] {
            for (since, user_since) in [
                (None, None),
                (Some("0"), Some("0")),
                (Some("150-0"), Some("0")),
                (Some("0"), Some("300-0")),
                (Some("250"), Some("200")),
                (Some("not-an-id"), Some("invalid")),
                (Some("999-0"), Some("0")),
                (Some("0"), Some("999-0")),
                (Some("$"), Some("0")),
                (Some("0"), Some("$")),
            ] {
                let expected =
                    sequential_mailbox_page(&mut queue, &user, device, since, user_since, count)
                        .await;
                let actual = queue
                    .read_mailbox_messages(&user, Some(device), since, user_since, count)
                    .await
                    .unwrap();
                assert_eq!(
                    mailbox_page_snapshot(&actual),
                    mailbox_page_snapshot(&expected),
                    "count={count}, since={since:?}, user_since={user_since:?}, flag={user_write}"
                );
            }
        }
    }
    let page = queue
        .read_mailbox_messages(&user, Some(device), None, None, 20)
        .await
        .unwrap();
    assert_eq!(
        page.entries
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>(),
        ["150-0", "200-0", "250-0", "400-0", "450-0", "500-0"]
    );
    assert!(
        page.entries[3..].iter().all(|(_, e)| e.is_none()),
        "corrupt/wrong-recipient entries still advance"
    );
    assert_eq!(page.user_only_ids, ["user-only"]);
    assert_eq!(page.sibling_skipped, 1);
    assert_eq!(page.user_examined_through.as_deref(), Some("500-0"));
    assert!(!page.has_more);
    assert!(
        queue
            .read_mailbox_messages(&user, Some(device), Some("*"), None, 20)
            .await
            .is_err(),
        "a Redis cursor error must not become an empty mailbox"
    );
    for device in [None, Some("")] {
        let legacy = queue
            .read_mailbox_messages(&user, device, Some("200-0"), Some("999-0"), 20)
            .await
            .unwrap();
        assert_eq!(
            legacy
                .entries
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            ["300-0", "400-0", "500-0"]
        );
        assert!(legacy.user_only_ids.is_empty());
        assert_eq!(legacy.user_examined_through, None);
    }
    let after: redis::Value = redis::cmd("XRANGE")
        .arg(&user_key)
        .arg("-")
        .arg("+")
        .query_async(queue.client.connection_mut())
        .await
        .unwrap();
    assert_eq!(after, before, "reads are not retention");
    assert_eq!(stream_len(&mut queue, &device_key).await, 3);
    clear_mailbox(&mut queue, &user, &[device]).await;
}

/// A missing or wrong-type source is empty, not a reason to lose the healthy source. Empty
/// stream groups may be omitted/reordered by Redis, so source identity must not be positional.
#[tokio::test]
#[ignore = "requires Redis"]
async fn mailbox_read_keeps_the_healthy_source_when_its_peer_is_missing_or_wrongtype() {
    let user = format!("test_mailbox_read_fault_{}", std::process::id());
    let device = "reader";
    let mut queue = mailbox_queue(true).await;
    let user_key = format!("{}:offline:{user}", queue.delivery_queue_prefix);
    let device_key = format!("{user_key}:{device}");
    for (bad_device, wrongtype) in [(true, false), (false, false), (true, true), (false, true)] {
        clear_mailbox(&mut queue, &user, &[device]).await;
        let (bad, good) = if bad_device {
            (&device_key, &user_key)
        } else {
            (&user_key, &device_key)
        };
        if wrongtype {
            let _: () = redis::cmd("SET")
                .arg(bad)
                .arg("not a stream")
                .query_async(queue.client.connection_mut())
                .await
                .unwrap();
        }
        let envelope =
            construct_message::MessageEnvelope::new_key_sync("alice".into(), user.clone());
        let payload = rmp_serde::encode::to_vec_named(&envelope).unwrap();
        let _: String = redis::cmd("XADD")
            .arg(good)
            .arg("100-0")
            .arg("message_id")
            .arg(&envelope.message_id)
            .arg("payload")
            .arg(payload)
            .query_async(queue.client.connection_mut())
            .await
            .unwrap();
        let expected = sequential_mailbox_page(&mut queue, &user, device, None, None, 20).await;
        let actual = queue
            .read_mailbox_messages(&user, Some(device), None, None, 20)
            .await
            .unwrap();
        assert_eq!(
            mailbox_page_snapshot(&actual),
            mailbox_page_snapshot(&expected)
        );
        assert_eq!(actual.entries.len(), 1);
        assert_eq!(
            actual.entries[0].1.as_ref().unwrap().message_id,
            envelope.message_id
        );
        assert_eq!(actual.user_only(), usize::from(bad_device));
        assert_eq!(stream_len(&mut queue, good).await, 1);
    }
    clear_mailbox(&mut queue, &user, &[device]).await;
    let _: () = redis::pipe()
        .cmd("SET")
        .arg(&user_key)
        .arg("wrong type")
        .cmd("SET")
        .arg(&device_key)
        .arg("wrong type")
        .query_async(queue.client.connection_mut())
        .await
        .unwrap();
    let empty = queue
        .read_mailbox_messages(&user, Some(device), None, None, 20)
        .await
        .unwrap();
    assert!(empty.entries.is_empty());
    assert!(!empty.has_more);
    clear_mailbox(&mut queue, &user, &[device]).await;
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
            .read_mailbox_messages(user, Some(device), Some("0"), Some("0"), 50)
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
            page.user_only(),
            0,
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

    // Device list empty — the shape of a failed `fetch_recipient_device_ids_for_user`, or of a
    // device that registered after this message was sent.
    let missed =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    queue
        .write_message_to_device_streams(user, &[], &missed)
        .await
        .expect("dispatch with no devices still lands in the user stream");

    let page = queue
        .read_mailbox_messages(user, Some(device), Some("0"), Some("0"), 50)
        .await
        .expect("read");

    assert_eq!(
        page.user_only(),
        1,
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
        .read_mailbox_messages(user, Some(device), Some("0"), Some("0"), 50)
        .await
        .expect("read");
    let ids: Vec<String> = page
        .entries
        .iter()
        .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.clone()))
        .collect();
    assert!(ids.contains(&env.message_id), "device-only delivery failed");
    assert_eq!(page.user_only(), 0);

    let user_key = format!("{}:offline:{}", queue.delivery_queue_prefix, user);
    assert_eq!(stream_len(&mut queue, &user_key).await, 0);

    clear_mailbox(&mut queue, user, &[device]).await;
}

/// Sender-supplied `max_queue_len` (historically TrustLevel::New = 100) must not
/// trim the recipient's mailbox. Redis MAXLEN is whole-stream retention.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_xadd_ignores_sender_envelope_maxlen() {
    let user = "test_mailbox_maxlen_user";
    let device = "test_mailbox_maxlen_dev";
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[device]).await;

    let devices = vec![device.to_string()];
    for _ in 0..5 {
        let env =
            construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
        queue
            .write_message_to_device_streams(user, &devices, &env)
            .await
            .expect("fill");
    }

    let mut tiny =
        construct_message::types::MessageEnvelope::new_key_sync("mallory".into(), user.into());
    tiny.max_queue_len = Some(1);
    queue
        .write_message_to_device_streams(user, &devices, &tiny)
        .await
        .expect("write with attacker maxlen");

    let device_key = format!(
        "{}:offline:{}:{}",
        queue.delivery_queue_prefix, user, device
    );
    let user_key = format!("{}:offline:{}", queue.delivery_queue_prefix, user);
    assert!(
        stream_len(&mut queue, &device_key).await >= 6,
        "sender MAXLEN=1 must not trim the recipient device stream"
    );
    assert!(
        stream_len(&mut queue, &user_key).await >= 6,
        "sender MAXLEN=1 must not trim the recipient user stream"
    );

    clear_mailbox(&mut queue, user, &[device]).await;
}

/// The 2026-09-21 baseline through Redis: with the legacy user stream still written, an
/// envelope routed to one device used to arrive at its sibling as well, by way of the
/// user stream, and to count as `user_only` on the sibling's read. Now the sibling's
/// read neither delivers it nor counts it; the named device's read is unchanged.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_sibling_read_skips_an_envelope_named_to_the_other_device() {
    let user = "test_mailbox_sibling_user";
    let (d1, d2) = ("test_mbx_sib_a", "test_mbx_sib_b");
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[d1, d2]).await;

    // Routed to d1 alone, as dispatch_envelope does for a named recipient_device.
    let mut env =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    env.recipient_device = Some(d1.to_string());
    queue
        .write_message_to_device_streams(user, &[d1.to_string()], &env)
        .await
        .expect("dispatch to d1");

    let mine = queue
        .read_mailbox_messages(user, Some(d1), Some("0"), Some("0"), 50)
        .await
        .expect("d1 read");
    assert_eq!(mine.entries.len(), 1, "the named device gets it");
    assert_eq!(mine.user_only(), 0, "and from its own stream");
    assert_eq!(mine.sibling_skipped, 0);

    let theirs = queue
        .read_mailbox_messages(user, Some(d2), Some("0"), Some("0"), 50)
        .await
        .expect("d2 read");
    assert!(
        theirs.entries.is_empty(),
        "the sibling must not receive a copy it was never encrypted for, got {}",
        theirs.entries.len()
    );
    assert_eq!(
        theirs.user_only(),
        0,
        "a sibling's envelope is not a coverage failure"
    );
    assert_eq!(theirs.sibling_skipped, 1);

    clear_mailbox(&mut queue, user, &[d1, d2]).await;
}

/// The user stream holds every device's entries, so for a reader of a three-device account
/// most of a user-stream read is siblings', and it ends earlier in time than the read of the
/// reader's own stream. A page that delivered its own entries past that point moved the
/// cursor over user-stream entries nobody had read: an entry only the user stream has (a
/// dispatch that found no devices) behind such a backlog was never delivered. Paged as
/// `GetPendingMessages` pages — one cursor for both streams.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_a_user_only_entry_behind_a_sibling_backlog_reaches_a_paged_read() {
    let user = "test_mailbox_horizon_user";
    let (a, b, c) = ("test_mbx_hz_a", "test_mbx_hz_b", "test_mbx_hz_c");
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[a, b, c]).await;

    let named = |device: &str| {
        let mut env =
            construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
        env.recipient_device = Some(device.to_string());
        env
    };
    for _ in 0..3 {
        for sibling in [b, c] {
            queue
                .write_message_to_device_streams(user, &[sibling.to_string()], &named(sibling))
                .await
                .expect("dispatch to a sibling");
        }
    }
    let user_only =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    queue
        .write_message_to_device_streams(user, &[], &user_only)
        .await
        .expect("dispatch that found no devices");
    let mut expected = vec![user_only.message_id.clone()];
    for _ in 0..2 {
        let own = named(a);
        expected.push(own.message_id.clone());
        queue
            .write_message_to_device_streams(user, &[a.to_string()], &own)
            .await
            .expect("dispatch to the reader");
    }

    let mut delivered = Vec::new();
    let mut cursor = "0".to_string();
    for _ in 0..20 {
        let page = queue
            .read_mailbox_messages(user, Some(a), Some(&cursor), Some(&cursor), 2)
            .await
            .expect("read");
        delivered.extend(
            page.entries
                .iter()
                .filter_map(|(_, e)| e.as_ref().map(|e| e.message_id.clone())),
        );
        cursor = page
            .resume_after(Some(&cursor))
            .expect("a cursor to resume from");
        if !page.has_more {
            break;
        }
    }
    delivered.sort();
    // User/device ids are independent. A twin beyond this page's horizon can be
    // delivered again on the next page: the mailbox contract is at-least-once.
    delivered.dedup();
    expected.sort();
    assert_eq!(
        delivered, expected,
        "every entry for the reader, no sibling entries"
    );

    clear_mailbox(&mut queue, user, &[a, b, c]).await;
}

/// Account deletion empties every mailbox of the account — the user stream and each
/// device stream — and no one else's. Mutation: drop the SCAN for device streams and
/// the device mailbox survives; widen the pattern and the neighbour's goes too.
#[tokio::test]
#[ignore] // Requires Redis
async fn mailbox_delete_removes_every_stream_of_the_account_and_no_other() {
    let (gone, neighbour) = ("test_mailbox_delete_user", "test_mailbox_delete_user2");
    let (d1, d2) = ("test_mbx_del_a", "test_mbx_del_b");
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, gone, &[d1, d2]).await;
    clear_mailbox(&mut queue, neighbour, &[d1]).await;

    let env = construct_message::types::MessageEnvelope::new_key_sync("alice".into(), gone.into());
    queue
        .write_message_to_device_streams(gone, &[d1.to_string(), d2.to_string()], &env)
        .await
        .expect("dispatch");
    let other =
        construct_message::types::MessageEnvelope::new_key_sync("alice".into(), neighbour.into());
    queue
        .write_message_to_device_streams(neighbour, &[d1.to_string()], &other)
        .await
        .expect("dispatch neighbour");

    let deleted = queue.delete_mailbox(gone).await.expect("delete");
    assert_eq!(deleted, 3, "user stream + two device streams");

    let prefix = queue.delivery_queue_prefix.clone();
    for key in [
        format!("{prefix}:offline:{gone}"),
        format!("{prefix}:offline:{gone}:{d1}"),
        format!("{prefix}:offline:{gone}:{d2}"),
    ] {
        assert_eq!(stream_len(&mut queue, &key).await, 0, "{key} survived");
    }
    assert_eq!(
        stream_len(&mut queue, &format!("{prefix}:offline:{neighbour}:{d1}")).await,
        1,
        "another account's mailbox was touched"
    );

    clear_mailbox(&mut queue, neighbour, &[d1]).await;
}

/// What a device that was away too long is told (decisions/mailbox-gap-is-reported.md): entries
/// the age sweep trimmed after its cursor are a gap; entries it had already read, trimmed after,
/// are not; a stream that never lost an entry is not, however old the cursor. The sweep records
/// what it trims (XTRIM itself does not move `max-deleted-entry-id`).
#[tokio::test]
#[ignore] // Requires Redis 7 (XINFO STREAM, XSETID MAXDELETEDID)
async fn mailbox_gap_names_what_the_age_sweep_trimmed_after_the_cursor() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let user = "test_mailbox_gap_user";
    let device = "test_mailbox_gap_dev";
    let mut queue = mailbox_queue(false).await;
    clear_mailbox(&mut queue, user, &[device]).await;
    let key = format!(
        "{}:offline:{}:{}",
        queue.delivery_queue_prefix, user, device
    );
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Two a month old, two from now.
    let stamps = [
        1_700_000_000_000u64,
        1_700_000_001_000,
        now_ms - 2000,
        now_ms - 1000,
    ];
    let mut ids = Vec::new();
    for ms in stamps {
        let id: String = redis::cmd("XADD")
            .arg(&key)
            .arg(format!("{ms}-0"))
            .arg("payload")
            .arg("x")
            .query_async(queue.client.connection_mut())
            .await
            .expect("XADD failed");
        ids.push(id);
    }
    let before = "1699999999999-0";
    assert_eq!(
        queue.mailbox_gap(user, Some(device), before).await.unwrap(),
        None,
        "nothing deleted yet: an old cursor alone is no gap"
    );

    let removed = queue
        .trim_streams_by_age(crate::MAILBOX_MAX_AGE_DAYS * 86_400)
        .await
        .expect("age sweep failed");
    assert!(removed >= 2);

    let gap = queue
        .mailbox_gap(user, Some(device), before)
        .await
        .unwrap()
        .expect("trimmed after the cursor: a gap");
    assert_eq!(gap.after_cursor, before);
    assert_eq!(gap.resumes_at, ids[2]);

    assert_eq!(
        queue
            .mailbox_gap(user, Some(device), &ids[1])
            .await
            .unwrap(),
        None,
        "a device that had read up to the last trimmed entry lost nothing"
    );
    assert_eq!(
        queue
            .mailbox_gap("test_mailbox_gap_nobody", Some("none"), before)
            .await
            .unwrap(),
        None,
        "no stream at all is no gap"
    );

    clear_mailbox(&mut queue, user, &[device]).await;
}

#[tokio::test]
#[ignore] // Requires Redis
async fn push_outstanding_marks_once_until_cleared() {
    let config = get_test_config();
    let mut queue = MessageQueue::new(&config).await.expect("queue");
    let device = format!("test-device-{}", std::process::id());

    assert!(queue.try_mark_push_outstanding(&device).await.unwrap());
    assert!(!queue.try_mark_push_outstanding(&device).await.unwrap());
    queue.clear_push_outstanding(&device).await.unwrap();
    assert!(queue.try_mark_push_outstanding(&device).await.unwrap());

    // Bounded: the marker carries the documented TTL.
    let ttl: i64 = redis::cmd("TTL")
        .arg(push_outstanding_key(&device))
        .query_async(&mut queue.clone_redis_connection())
        .await
        .unwrap();
    assert!(ttl > 0 && ttl <= PUSH_OUTSTANDING_TTL_SECONDS as i64);
    queue.clear_push_outstanding(&device).await.unwrap();
}

/// A lock-free dedup read remains EXISTS, not GET: any stored value marks a retry, and reads
/// neither create a marker for a new message nor refresh one. Mutation: return false, or use GET.
#[tokio::test]
#[ignore = "requires Redis"]
async fn dedup_read_without_the_queue_preserves_exists_semantics() {
    let mut queue = MessageQueue::new(&get_test_config()).await.expect("queue");
    let mut conn = queue.clone_redis_connection();
    let key = MessageDedupKey::new(
        &format!("test_dedup_reader_{}", std::process::id()),
        "recipient",
        None,
        "message",
    );
    let _: () = redis::cmd("DEL")
        .arg(key.as_str())
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(!is_message_duplicate(&mut conn, &key).await.unwrap());
    assert!(!queue.is_message_duplicate(&key).await.unwrap());

    for (command, args) in [
        ("SET", vec![""]),
        ("SET", vec!["1"]),
        ("HSET", vec!["field", "value"]),
        ("LPUSH", vec!["value"]),
    ] {
        let _: () = redis::cmd("DEL")
            .arg(key.as_str())
            .query_async(&mut conn)
            .await
            .unwrap();
        let _: redis::Value = redis::cmd(command)
            .arg(key.as_str())
            .arg(args)
            .query_async(&mut conn)
            .await
            .unwrap();
        let _: bool = redis::cmd("EXPIRE")
            .arg(key.as_str())
            .arg(60)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(
            is_message_duplicate(&mut conn, &key).await.unwrap(),
            "{command}"
        );
        assert!(queue.is_message_duplicate(&key).await.unwrap(), "{command}");
        let ttl: i64 = redis::cmd("TTL")
            .arg(key.as_str())
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(ttl > 0 && ttl <= 60, "a read must not change retention");
    }
    let _: () = redis::cmd("DEL")
        .arg(key.as_str())
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(!is_message_duplicate(&mut conn, &key).await.unwrap());
}

// ============================================================================
// Access-token blocklist: one read, the same answer the two reads gave
// ============================================================================

/// The two markers read as a single `MGET` must answer exactly what the two `EXISTS` in sequence
/// answered, in every combination. The behaviour this replaced is the contract; the saved round
/// trip is only worth having if it changes nothing.
///
/// Mutation: read only the token slot, or drop the device slot — a row below flips. Mutation:
/// swap the two fields — the `(false, true)` row flips.
#[tokio::test]
#[ignore = "requires Redis"]
async fn blocklist_standing_answers_what_the_two_separate_reads_answered() {
    async fn put(conn: &mut redis::aio::ConnectionManager, key: &str) {
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg("1")
            .query_async(conn)
            .await
            .unwrap();
    }

    async fn clear(conn: &mut redis::aio::ConnectionManager, keys: &[String]) {
        let _: () = redis::cmd("DEL").arg(keys).query_async(conn).await.unwrap();
    }

    /// What the removed pair of `EXISTS` calls answered, asked the same way it was asked.
    async fn two_separate_reads(
        conn: &mut redis::aio::ConnectionManager,
        token_key: &str,
        device_key: &str,
        names_a_device: bool,
    ) -> (bool, bool) {
        let token: bool = redis::cmd("EXISTS")
            .arg(token_key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        let revoked: bool = if names_a_device {
            redis::cmd("EXISTS")
                .arg(device_key)
                .query_async(&mut *conn)
                .await
                .unwrap()
        } else {
            false
        };
        (token, revoked)
    }

    let config = get_test_config();
    let queue = MessageQueue::new(&config).await.expect("queue");
    let mut conn = queue.clone_redis_connection();
    let suffix = std::process::id();
    let jti = format!("test_blocklist_jti_{suffix}");
    let device = format!("test_blocklist_device_{suffix}");
    // Per-test keys on a shared Redis: no FLUSHDB.
    let token_key = invalidated_token_key(&jti);
    let device_key = revoked_device_key(&device);
    let keys = [token_key.clone(), device_key.clone()];

    for (token_set, device_set) in [(false, false), (true, false), (false, true), (true, true)] {
        clear(&mut conn, &keys).await;
        if token_set {
            put(&mut conn, &token_key).await;
        }
        if device_set {
            put(&mut conn, &device_key).await;
        }
        let expected = two_separate_reads(&mut conn, &token_key, &device_key, true).await;
        let standing = blocklist_standing(&mut conn, &jti, Some(&device))
            .await
            .expect("one read of two keys");
        assert_eq!(
            (standing.token_invalidated, standing.device_revoked),
            expected,
            "token set: {token_set}, device set: {device_set}"
        );
        assert_eq!(standing.is_revoked(), expected.0 || expected.1);
    }

    // A token that names no device asks about one key. The device marker is set below and must
    // not reach an answer about a token that never mentioned a device.
    clear(&mut conn, &keys).await;
    put(&mut conn, &device_key).await;
    for device_arg in [None, Some("")] {
        let standing = blocklist_standing(&mut conn, &jti, device_arg)
            .await
            .expect("one read of one key");
        assert!(
            !standing.is_revoked(),
            "a device that was not named cannot refuse a token ({device_arg:?})"
        );
    }

    clear(&mut conn, &keys).await;
}

// ============================================================================
// One fan-out, one round trip
// ============================================================================

/// A device stream that refuses the write costs that device its copy and nothing else. The other
/// mailboxes still get theirs, and the count the caller decides "nowhere to land" on is of writes
/// that landed — a count of attempts would call a refused write a delivery.
///
/// Mutation: fail the whole fan-out on the first refused `XADD` — the sibling's stream stays empty
/// and the send comes back an error.
#[tokio::test]
#[ignore = "requires Redis"]
async fn mailbox_a_refused_device_stream_costs_only_that_copy() {
    let user = "test_mailbox_one_bad_device_user";
    let (good, bad) = ("test_mbx_onebad_ok", "test_mbx_onebad_bad");
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[good, bad]).await;

    // A string where the device stream belongs: `XADD` answers WRONGTYPE for that key alone.
    let bad_key = format!("{}:offline:{}:{}", queue.delivery_queue_prefix, user, bad);
    let mut conn = queue.clone_redis_connection();
    let _: () = redis::cmd("SET")
        .arg(&bad_key)
        .arg("not-a-stream")
        .query_async(&mut conn)
        .await
        .unwrap();

    let env = construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    let writes = queue
        .write_message_to_device_streams(user, &[good.to_string(), bad.to_string()], &env)
        .await
        .expect("a refused copy is not the message's failure");

    assert_eq!(writes.device_streams, 1, "only the healthy device's write");
    assert_eq!(
        writes.user_stream,
        Some(true),
        "the legacy copy still landed"
    );
    assert!(!writes.recipient_online, "nobody is streaming this user");

    let good_key = format!("{}:offline:{}:{}", queue.delivery_queue_prefix, user, good);
    assert_eq!(stream_len(&mut queue, &good_key).await, 1);

    let _: () = redis::cmd("DEL")
        .arg(&bad_key)
        .query_async(&mut conn)
        .await
        .unwrap();
    clear_mailbox(&mut queue, user, &[good, bad]).await;
}

/// A fan-out still wakes the account's `inbox:wakeup` channel, and the entry is there when the
/// wakeup is read. Nothing else asserts the publish: the stream tests poll, so dropping the
/// `PUBLISH` would leave every connected client waiting for the fallback tick instead of
/// delivering at once — silently, and only visible as latency.
///
/// The wakeup runs after the writes because Redis executes a pipeline in the order it was sent;
/// that is the mechanism, not a race this test could observe from outside.
///
/// Mutation: drop the `PUBLISH` from the fan-out — this times out waiting for a wakeup that never
/// comes.
#[tokio::test]
#[ignore = "requires Redis"]
async fn mailbox_a_fan_out_wakes_the_account_channel_after_writing() {
    use tokio_stream::StreamExt;

    let user = "test_mailbox_wakeup_order_user";
    let device = "test_mbx_wakeup_dev";
    let mut queue = mailbox_queue(true).await;
    clear_mailbox(&mut queue, user, &[device]).await;

    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let client = redis::Client::open(url.as_str()).expect("redis client");
    let mut pubsub = client.get_async_pubsub().await.expect("pubsub");
    let channel = format!("inbox:wakeup:{user}");
    pubsub.subscribe(&channel).await.expect("subscribe");

    let env = construct_message::types::MessageEnvelope::new_key_sync("alice".into(), user.into());
    queue
        .write_message_to_device_streams(user, &[device.to_string()], &env)
        .await
        .expect("dispatch");

    let mut messages = pubsub.into_on_message();
    let wakeup = tokio::time::timeout(std::time::Duration::from_secs(5), messages.next())
        .await
        .expect("the fan-out must publish a wakeup")
        .expect("one message");
    assert_eq!(wakeup.get_channel_name(), channel);

    let device_key = format!(
        "{}:offline:{}:{}",
        queue.delivery_queue_prefix, user, device
    );
    assert_eq!(
        stream_len(&mut queue, &device_key).await,
        1,
        "the wakeup must not arrive before the entry"
    );

    clear_mailbox(&mut queue, user, &[device]).await;
}
