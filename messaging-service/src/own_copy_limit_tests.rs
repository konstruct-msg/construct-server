//! A copy to one of the sender's own devices against the Sentinel limits (todo/277). Live Redis
//! and Postgres: what is checked is the counters. A missing service skips on a laptop and fails
//! under CI, as in `sealed_matrix_tests`.

use construct_config::MessagingConfig;
use construct_server_shared::sentinel_service::{
    OWN_COPY_LIMIT_HOUR, SendPermission, SentinelCore,
};
use redis::AsyncCommands;
use serial_test::serial;
use uuid::Uuid;

use crate::core::{is_own_copy, send_permission};
use crate::trust::{TrustLevel, check_send_limits};

fn absent(what: &str, error: impl std::fmt::Display) {
    assert!(
        std::env::var_os("CI").is_none(),
        "own_copy_limit: {what} is required under CI: {error}"
    );
    eprintln!("own_copy_limit: {what} unavailable ({error}) — skipping");
}

async fn sentinel() -> Option<(SentinelCore, redis::aio::ConnectionManager)> {
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:password@127.0.0.1:5432/construct_test".to_string()
    });
    let client = match redis::Client::open(redis_url) {
        Ok(client) => client,
        Err(e) => {
            absent("redis", e);
            return None;
        }
    };
    let redis = match construct_redis::manager_for(client).await {
        Ok(conn) => conn,
        Err(e) => {
            absent("redis", e);
            return None;
        }
    };
    let db = match sqlx::PgPool::connect(&database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            absent("postgres", e);
            return None;
        }
    };
    let _ = sqlx::migrate!("../shared/migrations").run(&db).await;
    Some((SentinelCore::new(db, redis.clone()), redis))
}

/// Fresh ids: an unknown device reads as `New`, ten messages an hour. Keys left behind are harmless,
/// because nothing else ever names these ids.
fn fresh() -> (String, String, String) {
    (
        Uuid::new_v4().simple().to_string(),
        Uuid::new_v4().simple().to_string(),
        Uuid::new_v4().to_string(),
    )
}

async fn copy(s: &SentinelCore, device: &str, sibling: &str, me: &str) -> SendPermission {
    send_permission(s, device, sibling, me, me).await.unwrap()
}

async fn message(s: &SentinelCore, device: &str, peer: &str, me: &str) -> SendPermission {
    let contact = Uuid::new_v4().to_string();
    send_permission(s, device, peer, me, &contact)
        .await
        .unwrap()
}

/// The stand of 2026-11-07: a device under 48 hours old, ten copies, and every copy after them
/// refused for an hour while messages to the contact went through.
#[tokio::test]
#[serial]
async fn copies_do_not_spend_the_message_limit() {
    let Some((s, _)) = sentinel().await else {
        return;
    };
    let (device, sibling, me) = fresh();

    for n in 0..30 {
        assert!(copy(&s, &device, &sibling, &me).await.allowed, "copy {n}");
    }
    assert!(
        message(&s, &device, &sibling, &me).await.allowed,
        "thirty copies must leave the ten messages untouched"
    );
}

/// The control: a limit that never refuses would pass the test above.
#[tokio::test]
#[serial]
async fn a_message_to_someone_else_still_stops_at_the_limit() {
    let Some((s, _)) = sentinel().await else {
        return;
    };
    let (device, peer, me) = fresh();

    for n in 0..10 {
        assert!(
            message(&s, &device, &peer, &me).await.allowed,
            "message {n}"
        );
    }
    let refused = message(&s, &device, &peer, &me).await;
    assert!(!refused.allowed);
    assert_eq!(refused.retry_after_seconds, 3600);
}

#[tokio::test]
#[serial]
async fn copies_have_a_ceiling_of_their_own() {
    let Some((s, mut redis)) = sentinel().await else {
        return;
    };
    let (device, sibling, me) = fresh();
    let key = format!("sentinel:rate:own_copy:user:{me}");
    let _: () = redis
        .set_ex(&key, OWN_COPY_LIMIT_HOUR - 1, 3600)
        .await
        .unwrap();

    assert!(
        copy(&s, &device, &sibling, &me).await.allowed,
        "the last one passes"
    );
    let refused = copy(&s, &device, &sibling, &me).await;
    assert!(!refused.allowed);
    assert_eq!(refused.retry_after_seconds, 3600);
}

/// The ceiling is the account's: a second device does not bring a second one.
#[tokio::test]
#[serial]
async fn the_ceiling_is_shared_across_the_accounts_devices() {
    let Some((s, mut redis)) = sentinel().await else {
        return;
    };
    let (device, sibling, me) = fresh();
    let key = format!("sentinel:rate:own_copy:user:{me}");
    let _: () = redis.set_ex(&key, OWN_COPY_LIMIT_HOUR, 3600).await.unwrap();

    assert!(!copy(&s, &device, &sibling, &me).await.allowed);
    assert!(!copy(&s, &sibling, &device, &me).await.allowed);
}

/// A flagged device has five messages an hour. Copies must not be the way around that.
#[tokio::test]
#[serial]
async fn a_flagged_device_keeps_its_limit_on_copies() {
    let Some((s, mut redis)) = sentinel().await else {
        return;
    };
    let (device, sibling, me) = fresh();
    let _: () = redis
        .set_ex(format!("sentinel:flag:{device}"), 1, 3600)
        .await
        .unwrap();

    for n in 0..5 {
        assert!(copy(&s, &device, &sibling, &me).await.allowed, "copy {n}");
    }
    assert!(!copy(&s, &device, &sibling, &me).await.allowed);
}

#[tokio::test]
#[serial]
async fn a_banned_device_sends_no_copies() {
    let Some((s, mut redis)) = sentinel().await else {
        return;
    };
    let (device, sibling, me) = fresh();
    let _: () = redis
        .set_ex(format!("sentinel:ban:{device}"), 1, 3600)
        .await
        .unwrap();

    assert!(!copy(&s, &device, &sibling, &me).await.allowed);
}

/// The second limiter on the same send. Sentinel alone is not the whole path: this one would refuse
/// the copy next.
#[tokio::test]
#[serial]
async fn copies_do_not_spend_the_hourly_or_fanout_limit() {
    let Some((_, mut redis)) = sentinel().await else {
        return;
    };
    let config = MessagingConfig::default();
    let me = Uuid::new_v4().to_string();
    let limit = TrustLevel::New.hourly_limit(&config);

    for n in 0..limit + 5 {
        let refused = check_send_limits(&mut redis, TrustLevel::New, &config, &me, &me).await;
        assert!(refused.is_none(), "copy {n}: {refused:?}");
    }
    let contact = Uuid::new_v4().to_string();
    assert!(
        check_send_limits(&mut redis, TrustLevel::New, &config, &me, &contact)
            .await
            .is_none(),
        "copies must leave the hourly limit untouched"
    );
    let used: i64 = redis.get(format!("rate:msg:{{{me}}}:hour")).await.unwrap();
    assert_eq!(used, 1, "only the message counted");
}

/// A transport that asks Sentinel directly would refuse copies the other one lets through.
#[test]
fn both_transports_ask_through_the_one_function() {
    for (name, source) in [
        ("grpc.rs", include_str!("grpc.rs")),
        ("stream.rs", include_str!("stream.rs")),
    ] {
        assert!(source.contains("core::send_permission("), "{name}");
        assert!(!source.contains(".check_send_permission("), "{name}");
    }
}

#[test]
fn only_the_senders_own_account_is_a_copy() {
    let me = "296a7249-2b7f-4f36-85d9-d87de1817d06";
    assert!(is_own_copy(me, me));
    assert!(is_own_copy(me, &me.to_uppercase()));
    assert!(!is_own_copy(me, "58de814e-0894-4193-a8e0-9649f53eb000"));
    assert!(!is_own_copy(me, "ed25519:abcd"));
    assert!(!is_own_copy(me, ""));
}
