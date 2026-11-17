//! Service-backed contracts for the rate limiter.
//!
//! Everything here needs a real service, so each test is `#[ignore]` naming the service
//! it needs. CI runs the whole workspace with `-- --ignored` against its own Redis and
//! PostgreSQL; a plain `cargo test` neither runs nor reports these, which is exactly why
//! the reason is written out instead of left bare.
//!
//! What is being pinned down:
//!
//! - **The sliding window decides the limit in the right direction.** `count >= max` is
//!   an off-by-one in waiting: `>` lets one extra event through on every limit, `<`
//!   refuses the first event of every window. Both look like "the limit works" from the
//!   outside until someone counts.
//! - **The window is a window.** An entry older than `window_seconds` must stop counting,
//!   and the key must outlive the window by a small buffer rather than dying with it.
//! - **Account age and warmup come from the primary device's clock**, and an account with
//!   no primary device is treated as new — the cautious direction for an anti-spam limit.
//! - **The warmup cache answers without PostgreSQL and writes the answer back.**

use construct_rate_limit::{
    get_user_account_age_hours, is_user_in_warmup, is_user_in_warmup_cached,
    sliding_window_check_and_record,
};
use redis::AsyncCommands;
use sqlx::PgPool;
use uuid::Uuid;

#[path = "../../../shared/test_support/postgres.rs"]
mod postgres;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../../shared/migrations");

/// A real Redis connection, built through `construct_redis` so it carries the shared
/// response timeouts. Not a lazy handle: every caller here expects to transact, and a
/// connection without a timeout can only hang.
async fn redis_manager() -> redis::aio::ConnectionManager {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    construct_redis::connect_manager(&url)
        .await
        .expect("Redis required for this test")
}

/// Per-test key so parallel runs and repeated mutation runs never share a window. Never
/// flush a shared Redis: a neighbouring test's keys are not ours to delete.
fn unique_key(test: &str) -> String {
    format!("rl:test:{test}:{}", Uuid::new_v4().simple())
}

/// A pool that is never expected to be touched. Used where the contract is that a code
/// path does *not* reach PostgreSQL.
fn unreachable_pool() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(50))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .expect("lazy pool")
}

/// Insert a user whose primary device registered `age_hours` ago.
///
/// The two SQL functions read `devices.registered_at` through `users.primary_device_id`,
/// so both rows are required for the lookups to mean anything.
async fn user_with_primary_device_age(pool: &PgPool, age_hours: i32) -> Uuid {
    let device_id = Uuid::new_v4().simple().to_string();
    let user_id: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(pool)
        .await
        .expect("user");
    sqlx::query(
        r#"
        INSERT INTO devices (
            device_id, server_hostname, user_id, verifying_key, identity_public,
            signed_prekey_public, signed_prekey_signature, crypto_suites,
            registered_at, is_active, supports_pq_ratchet
        ) VALUES (
            $1, 'test.local', $2, $3, $4, $5, $6, '[]'::jsonb,
            NOW() - make_interval(hours => $7), TRUE, FALSE
        )
        "#,
    )
    .bind(&device_id)
    .bind(user_id)
    .bind(vec![1u8; 32])
    .bind(Uuid::new_v4().as_bytes().repeat(2))
    .bind(vec![3u8; 32])
    .bind(vec![4u8; 64])
    .bind(age_hours)
    .execute(pool)
    .await
    .expect("device");
    sqlx::query("UPDATE users SET primary_device_id = $1 WHERE id = $2")
        .bind(&device_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("primary device");
    user_id
}

// ── Sliding window ────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Redis"]
async fn sliding_window_allows_the_limit_then_refuses_without_recording() {
    let mut conn = redis_manager().await;
    let key = unique_key("limit");

    assert!(
        sliding_window_check_and_record(&mut conn, &key, 2, 60)
            .await
            .expect("first"),
        "the first event of a window is always under any positive limit"
    );
    assert!(
        sliding_window_check_and_record(&mut conn, &key, 2, 60)
            .await
            .expect("second"),
        "the limit counts events, so the second of two is still allowed"
    );
    assert!(
        !sliding_window_check_and_record(&mut conn, &key, 2, 60)
            .await
            .expect("third"),
        "the third event is over a limit of two"
    );
    // A refusal must not consume budget, or a client that keeps retrying would push its
    // own window further out instead of waiting for it to drain.
    assert!(
        !sliding_window_check_and_record(&mut conn, &key, 2, 60)
            .await
            .expect("fourth"),
        "a refused event must not be recorded"
    );
}

#[tokio::test]
#[ignore = "requires Redis"]
async fn sliding_window_stops_counting_entries_older_than_the_window() {
    let mut conn = redis_manager().await;
    let key = unique_key("expiry");

    assert!(
        sliding_window_check_and_record(&mut conn, &key, 1, 1)
            .await
            .expect("first")
    );
    assert!(
        !sliding_window_check_and_record(&mut conn, &key, 1, 1)
            .await
            .expect("second"),
        "a limit of one refuses the second event inside the window"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

    assert!(
        sliding_window_check_and_record(&mut conn, &key, 1, 1)
            .await
            .expect("after the window"),
        "an entry older than the window must no longer count against it"
    );
}

#[tokio::test]
#[ignore = "requires Redis"]
async fn sliding_window_keeps_the_key_alive_past_the_window() {
    let mut conn = redis_manager().await;
    let key = unique_key("ttl");
    let window_secs = 60i64;

    assert!(
        sliding_window_check_and_record(&mut conn, &key, 5, window_secs)
            .await
            .expect("charge")
    );

    let ttl: i64 = conn.ttl(&key).await.expect("ttl");
    // Outlive the window by a small buffer (the code adds 60s), but not by a factor:
    // too short and the window forgets itself early, too long and expired windows keep
    // their keys resident.
    assert!(
        (window_secs..=window_secs + 60).contains(&ttl),
        "TTL must cover the window plus a buffer, got {ttl}"
    );
}

// ── Warmup cache ──────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Redis"]
async fn warmup_cache_answers_from_redis_without_touching_postgres() {
    let mut conn = redis_manager().await;
    let pool = unreachable_pool();
    let user = Uuid::new_v4();

    let key = format!("rl:warmup:{user}");
    let _: () = conn.set_ex(&key, 1u8, 60).await.expect("seed warm");
    assert!(
        is_user_in_warmup_cached(&mut conn, &pool, user)
            .await
            .expect("cached warm"),
        "a cached 1 means in warmup"
    );

    let _: () = conn.set_ex(&key, 0u8, 60).await.expect("seed settled");
    assert!(
        !is_user_in_warmup_cached(&mut conn, &pool, user)
            .await
            .expect("cached settled"),
        "a cached 0 means past warmup"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn warmup_cache_miss_reads_postgres_and_writes_the_answer_back() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let mut conn = redis_manager().await;
    let user = user_with_primary_device_age(&db.pool, 1).await;

    let key = format!("rl:warmup:{user}");
    let _: i32 = conn.del(&key).await.expect("clear cache");

    assert!(
        is_user_in_warmup_cached(&mut conn, &db.pool, user)
            .await
            .expect("miss"),
        "a one-hour-old account is in warmup"
    );
    let cached: Option<u8> = conn.get(&key).await.expect("read back");
    assert_eq!(
        cached,
        Some(1),
        "the answer must be written back, or every action pays a PostgreSQL round-trip"
    );

    db.cleanup().await;
}

// ── SQL lookups ───────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn account_age_and_warmup_follow_the_primary_device() {
    let db = postgres::Database::new(&MIGRATIONS).await;

    let fresh = user_with_primary_device_age(&db.pool, 1).await;
    assert!(
        is_user_in_warmup(&db.pool, fresh).await.expect("fresh"),
        "a one-hour-old account is inside the 48h warmup"
    );
    let age = get_user_account_age_hours(&db.pool, fresh)
        .await
        .expect("age");
    assert!(
        (0.9..1.5).contains(&age),
        "a device registered one hour ago is about one hour old, got {age}"
    );

    let settled = user_with_primary_device_age(&db.pool, 100).await;
    assert!(
        !is_user_in_warmup(&db.pool, settled).await.expect("settled"),
        "a 100-hour-old account is past warmup"
    );

    let unknown = Uuid::new_v4();
    assert!(
        is_user_in_warmup(&db.pool, unknown).await.expect("unknown"),
        "an account with no primary device is treated as new, not as trusted"
    );
    assert_eq!(
        get_user_account_age_hours(&db.pool, unknown)
            .await
            .expect("unknown age"),
        0.0,
        "an account with no primary device has no measurable age"
    );

    db.cleanup().await;
}
