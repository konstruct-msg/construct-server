//! What `cleanup_mls_expired()` deletes and, as much, what it must leave: each table gets an
//! expired row and a live one, in a schema of its own.
use super::postgres;
use super::test_helpers::create_test_device;
use crate::cleanup::run_cleanup;
use sqlx::PgPool;
use uuid::Uuid;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../shared/migrations");

async fn group(pool: &PgPool, dissolved_hours_ago: Option<i32>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mls_groups (group_id, ratchet_tree, encrypted_group_context, dissolved_at)
         VALUES ($1, 'tree', 'context', NOW() - make_interval(hours => $2))",
    )
    .bind(id)
    .bind(dissolved_hours_ago)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// One row in each of the four expiring tables, `hours` from now (negative: already expired).
async fn rows(pool: &PgPool, group: Uuid, hours: i32) {
    let (user, device, _) = create_test_device(pool).await;
    let seq: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_messages WHERE group_id = $1")
        .bind(group)
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO group_messages (group_id, epoch, mls_ciphertext, sequence_number, expires_at)
         VALUES ($1, 0, 'ct', $2, NOW() + make_interval(hours => $3))",
    )
    .bind(group)
    .bind(seq)
    .bind(hours)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO group_commits
             (group_id, epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot, expires_at)
         VALUES ($1, $2, $2 + 1, 'commit', 'tree', NOW() + make_interval(hours => $3))",
    )
    .bind(group)
    .bind(seq)
    .bind(hours)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO group_invites
             (group_id, target_device_id, mls_welcome, key_package_ref, epoch, expires_at)
         VALUES ($1, $2, 'welcome', 'ref', 0, NOW() + make_interval(hours => $3))",
    )
    .bind(group)
    .bind(&device)
    .bind(hours)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO group_key_packages (user_id, device_id, key_package, key_package_ref, expires_at)
         VALUES ($1, $2, 'kp', $3, NOW() + make_interval(hours => $4))",
    )
    .bind(user)
    .bind(&device)
    .bind(device.as_bytes())
    .bind(hours)
    .execute(pool)
    .await
    .unwrap();
}

async fn expiries_past(pool: &PgPool, table: &str) -> (i64, i64) {
    sqlx::query_as(&format!(
        "SELECT COUNT(*) FILTER (WHERE expires_at < NOW()),
                COUNT(*) FILTER (WHERE expires_at >= NOW()) FROM {table}"
    ))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cleanup_deletes_what_expired_and_leaves_what_did_not() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let live = group(&db.pool, None).await;
    let recently_dissolved = group(&db.pool, Some(23)).await;
    let dissolved = group(&db.pool, Some(25)).await;
    rows(&db.pool, live, -1).await;
    rows(&db.pool, live, 1).await;
    // Not expired, but their group is gone: they go with it, KeyPackage excepted.
    rows(&db.pool, dissolved, 1).await;

    let stats: Vec<(String, i32)> = run_cleanup(&db.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.operation, s.deleted_count))
        .collect();

    let mut left = Vec::new();
    for table in [
        "group_messages",
        "group_commits",
        "group_invites",
        "group_key_packages",
    ] {
        left.push((table, expiries_past(&db.pool, table).await));
    }
    let mut groups: Vec<Uuid> = sqlx::query_scalar("SELECT group_id FROM mls_groups")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    let second: i32 = run_cleanup(&db.pool)
        .await
        .unwrap()
        .iter()
        .map(|s| s.deleted_count)
        .sum();
    db.cleanup().await;

    assert_eq!(
        stats,
        [
            ("group_messages".to_string(), 1),
            ("group_commits".to_string(), 1),
            ("group_invites".to_string(), 1),
            ("key_packages".to_string(), 1),
            ("dissolved_groups".to_string(), 1),
        ]
    );
    assert_eq!(
        left,
        [
            ("group_messages", (0, 1)),
            ("group_commits", (0, 1)),
            ("group_invites", (0, 1)),
            ("group_key_packages", (0, 2)),
        ]
    );
    let mut expected = [live, recently_dissolved];
    expected.sort();
    groups.sort();
    assert_eq!(
        groups, expected,
        "only a group dissolved over 24 h ago goes"
    );
    assert_eq!(second, 0, "a second pass finds nothing");
}
