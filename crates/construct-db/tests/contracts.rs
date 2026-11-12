//! Exercise production SQL against a freshly migrated schema, including competing connections.
#[path = "../../../shared/test_support/postgres.rs"]
mod postgres;

use chrono::{Duration, Utc};
use construct_db::{channel as ch, mls, *};
use postgres::Database;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../../shared/migrations");

async fn user(pool: &DbPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn device(pool: &DbPool, user: Uuid) -> String {
    let id = Uuid::new_v4().simple().to_string();
    create_device(
        pool,
        CreateDeviceData {
            device_id: id.clone(),
            server_hostname: "test.local".into(),
            verifying_key: vec![1; 32],
            identity_public: Uuid::new_v4().as_bytes().repeat(2),
            signed_prekey_public: vec![3; 32],
            signed_prekey_signature: vec![4; 64],
            crypto_suites: "[]".into(),
            supports_pq_ratchet: false,
        },
        Some(user),
    )
    .await
    .unwrap();
    id
}

async fn group(pool: &DbPool, creator: &str) -> Uuid {
    let id = Uuid::new_v4();
    mls::create_group_with_creator(
        pool,
        mls::NewGroup {
            group_id: id,
            creator_device_id: creator,
            initial_ratchet_tree: b"tree0",
            encrypted_group_context: b"opaque",
            max_members: 20,
            message_retention_days: 30,
            threads_enabled: false,
            created_at: Utc::now(),
        },
    )
    .await
    .unwrap();
    id
}

async fn package(pool: &DbPool, user: Uuid, device: &str, age: i64, expired: bool) -> Vec<u8> {
    let reference = Uuid::new_v4().as_bytes().to_vec();
    let now = Utc::now();
    mls::insert_group_key_package(
        pool,
        mls::NewGroupKeyPackage {
            user_id: user,
            device_id: device,
            key_package: &reference,
            key_package_ref: &reference,
            published_at: now - Duration::hours(age),
            expires_at: now + Duration::hours(if expired { -1 } else { 24 }),
        },
    )
    .await
    .unwrap();
    reference
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn key_packages_are_single_use_under_contention_in_both_selection_modes() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let d = device(&db.pool, u).await;
    for preferred in [false, true] {
        let reference = package(&db.pool, u, &d, 0, false).await;
        let barrier = Arc::new(Barrier::new(8));
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let (pool, d, b) = (db.pool.clone(), d.clone(), barrier.clone());
            jobs.push(tokio::spawn(async move {
                b.wait().await;
                mls::consume_key_package_for_user(&pool, u, preferred.then_some(d.as_str()))
                    .await
                    .unwrap()
            }));
        }
        let mut consumed = Vec::new();
        for job in jobs {
            if let Some(row) = job.await.unwrap() {
                consumed.push(row);
            }
        }
        assert_eq!(consumed.len(), 1, "exactly one consumer wins");
        assert_eq!(consumed[0].key_package_ref, reference);
        assert_eq!(consumed[0].key_package, reference);
        assert_eq!(consumed[0].device_id, d);
        assert_eq!(
            mls::count_key_packages_for_device(&db.pool, &d)
                .await
                .unwrap(),
            0
        );
    }
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn key_package_selection_scopes_account_device_expiry_and_oldest_first() {
    let db = Database::new(&MIGRATIONS).await;
    let (u, v) = (user(&db.pool).await, user(&db.pool).await);
    let (a, b, c) = (
        device(&db.pool, u).await,
        device(&db.pool, u).await,
        device(&db.pool, v).await,
    );
    let expired = package(&db.pool, u, &a, 10, true).await;
    let other = package(&db.pool, v, &c, 9, false).await;
    let oldest = package(&db.pool, u, &b, 8, false).await;
    let selected = package(&db.pool, u, &a, 4, false).await;
    let newest = package(&db.pool, u, &a, 1, false).await;
    assert!(
        mls::consume_key_package_for_user(&db.pool, u, Some(&c))
            .await
            .unwrap()
            .is_none()
    );
    let row = mls::consume_key_package_for_user(&db.pool, u, Some(&a))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.key_package_ref, selected);
    let row = mls::consume_key_package_for_user(&db.pool, u, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.key_package_ref, oldest);
    assert_eq!(
        mls::get_key_package_count(&db.pool, u, None)
            .await
            .unwrap()
            .count,
        1
    );
    assert_eq!(
        mls::get_key_package_count(&db.pool, u, Some(&a))
            .await
            .unwrap()
            .count,
        1
    );
    assert_eq!(
        mls::consume_key_package_for_user(&db.pool, u, None)
            .await
            .unwrap()
            .unwrap()
            .key_package_ref,
        newest
    );
    assert!(
        mls::consume_key_package_for_user(&db.pool, u, Some(&a))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        mls::consume_key_package_for_user(&db.pool, u, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        mls::consume_key_package_for_user(&db.pool, v, None)
            .await
            .unwrap()
            .unwrap()
            .key_package_ref,
        other
    );
    assert!(
        mls::get_key_package_device_by_ref(&db.pool, &expired)
            .await
            .unwrap()
            .is_none()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn invite_burn_has_one_winner_and_never_overwrites_owner_or_retention() {
    let db = Database::new(&MIGRATIONS).await;
    let (u, v) = (user(&db.pool).await, user(&db.pool).await);
    let jti = Uuid::new_v4();
    let barrier = Arc::new(Barrier::new(8));
    let mut jobs = Vec::new();
    for _ in 0..8 {
        let (p, b) = (db.pool.clone(), barrier.clone());
        jobs.push(tokio::spawn(async move {
            b.wait().await;
            burn_used_invite(&p, &jti, &u, Some("device"), 300)
                .await
                .unwrap()
        }));
    }
    let mut wins = 0;
    for j in jobs {
        wins += usize::from(j.await.unwrap());
    }
    assert_eq!(wins, 1);
    let before: (
        Uuid,
        Option<String>,
        chrono::DateTime<Utc>,
        chrono::DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT user_id, device_id, used_at, expires_at FROM used_invites WHERE jti=$1",
    )
    .bind(jti)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(before.0, u);
    assert_eq!(before.1.as_deref(), Some("device"));
    assert_eq!((before.3 - before.2).num_seconds(), 300);
    assert!(
        !burn_used_invite(&db.pool, &jti, &v, None, 999)
            .await
            .unwrap()
    );
    let after: (
        Uuid,
        Option<String>,
        chrono::DateTime<Utc>,
        chrono::DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT user_id, device_id, used_at, expires_at FROM used_invites WHERE jti=$1",
    )
    .bind(jti)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    assert!(
        burn_used_invite(&db.pool, &Uuid::new_v4(), &v, None, 300)
            .await
            .unwrap()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn blocklist_is_directional_idempotent_and_scoped_on_unblock() {
    let db = Database::new(&MIGRATIONS).await;
    let (a, b, c) = (
        user(&db.pool).await,
        user(&db.pool).await,
        user(&db.pool).await,
    );
    block_user(&db.pool, &a, &b, Some("first")).await.unwrap();
    block_user(&db.pool, &a, &b, Some("updated")).await.unwrap();
    block_user(&db.pool, &a, &c, None).await.unwrap();
    block_user(&db.pool, &c, &b, None).await.unwrap();
    assert!(is_blocked_by(&db.pool, &a, &b).await.unwrap());
    assert!(!is_blocked_by(&db.pool, &b, &a).await.unwrap());
    assert!(!is_blocked_by(&db.pool, &b, &c).await.unwrap());
    let list = get_blocked_users(&db.pool, &a).await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(
        list.iter()
            .find(|r| r.user_id == b)
            .unwrap()
            .reason
            .as_deref(),
        Some("updated")
    );
    assert!(unblock_user(&db.pool, &a, &b).await.unwrap());
    assert!(!unblock_user(&db.pool, &a, &b).await.unwrap());
    assert!(!is_blocked_by(&db.pool, &a, &b).await.unwrap());
    assert!(is_blocked_by(&db.pool, &a, &c).await.unwrap());
    assert!(is_blocked_by(&db.pool, &c, &b).await.unwrap());
    db.cleanup().await;
}

/// The routing set of a send is `get_active_device_ids`, and it must be the same set the full-row
/// read produced — that read is what the send path used before, so a difference here is a message
/// delivered to a different set of mailboxes.
///
/// Mutation: drop `AND is_active = TRUE` — the deactivated device reappears. Mutation: drop the
/// `user_id` filter — the other account's device appears.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn active_device_ids_are_the_set_the_full_rows_named() {
    let db = Database::new(&MIGRATIONS).await;
    let (u, v) = (user(&db.pool).await, user(&db.pool).await);
    let (a, b, gone, other) = (
        device(&db.pool, u).await,
        device(&db.pool, u).await,
        device(&db.pool, u).await,
        device(&db.pool, v).await,
    );
    // Fixture state only: this contract tests directory reads, not the guarded removal flow.
    // Real device removal must stay behind the auth service's primary-device guard.
    let inactive = sqlx::query("UPDATE devices SET is_active = FALSE WHERE device_id = $1")
        .bind(&gone)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        inactive.rows_affected(),
        1,
        "the inactive fixture must exist"
    );

    let mut full: Vec<String> = get_devices_by_user_id(&db.pool, &u)
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.device_id)
        .collect();
    full.sort();
    let mut ids = get_active_device_ids(&db.pool, &u).await.unwrap();
    ids.sort();
    assert_eq!(ids, full, "the ids are the rows' ids, in the same set");
    assert_eq!(ids, {
        let mut expected = vec![a.clone(), b.clone()];
        expected.sort();
        expected
    });
    assert!(!ids.contains(&gone), "a signed-out device keeps no mailbox");
    assert!(
        !ids.contains(&other),
        "another account's device is not this set"
    );

    // An account with no devices answers an empty list, not an error: the send path reads a
    // failed lookup and an empty account the same way.
    let nobody = user(&db.pool).await;
    assert!(
        get_active_device_ids(&db.pool, &nobody)
            .await
            .unwrap()
            .is_empty()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn route_lookup_returns_the_exact_account_and_directory_fields() {
    let db = Database::new(&MIGRATIONS).await;
    let (a, b) = (user(&db.pool).await, user(&db.pool).await);
    let d = device(&db.pool, a).await;
    let key = Uuid::new_v4().as_bytes().repeat(124); // 1984-byte hybrid identity
    let route = construct_types::user_id::RouteId::compute(&key, 3);
    let route = route.as_str();
    sqlx::query("UPDATE users SET route_id=$1,identity_key_type=3,identity_public_key=$2,primary_device_id=$3 WHERE id=$4")
        .bind(route).bind(&key).bind(&d).bind(a).execute(&db.pool).await.unwrap();
    let row = get_user_by_route_id(&db.pool, route)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.id, a);
    assert_eq!(row.identity_key_type, 3);
    assert_eq!(row.identity_public_key, Some(key));
    assert_eq!(row.route_id.as_deref(), Some(route));
    assert_eq!(row.primary_device_id.as_deref(), Some(d.as_str()));
    assert!(
        get_user_by_route_id(&db.pool, &"f".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    assert!(get_user_by_route_id(&db.pool, "").await.unwrap().is_none());
    let duplicate = sqlx::query("UPDATE users SET route_id=$1 WHERE id=$2")
        .bind(route)
        .bind(b)
        .execute(&db.pool)
        .await
        .unwrap_err();
    assert_eq!(
        duplicate.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ownership_transfer_and_member_removal_are_group_and_device_scoped() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let (a, b, c) = (
        device(&db.pool, u).await,
        device(&db.pool, u).await,
        device(&db.pool, u).await,
    );
    let (g, h) = (group(&db.pool, &a).await, group(&db.pool, &a).await);
    for id in [g, h] {
        mls::insert_group_member(
            &db.pool,
            mls::NewGroupMember {
                group_id: id,
                device_id: &b,
                leaf_index: 1,
                acceptance_signature: Some(b"proof"),
                joined_at: Utc::now(),
            },
        )
        .await
        .unwrap();
        mls::upsert_group_admin_role(&db.pool, id, &b, 1, Some(b"token"), &a, Utc::now())
            .await
            .unwrap();
    }
    mls::upsert_group_admin_role(&db.pool, g, &c, 2, None, &a, Utc::now())
        .await
        .unwrap();
    assert!(
        !mls::get_group_admin_access(&db.pool, g, &c)
            .await
            .unwrap()
            .unwrap()
            .is_full_admin
    );
    assert!(
        mls::get_group_admin_access(&db.pool, h, &c)
            .await
            .unwrap()
            .is_none()
    );
    let mut tx = db.pool.begin().await.unwrap();
    mls::transfer_group_ownership(&mut tx, g, &a, &b)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        mls::get_group_admin_access(&db.pool, g, &a)
            .await
            .unwrap()
            .unwrap()
            .is_creator
    );
    let mut tx = db.pool.begin().await.unwrap();
    mls::transfer_group_ownership(&mut tx, g, &a, &b)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let old = mls::get_group_admin_access(&db.pool, g, &a)
        .await
        .unwrap()
        .unwrap();
    let new = mls::get_group_admin_access(&db.pool, g, &b)
        .await
        .unwrap()
        .unwrap();
    assert!(!old.is_creator && old.is_full_admin);
    assert!(new.is_creator && new.is_full_admin);
    assert!(
        mls::get_group_admin_access(&db.pool, h, &a)
            .await
            .unwrap()
            .unwrap()
            .is_creator
    );
    assert!(
        !mls::get_group_admin_access(&db.pool, h, &b)
            .await
            .unwrap()
            .unwrap()
            .is_creator
    );
    mls::remove_group_member(&db.pool, g, &b).await.unwrap();
    mls::remove_group_admin_role(&db.pool, g, &b).await.unwrap();
    assert!(!mls::is_group_member(&db.pool, g, &b).await.unwrap());
    assert!(
        mls::get_group_admin_access(&db.pool, g, &b)
            .await
            .unwrap()
            .is_none()
    );
    assert!(mls::is_group_member(&db.pool, g, &a).await.unwrap());
    assert!(mls::is_group_member(&db.pool, h, &b).await.unwrap());
    assert!(
        mls::get_group_admin_access(&db.pool, h, &b)
            .await
            .unwrap()
            .is_some()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn ownership_transfer_rechecks_owner_and_target_inside_the_transaction() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let (a, b, c) = (
        device(&db.pool, u).await,
        device(&db.pool, u).await,
        device(&db.pool, u).await,
    );
    let g = group(&db.pool, &a).await;
    mls::upsert_group_admin_role(&db.pool, g, &b, 2, None, &a, Utc::now())
        .await
        .unwrap();
    for (from, to) in [(&a, &b), (&a, &c), (&b, &a), (&a, &a)] {
        let mut tx = db.pool.begin().await.unwrap();
        let result = mls::transfer_group_ownership(&mut tx, g, from, to).await;
        tx.rollback().await.unwrap();
        assert!(
            result.is_err(),
            "only a current owner may transfer to a different FULL admin"
        );
    }
    assert!(
        mls::get_group_admin_access(&db.pool, g, &a)
            .await
            .unwrap()
            .unwrap()
            .is_creator
    );
    assert!(
        !mls::get_group_admin_access(&db.pool, g, &b)
            .await
            .unwrap()
            .unwrap()
            .is_full_admin
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn concurrent_ownership_transfers_leave_exactly_one_creator() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let (a, b, c) = (
        device(&db.pool, u).await,
        device(&db.pool, u).await,
        device(&db.pool, u).await,
    );
    let g = group(&db.pool, &a).await;
    for d in [&b, &c] {
        mls::upsert_group_admin_role(&db.pool, g, d, 1, None, &a, Utc::now())
            .await
            .unwrap();
    }
    let mut jobs = Vec::new();
    let barrier = Arc::new(Barrier::new(2));
    for target in [b, c] {
        let (p, old, b) = (db.pool.clone(), a.clone(), barrier.clone());
        jobs.push(tokio::spawn(async move {
            let mut tx = p.begin().await.unwrap();
            b.wait().await;
            if mls::transfer_group_ownership(&mut tx, g, &old, &target)
                .await
                .is_ok()
            {
                tx.commit().await.unwrap();
                true
            } else {
                tx.rollback().await.unwrap();
                false
            }
        }));
    }
    let mut wins = 0;
    for job in jobs {
        wins += usize::from(job.await.unwrap());
    }
    let creators: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_admins WHERE group_id=$1 AND is_creator")
            .bind(g)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    db.cleanup().await;
    assert_eq!(wins, 1);
    assert_eq!(creators, 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn group_invites_are_group_device_expiry_scoped_and_deleted_on_consumption() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let (a, b) = (device(&db.pool, u).await, device(&db.pool, u).await);
    let (g, h) = (group(&db.pool, &a).await, group(&db.pool, &a).await);
    let now = Utc::now();
    let invite = Uuid::new_v4();
    mls::insert_group_invite(
        &db.pool,
        mls::NewGroupInvite {
            invite_id: invite,
            group_id: g,
            target_device_id: &b,
            mls_welcome: b"welcome",
            key_package_ref: b"ref",
            epoch: 7,
            invited_at: now,
            expires_at: now + Duration::days(1),
        },
    )
    .await
    .unwrap();
    assert!(
        mls::get_group_invite_for_accept(&db.pool, invite, h)
            .await
            .unwrap()
            .is_none()
    );
    let row = mls::get_group_invite_for_accept(&db.pool, invite, g)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.target_device_id, b);
    assert_eq!(row.mls_welcome, b"welcome");
    assert_eq!(row.key_package_ref, b"ref");
    assert_eq!(row.epoch, 7);
    assert!(
        mls::has_pending_group_invite(&db.pool, g, &b)
            .await
            .unwrap()
    );
    assert!(
        !mls::has_pending_group_invite(&db.pool, g, &a)
            .await
            .unwrap()
    );
    assert_eq!(
        mls::list_pending_group_invites(&db.pool, &b, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::query("UPDATE group_invites SET expires_at=NOW()-INTERVAL '1 second' WHERE invite_id=$1")
        .bind(invite)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        mls::get_group_invite_for_accept(&db.pool, invite, g)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !mls::has_pending_group_invite(&db.pool, g, &b)
            .await
            .unwrap()
    );
    assert!(
        mls::list_pending_group_invites(&db.pool, &b, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    mls::delete_group_invite(&db.pool, invite).await.unwrap();
    assert!(
        mls::get_group_invite_target_device(&db.pool, invite, g)
            .await
            .unwrap()
            .is_none()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn channel_invite_usage_is_atomic_bounded_and_rejects_expired_revoked_missing() {
    let db = Database::new(&MIGRATIONS).await;
    let channel = ch::create_channel(&db.pool, "owner", "PRIVATE", b"opaque", 100, 30)
        .await
        .unwrap()
        .channel_id;
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, channel, "owner", Some(1), None)
        .await
        .unwrap();
    let b = Arc::new(Barrier::new(8));
    let mut jobs = Vec::new();
    for _ in 0..8 {
        let (p, t, b) = (db.pool.clone(), token.clone(), b.clone());
        jobs.push(tokio::spawn(async move {
            b.wait().await;
            ch::increment_channel_invite_link_usage(&p, &t)
                .await
                .unwrap()
        }));
    }
    let mut wins = 0;
    for job in jobs {
        wins += usize::from(job.await.unwrap());
    }
    assert_eq!(wins, 1);
    let row = ch::resolve_channel_invite_link(&db.pool, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.channel_id, channel);
    assert_eq!(row.max_uses, Some(1));
    assert_eq!(row.use_count, 1);
    assert!(
        !ch::increment_channel_invite_link_usage(&db.pool, &token)
            .await
            .unwrap()
    );
    let other = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(
        &db.pool,
        &other,
        channel,
        "owner",
        None,
        Some(Utc::now() - Duration::hours(1)),
    )
    .await
    .unwrap();
    assert!(
        !ch::increment_channel_invite_link_usage(&db.pool, &other)
            .await
            .unwrap()
    );
    assert!(
        ch::resolve_channel_invite_link(&db.pool, &other)
            .await
            .unwrap()
            .unwrap()
            .expires_at
            .is_some()
    );
    let unlimited = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &unlimited, channel, "owner", None, None)
        .await
        .unwrap();
    for _ in 0..3 {
        assert!(
            ch::increment_channel_invite_link_usage(&db.pool, &unlimited)
                .await
                .unwrap()
        );
    }
    assert!(
        ch::revoke_channel_invite_link(&db.pool, Uuid::new_v4(), &unlimited)
            .await
            .is_err()
    );
    ch::revoke_channel_invite_link(&db.pool, channel, &unlimited)
        .await
        .unwrap();
    assert!(
        !ch::increment_channel_invite_link_usage(&db.pool, &unlimited)
            .await
            .unwrap()
    );
    let row = ch::resolve_channel_invite_link(&db.pool, &unlimited)
        .await
        .unwrap()
        .unwrap();
    assert!(row.revoked_at.is_some());
    assert_eq!(row.use_count, 3);
    assert!(
        !ch::increment_channel_invite_link_usage(&db.pool, "missing")
            .await
            .unwrap()
    );
    assert!(
        ch::resolve_channel_invite_link(&db.pool, "missing")
            .await
            .unwrap()
            .is_none()
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn sender_key_rotation_and_reads_are_scoped() {
    let db = Database::new(&MIGRATIONS).await;
    let a = ch::create_channel(&db.pool, "owner", "PRIVATE", b"opaque", 100, 30)
        .await
        .unwrap()
        .channel_id;
    let b = ch::create_channel(&db.pool, "owner", "PRIVATE", b"opaque", 100, 30)
        .await
        .unwrap()
        .channel_id;
    for (id, d, key) in [
        (a, "alice", b"old".as_slice()),
        (a, "bob", b"bob".as_slice()),
        (b, "alice", b"other".as_slice()),
    ] {
        sqlx::query("INSERT INTO channel_sender_keys (channel_id,device_id,encrypted_sender_key) VALUES ($1,$2,$3)")
            .bind(id).bind(d).bind(key).execute(&db.pool).await.unwrap();
    }
    ch::rotate_channel_sender_key(&db.pool, a, "alice")
        .await
        .unwrap();
    assert!(
        ch::get_channel_sender_key(&db.pool, a, "alice")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ch::get_channel_sender_key(&db.pool, a, "bob")
            .await
            .unwrap()
            .as_deref(),
        Some(b"bob".as_slice())
    );
    assert_eq!(
        ch::get_channel_sender_key(&db.pool, b, "alice")
            .await
            .unwrap()
            .as_deref(),
        Some(b"other".as_slice())
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn epoch_lock_blocks_a_competing_connection_until_the_new_state_is_committed() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let d = device(&db.pool, u).await;
    let g = group(&db.pool, &d).await;
    let mut first = db.pool.begin().await.unwrap();
    assert_eq!(
        mls::lock_group_epoch_for_update(&mut first, g)
            .await
            .unwrap(),
        0
    );
    let (send, recv) = tokio::sync::oneshot::channel();
    let p = db.pool.clone();
    let second = tokio::spawn(async move {
        let mut tx = p.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        send.send(pid).unwrap();
        let epoch = mls::lock_group_epoch_for_update(&mut tx, g).await.unwrap();
        tx.rollback().await.unwrap();
        epoch
    });
    let pid = recv.await.unwrap();
    // Observe an actual row-lock wait, not an assumed scheduling delay.
    let waiting = tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let locked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')")
                .bind(pid).fetch_one(&db.pool).await.unwrap();
            if locked { break true; }
            if second.is_finished() { break false; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap_or(false);
    let now = Utc::now();
    mls::insert_group_commit(
        &mut first,
        mls::NewGroupCommit {
            group_id: g,
            epoch_from: 0,
            epoch_to: 1,
            mls_commit: b"commit1",
            ratchet_tree_snapshot: b"tree1",
            committed_at: now,
            expires_at: now + Duration::days(30),
        },
    )
    .await
    .unwrap();
    mls::update_group_epoch_and_ratchet_tree(&mut first, g, b"tree1", 1)
        .await
        .unwrap();
    first.commit().await.unwrap();
    let observed = second.await.unwrap();
    assert!(
        waiting,
        "competing transaction must wait on the production row lock"
    );
    assert_eq!(
        observed, 1,
        "second connection must see the committed epoch"
    );
    let history = mls::get_group_commits_since(&db.pool, g, 0).await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].epoch_from, 0);
    assert_eq!(history[0].epoch_to, 1);
    assert_eq!(history[0].mls_commit, b"commit1");
    assert_eq!(history[0].ratchet_tree_snapshot, b"tree1");
    let mut tx = db.pool.begin().await.unwrap();
    mls::update_group_epoch_and_ratchet_tree(&mut tx, g, b"discard", 2)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let state: (i64, Vec<u8>) =
        sqlx::query_as("SELECT epoch,ratchet_tree FROM mls_groups WHERE group_id=$1")
            .bind(g)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(state, (1, b"tree1".to_vec()));
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn migrations_enforce_resource_constraints_and_deletion_cascades() {
    let db = Database::new(&MIGRATIONS).await;
    let u = user(&db.pool).await;
    let d = device(&db.pool, u).await;
    let g = group(&db.pool, &d).await;
    let now = Utc::now();
    let mut tx = db.pool.begin().await.unwrap();
    let bad = mls::insert_group_commit(
        &mut tx,
        mls::NewGroupCommit {
            group_id: g,
            epoch_from: 0,
            epoch_to: 2,
            mls_commit: b"invalid",
            ratchet_tree_snapshot: b"invalid",
            committed_at: now,
            expires_at: now + Duration::days(30),
        },
    )
    .await
    .unwrap_err();
    let code = bad
        .downcast_ref::<sqlx::Error>()
        .unwrap()
        .as_database_error()
        .unwrap()
        .code()
        .unwrap()
        .into_owned();
    tx.rollback().await.unwrap();
    assert_eq!(code, "23514");
    for (column, value) in [
        ("max_members", 0),
        ("max_members", 2049),
        ("message_retention_days", 0),
        ("message_retention_days", 91),
    ] {
        let err = sqlx::query(&format!(
            "UPDATE mls_groups SET {column}=$1 WHERE group_id=$2"
        ))
        .bind(value as i16)
        .bind(g)
        .execute(&db.pool)
        .await
        .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    let reference = package(&db.pool, u, &d, 0, false).await;
    burn_used_invite(&db.pool, &Uuid::new_v4(), &u, Some(&d), 300)
        .await
        .unwrap();
    let duplicate = sqlx::query("INSERT INTO group_key_packages(user_id,device_id,key_package,key_package_ref) VALUES($1,$2,$3,$3)")
        .bind(u).bind(&d).bind(&reference).execute(&db.pool).await.unwrap_err();
    assert_eq!(
        duplicate.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    // Device ownership intentionally has no FK after the passwordless redesign;
    // account deletion must run the production transaction, not delete one row.
    delete_user_account(&db.pool, &u, b"contract-contact-secret")
        .await
        .unwrap();
    for table in [
        "devices",
        "group_key_packages",
        "used_invites",
        "group_members",
        "group_admins",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "{table} must not retain deleted account resources"
        );
    }
    db.cleanup().await;
}
