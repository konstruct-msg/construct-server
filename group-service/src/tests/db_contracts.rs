//! RPC consumers of the SQL invariants; no copied authorization or commit algorithm.
use super::postgres;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, make_test_service,
};
use construct_db::channel as ch;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService, mls_service_server::MlsService,
};
use ed25519_dalek::Signer;
use std::sync::Arc;
use tonic::{Code, Request};
use uuid::Uuid;

static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../shared/migrations");

fn request<T>(user: Uuid, device: &str, body: T) -> Request<T> {
    Request::from_parts(
        create_metadata(&user, device),
        tonic::Extensions::default(),
        body,
    )
}

async fn clear_subscription_limits(svc: &crate::service::GroupServiceImpl, users: &[Uuid]) {
    let keys: Vec<String> = users
        .iter()
        .flat_map(|u| {
            [
                format!("rl:warmup:{u}"),
                format!("rl:channel:subscribe_channel:{u}"),
            ]
        })
        .collect();
    let _: usize = redis::cmd("DEL")
        .arg(keys)
        .query_async(&mut svc.redis.clone())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn private_channel_rejects_another_channels_invite_without_burning_it() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (user, device, _) = create_test_device(&db.pool).await;
    let svc = make_test_service(Arc::new(db.pool.clone())).await;
    let a = ch::create_channel(&db.pool, &device, "PRIVATE", b"a", 100, 30)
        .await
        .unwrap()
        .channel_id;
    let b = ch::create_channel(&db.pool, &device, "PRIVATE", b"b", 100, 30)
        .await
        .unwrap()
        .channel_id;
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, a, &device, Some(1), None)
        .await
        .unwrap();
    let result = svc
        .subscribe_channel(request(
            user,
            &device,
            proto::SubscribeChannelRequest {
                channel_id: b.to_string(),
                invite_token: token.clone(),
            },
        ))
        .await;
    let membership = ch::is_channel_subscriber(&db.pool, b, &device)
        .await
        .unwrap();
    let uses = ch::resolve_channel_invite_link(&db.pool, &token)
        .await
        .unwrap()
        .unwrap()
        .use_count;
    clear_subscription_limits(&svc, &[user]).await;
    db.cleanup().await;
    assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
    assert!(!membership);
    assert_eq!(uses, 0);
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn private_channel_concurrent_subscriptions_cannot_exceed_a_one_use_invite() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let svc = Arc::new(make_test_service(Arc::new(db.pool.clone())).await);
    let (_, od, _) = create_test_device(&db.pool).await;
    let a = ch::create_channel(&db.pool, &od, "PRIVATE", b"a", 100, 30)
        .await
        .unwrap()
        .channel_id;
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, a, &od, Some(1), None)
        .await
        .unwrap();
    let mut clients = Vec::new();
    for _ in 0..8 {
        let (u, d, _) = create_test_device(&db.pool).await;
        clients.push((u, d));
    }
    let users: Vec<Uuid> = clients.iter().map(|(u, _)| *u).collect();
    // Hold the admission row until multiple RPCs are waiting on the channel lock.
    // The observer counts pg_stat_activity lock waits instead of sleeping.
    let mut lock = db.pool.begin().await.unwrap();
    sqlx::query("SELECT channel_id FROM channels WHERE channel_id=$1 FOR UPDATE")
        .bind(a)
        .execute(&mut *lock)
        .await
        .unwrap();
    let mut jobs = Vec::new();
    for (u, d) in clients {
        let (svc, t) = (svc.clone(), token.clone());
        jobs.push(tokio::spawn(async move {
            svc.subscribe_channel(request(
                u,
                &d,
                proto::SubscribeChannelRequest {
                    channel_id: a.to_string(),
                    invite_token: t,
                },
            ))
            .await
        }));
    }
    // The pool has spare connections for an observer while all eight RPCs wait.
    let ready = tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND query LIKE '%SELECT visibility::TEXT, max_subscribers FROM channels%' AND query NOT LIKE '%pg_stat_activity%'")
                .fetch_one(&db.pool).await.unwrap();
            if count >= 2 { break; }
            tokio::task::yield_now().await;
        }
    }).await;
    lock.rollback().await.unwrap();
    let mut wins = 0;
    let mut denied = 0;
    for job in jobs {
        match job.await.unwrap() {
            Ok(_) => wins += 1,
            Err(e) => {
                assert_eq!(e.code(), Code::ResourceExhausted);
                denied += 1;
            }
        }
    }
    let count = ch::get_channel_subscriber_count(&db.pool, a).await.unwrap();
    clear_subscription_limits(&svc, &users).await;
    db.cleanup().await;
    assert!(
        ready.is_ok(),
        "at least two real RPCs must contend on the invite row"
    );
    assert_eq!(wins, 1);
    assert_eq!(denied, 7);
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn competing_submit_commit_rpcs_accept_only_one_commit_for_an_epoch() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (user, device, _) = create_test_device(&db.pool).await;
    let group = create_test_group_in_db(&db.pool, &device).await;
    let svc = Arc::new(make_test_service(Arc::new(db.pool.clone())).await);
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut jobs = Vec::new();
    for n in 1..=8 {
        let (svc, d, b) = (svc.clone(), device.clone(), barrier.clone());
        jobs.push(tokio::spawn(async move {
            b.wait().await;
            (
                n,
                svc.submit_commit(request(
                    user,
                    &d,
                    proto::SubmitCommitRequest {
                        group_id: group.to_string(),
                        epoch: 0,
                        mls_commit: vec![n],
                        new_ratchet_tree: vec![n, 0],
                        welcome_deliveries: vec![],
                    },
                ))
                .await,
            )
        }));
    }
    let mut winners = Vec::new();
    let mut epochs = Vec::new();
    let mut errors = Vec::new();
    for job in jobs {
        let (n, result) = job.await.unwrap();
        match result {
            Ok(r) => {
                epochs.push(r.into_inner().new_epoch);
                winners.push(n);
            }
            Err(e) => errors.push(e.code()),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(epochs, vec![1]);
    assert_eq!(errors, vec![Code::Aborted; 7]);
    let commits = construct_db::mls::get_group_commits_since(&db.pool, group, 0)
        .await
        .unwrap();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].mls_commit, vec![winners[0]]);
    let state: (i64, Vec<u8>) =
        sqlx::query_as("SELECT epoch,ratchet_tree FROM mls_groups WHERE group_id=$1")
            .bind(group)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(state, (1, vec![winners[0], 0]));
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn concurrent_signed_ownership_requests_reject_the_stale_owner_as_permission_denied() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, owner, key) = create_test_device(&db.pool).await;
    let g = create_test_group_in_db(&db.pool, &owner).await;
    let svc = Arc::new(make_test_service(Arc::new(db.pool.clone())).await);
    let mut requests = Vec::new();
    for leaf in 1..=2 {
        let (_, d, k) = create_test_device(&db.pool).await;
        construct_db::mls::insert_group_member(
            &db.pool,
            construct_db::mls::NewGroupMember {
                group_id: g,
                device_id: &d,
                leaf_index: leaf,
                acceptance_signature: Some(b"opaque"),
                joined_at: chrono::Utc::now(),
            },
        )
        .await
        .unwrap();
        construct_db::mls::upsert_group_admin_role(
            &db.pool,
            g,
            &d,
            1,
            None,
            &owner,
            chrono::Utc::now(),
        )
        .await
        .unwrap();
        let ts = chrono::Utc::now().timestamp();
        requests.push(request(
            u,
            &owner,
            proto::TransferOwnershipRequest {
                group_id: g.to_string(),
                new_owner_device_id: d.clone(),
                signature_timestamp: ts,
                owner_signature: key
                    .sign(format!("CONSTRUCT_TRANSFER_OWNERSHIP:{g}:{d}:{ts}").as_bytes())
                    .to_bytes()
                    .to_vec(),
                new_owner_acceptance: k
                    .sign(format!("CONSTRUCT_ACCEPT_OWNERSHIP:{g}:{owner}:{ts}").as_bytes())
                    .to_bytes()
                    .to_vec(),
            },
        ));
    }
    let mut lock = db.pool.begin().await.unwrap();
    construct_db::mls::lock_group_epoch_for_update(&mut lock, g)
        .await
        .unwrap();
    let mut jobs = Vec::new();
    for req in requests {
        let svc = svc.clone();
        jobs.push(tokio::spawn(
            async move { svc.transfer_ownership(req).await },
        ));
    }
    let ready=tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND query LIKE '%SELECT epoch FROM mls_groups%' AND query NOT LIKE '%pg_stat_activity%'")
                .fetch_one(&db.pool).await.unwrap();
            if count>=2 { break; }
            if jobs.iter().any(|j|j.is_finished()) { break; }
            tokio::task::yield_now().await;
        }
    }).await;
    lock.rollback().await.unwrap();
    let mut wins = 0;
    let mut denied = 0;
    let mut codes = Vec::new();
    for job in jobs {
        match job.await.unwrap() {
            Ok(_) => wins += 1,
            Err(e) => {
                denied += 1;
                codes.push(e.code());
            }
        }
    }
    let creators: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_admins WHERE group_id=$1 AND is_creator")
            .bind(g)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    db.cleanup().await;
    assert!(ready.is_ok());
    assert_eq!(wins, 1);
    assert_eq!(denied, 1);
    assert_eq!(creators, 1);
    assert_eq!(codes, vec![Code::PermissionDenied]);
}
