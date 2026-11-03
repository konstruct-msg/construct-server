use super::postgres;
use super::test_helpers::{create_metadata, create_test_device, make_test_service};
use construct_db::channel as ch;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};
use std::sync::Arc;
use tonic::{Code, Request};
use uuid::Uuid;
static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../shared/migrations");
fn req<T>(u: Uuid, d: &str, body: T) -> Request<T> {
    Request::from_parts(create_metadata(&u, d), tonic::Extensions::default(), body)
}
async fn subscribe(
    svc: &crate::service::GroupServiceImpl,
    u: Uuid,
    d: &str,
    c: Uuid,
    t: &str,
) -> Result<tonic::Response<proto::SubscribeChannelResponse>, tonic::Status> {
    svc.subscribe_channel(req(
        u,
        d,
        proto::SubscribeChannelRequest {
            channel_id: c.to_string(),
            invite_token: t.into(),
        },
    ))
    .await
}
async fn cleanup_limits(svc: &crate::service::GroupServiceImpl, users: &[Uuid]) {
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
async fn full_channel_does_not_spend_invite_and_successful_retry_is_idempotent() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, d, _) = create_test_device(&db.pool).await;
    let svc = make_test_service(Arc::new(db.pool.clone())).await;
    let c = ch::create_channel(&db.pool, "owner", "PRIVATE", b"opaque", 1, 30)
        .await
        .unwrap()
        .channel_id;
    ch::subscribe_to_channel(&db.pool, c, "owner", true)
        .await
        .unwrap();
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, c, "owner", Some(1), None)
        .await
        .unwrap();
    let denied = subscribe(&svc, u, &d, c, &token).await;
    let uses = ch::resolve_channel_invite_link(&db.pool, &token)
        .await
        .unwrap()
        .unwrap()
        .use_count;
    assert_eq!(denied.unwrap_err().code(), Code::ResourceExhausted);
    assert_eq!(uses, 0, "capacity refusal must not consume the invite");
    sqlx::query("UPDATE channels SET max_subscribers=2 WHERE channel_id=$1")
        .bind(c)
        .execute(&db.pool)
        .await
        .unwrap();
    let first = subscribe(&svc, u, &d, c, &token)
        .await
        .unwrap()
        .into_inner();
    let retry = subscribe(&svc, u, &d, c, &token)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.subscribed_at, retry.subscribed_at);
    assert_eq!(
        ch::get_channel_subscriber_count(&db.pool, c).await.unwrap(),
        2
    );
    assert_eq!(
        ch::resolve_channel_invite_link(&db.pool, &token)
            .await
            .unwrap()
            .unwrap()
            .use_count,
        1
    );
    cleanup_limits(&svc, &[u]).await;
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn failed_subscription_insert_rolls_back_invite_and_counter() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, d, _) = create_test_device(&db.pool).await;
    let svc = make_test_service(Arc::new(db.pool.clone())).await;
    let c = ch::create_channel(&db.pool, "owner", "PRIVATE", b"opaque", 0, 30)
        .await
        .unwrap()
        .channel_id;
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, c, "owner", Some(1), None)
        .await
        .unwrap();
    // Deterministic storage failure, confined to this test's private schema.
    sqlx::query(
        "ALTER TABLE channel_subscribers ADD CONSTRAINT reject_subscriptions CHECK (FALSE)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    let result = subscribe(&svc, u, &d, c, &token).await;
    let uses = ch::resolve_channel_invite_link(&db.pool, &token)
        .await
        .unwrap()
        .unwrap()
        .use_count;
    let count = ch::get_channel_subscriber_count(&db.pool, c).await.unwrap();
    let member = ch::is_channel_subscriber(&db.pool, c, &d).await.unwrap();
    cleanup_limits(&svc, &[u]).await;
    db.cleanup().await;
    assert_eq!(result.unwrap_err().code(), Code::Internal);
    assert_eq!(uses, 0);
    assert_eq!(count, 0);
    assert!(!member);
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn concurrent_public_subscriptions_respect_the_last_slot() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let svc = Arc::new(make_test_service(Arc::new(db.pool.clone())).await);
    let c = ch::create_channel(&db.pool, "owner", "PUBLIC", b"opaque", 1, 30)
        .await
        .unwrap()
        .channel_id;
    let mut lock = db.pool.begin().await.unwrap();
    sqlx::query("SELECT channel_id FROM channels WHERE channel_id=$1 FOR UPDATE")
        .bind(c)
        .execute(&mut *lock)
        .await
        .unwrap();
    let mut jobs = Vec::new();
    let mut users = Vec::new();
    for _ in 0..8 {
        let (u, d, _) = create_test_device(&db.pool).await;
        users.push(u);
        let svc = svc.clone();
        jobs.push(tokio::spawn(
            async move { subscribe(&svc, u, &d, c, "").await },
        ));
    }
    // Wait for actual channel-row contenders. The original code only blocks
    // after INSERT, when it updates the counter, so it also reproduces this race.
    let ready=tokio::time::timeout(std::time::Duration::from_secs(5),async{loop{
        let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND query NOT LIKE '%pg_stat_activity%'").fetch_one(&db.pool).await.unwrap();
        if n>=2{break;}tokio::task::yield_now().await;
    }}).await;
    lock.rollback().await.unwrap();
    let (mut wins, mut refused) = (0, 0);
    let mut codes = Vec::new();
    for job in jobs {
        match job.await.unwrap() {
            Ok(_) => wins += 1,
            Err(e) => {
                refused += 1;
                codes.push(e.code());
            }
        }
    }
    let count = ch::get_channel_subscriber_count(&db.pool, c).await.unwrap();
    let actual: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscribers WHERE channel_id=$1")
            .bind(c)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    cleanup_limits(&svc, &users).await;
    db.cleanup().await;
    assert!(ready.is_ok());
    assert_eq!(wins, 1);
    assert_eq!(refused, 7);
    assert!(codes.iter().all(|c| *c == Code::ResourceExhausted));
    assert_eq!(count, 1);
    assert_eq!(actual, 1);
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn channel_posts_require_membership_of_the_posts_own_channel() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, d, _) = create_test_device(&db.pool).await;
    let svc = make_test_service(Arc::new(db.pool.clone())).await;
    let a = ch::create_channel(&db.pool, "owner", "PRIVATE", b"a", 0, 30)
        .await
        .unwrap()
        .channel_id;
    let b = ch::create_channel(&db.pool, "owner", "PUBLIC", b"b", 0, 30)
        .await
        .unwrap()
        .channel_id;
    ch::subscribe_to_channel(&db.pool, b, &d, false)
        .await
        .unwrap();
    let post = ch::insert_channel_post(
        &db.pool,
        a,
        "owner",
        b"cipher",
        None,
        None,
        chrono::Utc::now() + chrono::Duration::days(1),
    )
    .await
    .unwrap();
    let list = svc
        .list_posts(req(
            u,
            &d,
            proto::ListPostsRequest {
                channel_id: a.to_string(),
                ..Default::default()
            },
        ))
        .await;
    let get = svc
        .get_post(req(
            u,
            &d,
            proto::GetPostRequest {
                post_id: post.post_id.to_string(),
            },
        ))
        .await;
    assert_eq!(list.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(get.unwrap_err().code(), Code::PermissionDenied);
    ch::subscribe_to_channel(&db.pool, a, &d, false)
        .await
        .unwrap();
    let list = svc
        .list_posts(req(
            u,
            &d,
            proto::ListPostsRequest {
                channel_id: a.to_string(),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let get = svc
        .get_post(req(
            u,
            &d,
            proto::GetPostRequest {
                post_id: post.post_id.to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.posts.len(), 1);
    assert_eq!(list.posts[0].ciphertext, b"cipher");
    assert_eq!(get.post.unwrap().ciphertext, b"cipher");
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn zero_cleanup_interval_does_not_panic_on_worker_start() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let pool = db.pool.clone();
    let result = tokio::spawn(crate::cleanup::cleanup_worker(pool, 0, async {})).await;
    db.cleanup().await;
    assert!(result.is_ok());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn unsubscribe_keeps_membership_visible_until_its_counter_can_commit() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let c = ch::create_channel(&db.pool, "owner", "PUBLIC", b"opaque", 0, 30)
        .await
        .unwrap()
        .channel_id;
    ch::subscribe_to_channel(&db.pool, c, "member", false)
        .await
        .unwrap();
    let mut lock = db.pool.begin().await.unwrap();
    sqlx::query("SELECT channel_id FROM channels WHERE channel_id=$1 FOR UPDATE")
        .bind(c)
        .execute(&mut *lock)
        .await
        .unwrap();
    let pool = db.pool.clone();
    let job = tokio::spawn(async move {
        ch::unsubscribe_from_channel(&pool, c, "member")
            .await
            .unwrap()
    });
    let waited=tokio::time::timeout(std::time::Duration::from_secs(5),async{loop{
        let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND query NOT LIKE '%pg_stat_activity%'").fetch_one(&db.pool).await.unwrap();
        if n>=1{break;}tokio::task::yield_now().await;
    }}).await;
    let visible = ch::is_channel_subscriber(&db.pool, c, "member")
        .await
        .unwrap();
    lock.rollback().await.unwrap();
    let removed = job.await.unwrap();
    let count = ch::get_channel_subscriber_count(&db.pool, c).await.unwrap();
    db.cleanup().await;
    assert!(waited.is_ok());
    assert!(
        visible,
        "membership must not disappear ahead of its counter transaction"
    );
    assert!(removed);
    assert_eq!(count, 0);
}

fn counter(name: &str) -> f64 {
    prometheus::gather()
        .iter()
        .find(|f| f.name() == name)
        .and_then(|f| f.get_metric().first())
        .map(|m| m.get_counter().value())
        .unwrap_or(0.0)
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn private_admission_preserves_invite_errors_and_unlimited_capacity() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, d, _) = create_test_device(&db.pool).await;
    let svc = make_test_service(Arc::new(db.pool.clone())).await;
    let a = ch::create_channel(&db.pool, "owner", "PRIVATE", b"a", 0, 30)
        .await
        .unwrap()
        .channel_id;
    let b = ch::create_channel(&db.pool, "owner", "PRIVATE", b"b", 0, 30)
        .await
        .unwrap()
        .channel_id;
    let mut cases = vec![
        (String::new(), Code::PermissionDenied),
        ("missing".into(), Code::NotFound),
    ];
    for (channel, expired, revoked, exhausted, code) in [
        (b, false, false, false, Code::PermissionDenied),
        (a, true, false, false, Code::PermissionDenied),
        (a, false, true, false, Code::PermissionDenied),
        (a, false, false, true, Code::ResourceExhausted),
    ] {
        let token = Uuid::new_v4().simple().to_string();
        ch::create_channel_invite_link(
            &db.pool,
            &token,
            channel,
            "owner",
            Some(1),
            expired.then(|| chrono::Utc::now() - chrono::Duration::hours(1)),
        )
        .await
        .unwrap();
        if revoked {
            ch::revoke_channel_invite_link(&db.pool, channel, &token)
                .await
                .unwrap();
        }
        if exhausted {
            assert!(
                ch::increment_channel_invite_link_usage(&db.pool, &token)
                    .await
                    .unwrap()
            );
        }
        cases.push((token, code));
    }
    for (token, code) in cases {
        assert_eq!(
            subscribe(&svc, u, &d, a, &token).await.unwrap_err().code(),
            code
        );
    }
    assert!(!ch::is_channel_subscriber(&db.pool, a, &d).await.unwrap());
    assert_eq!(
        ch::get_channel_subscriber_count(&db.pool, a).await.unwrap(),
        0
    );
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, a, "owner", None, None)
        .await
        .unwrap();
    let first = subscribe(&svc, u, &d, a, &token)
        .await
        .unwrap()
        .into_inner();
    let retry = subscribe(&svc, u, &d, a, "").await.unwrap().into_inner();
    assert_eq!(first.subscribed_at, retry.subscribed_at);
    assert_eq!(
        ch::resolve_channel_invite_link(&db.pool, &token)
            .await
            .unwrap()
            .unwrap()
            .use_count,
        1
    );
    cleanup_limits(&svc, &[u]).await;
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn invite_revoked_while_usage_update_waits_cannot_create_a_subscription() {
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, d, _) = create_test_device(&db.pool).await;
    let svc = Arc::new(make_test_service(Arc::new(db.pool.clone())).await);
    let c = ch::create_channel(&db.pool, "owner", "PRIVATE", b"opaque", 0, 30)
        .await
        .unwrap()
        .channel_id;
    let token = Uuid::new_v4().simple().to_string();
    ch::create_channel_invite_link(&db.pool, &token, c, "owner", Some(1), None)
        .await
        .unwrap();
    let mut revocation = db.pool.begin().await.unwrap();
    sqlx::query("UPDATE channel_invite_links SET revoked_at=NOW() WHERE token=$1")
        .bind(&token)
        .execute(&mut *revocation)
        .await
        .unwrap();
    let (s, t, dev) = (svc.clone(), token.clone(), d.clone());
    let job = tokio::spawn(async move { subscribe(&s, u, &dev, c, &t).await });
    let waited=tokio::time::timeout(std::time::Duration::from_secs(5),async{loop{
        let n:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND query LIKE '%UPDATE channel_invite_links%' AND query NOT LIKE '%pg_stat_activity%'").fetch_one(&db.pool).await.unwrap();
        if n>=1{break;}
        if job.is_finished(){break;}
        tokio::task::yield_now().await;
    }}).await;
    revocation.commit().await.unwrap();
    let result = job.await.unwrap();
    let member = ch::is_channel_subscriber(&db.pool, c, &d).await.unwrap();
    let count = ch::get_channel_subscriber_count(&db.pool, c).await.unwrap();
    cleanup_limits(&svc, &[u]).await;
    db.cleanup().await;
    assert!(waited.is_ok());
    assert_eq!(result.unwrap_err().code(), Code::ResourceExhausted);
    assert!(!member);
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires Postgres and Redis"]
async fn production_events_increment_their_prometheus_series() {
    use super::test_helpers::create_test_group_in_db;
    use construct_server_shared::shared::proto::services::v1::mls_service_server::MlsService;
    let db = postgres::Database::new(&MIGRATIONS).await;
    let (u, d, _) = create_test_device(&db.pool).await;
    let g = create_test_group_in_db(&db.pool, &d).await;
    let svc = make_test_service(Arc::new(db.pool.clone())).await;
    let sent = counter("mls_group_messages_sent_total");
    let commits = counter("mls_commits_submitted_total");
    let mismatches = counter("mls_epoch_mismatches_total");
    let cleaned = counter("mls_cleanup_deleted_total");
    let body = proto::SendGroupMessageRequest {
        group_id: g.to_string(),
        epoch: 0,
        mls_ciphertext: vec![1],
        ..Default::default()
    };
    svc.send_group_message(req(u, &d, body.clone()))
        .await
        .unwrap();
    svc.submit_commit(req(
        u,
        &d,
        proto::SubmitCommitRequest {
            group_id: g.to_string(),
            epoch: 0,
            mls_commit: vec![1],
            new_ratchet_tree: vec![2],
            ..Default::default()
        },
    ))
    .await
    .unwrap();
    assert_eq!(
        svc.send_group_message(req(u, &d, body))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        svc.submit_commit(req(
            u,
            &d,
            proto::SubmitCommitRequest {
                group_id: g.to_string(),
                epoch: 0,
                mls_commit: vec![1],
                new_ratchet_tree: vec![2],
                ..Default::default()
            }
        ))
        .await
        .unwrap_err()
        .code(),
        Code::Aborted
    );
    assert!(counter("mls_group_messages_sent_total") >= sent + 1.0);
    assert!(counter("mls_commits_submitted_total") >= commits + 1.0);
    assert!(counter("mls_epoch_mismatches_total") >= mismatches + 2.0);
    sqlx::query("UPDATE group_messages SET expires_at=NOW()-INTERVAL '1 hour' WHERE group_id=$1")
        .bind(g)
        .execute(&db.pool)
        .await
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(crate::cleanup::cleanup_worker(db.pool.clone(), 24, async {
        let _ = stopped.await;
    }));
    let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if counter("mls_cleanup_deleted_total") >= cleaned + 1.0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    stop.send(()).unwrap();
    worker.await.unwrap();
    db.cleanup().await;
    assert!(observed.is_ok());
}
