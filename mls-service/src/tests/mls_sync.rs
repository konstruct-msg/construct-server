use chrono::Utc;
use tonic::Request;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db,
};
use crate::service::MlsServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

// ── SubmitCommit ──────────────────────────────────────────────────

#[tokio::test]
async fn test_submit_commit_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let service = MlsServiceImpl { db: db.clone() };
    let meta = create_metadata(&_admin_user_id, &admin_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::SubmitCommitRequest {
            group_id: group_id.to_string(),
            epoch: 0,
            mls_commit: vec![1, 2, 3, 4],
            welcome_deliveries: vec![],
            new_ratchet_tree: vec![5, 6, 7, 8],
        },
    );

    let response = service
        .submit_commit(request)
        .await
        .expect("SubmitCommit should succeed");
    let inner = response.into_inner();

    assert!(inner.success);
    assert_eq!(inner.new_epoch, 1);
    assert!(inner.committed_at > 0);

    // Verify epoch updated in DB
    let epoch: i64 = sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE group_id = $1")
        .bind(group_id)
        .fetch_optional(db.as_ref())
        .await
        .expect("Failed to query")
        .flatten()
        .unwrap_or(0);

    assert_eq!(epoch, 1);

    // Verify commit stored
    let commit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_commits WHERE group_id = $1")
            .bind(group_id)
            .fetch_optional(db.as_ref())
            .await
            .expect("Failed to query")
            .flatten()
            .unwrap_or(0);

    assert_eq!(commit_count, 1);
}

#[tokio::test]
async fn test_submit_commit_epoch_mismatch() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    let service = MlsServiceImpl { db };
    let meta = create_metadata(&_admin_user_id, &admin_device_id);

    // Try to submit with wrong epoch (1 instead of 0)
    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::SubmitCommitRequest {
            group_id: group_id.to_string(),
            epoch: 1, // Wrong! Should be 0
            mls_commit: vec![1, 2, 3],
            welcome_deliveries: vec![],
            new_ratchet_tree: vec![4, 5, 6],
        },
    );

    let result = service.submit_commit(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Aborted);
}

#[tokio::test]
async fn test_submit_commit_non_member() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Create non-member
    let (non_member_user_id, non_member_device_id, _) = create_test_device(&db).await;

    let service = MlsServiceImpl { db };
    let meta = create_metadata(&non_member_user_id, &non_member_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::SubmitCommitRequest {
            group_id: group_id.to_string(),
            epoch: 0,
            mls_commit: vec![1, 2, 3],
            welcome_deliveries: vec![],
            new_ratchet_tree: vec![4, 5, 6],
        },
    );

    let result = service.submit_commit(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

// ── FetchCommits ──────────────────────────────────────────────────

#[tokio::test]
async fn test_fetch_commits_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Insert 3 commits
    let now = Utc::now();
    for epoch in 0i64..3 {
        sqlx::query(
            r#"
                INSERT INTO group_commits
                    (group_id, epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot, committed_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
        )
        .bind(group_id)
        .bind(epoch)
        .bind(epoch + 1)
        .bind(vec![epoch as u8])
        .bind(vec![epoch as u8, epoch as u8])
        .bind(now)
        .bind(now + chrono::Duration::days(30))
        .execute(db.as_ref())
        .await
        .expect("Failed to insert commit");
    }

    let service = MlsServiceImpl { db };
    let meta = create_metadata(&_admin_user_id, &admin_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::FetchCommitsRequest {
            group_id: group_id.to_string(),
            since_epoch: 0,
        },
    );

    let response = service
        .fetch_commits(request)
        .await
        .expect("FetchCommits should succeed");

    // Collect stream items
    let stream = response.into_inner();
    let items: Vec<_> = futures_util::StreamExt::collect(stream).await;

    assert_eq!(items.len(), 3);
}

#[tokio::test]
async fn test_fetch_commits_non_member() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Create non-member
    let (non_member_user_id, non_member_device_id, _) = create_test_device(&db).await;

    let service = MlsServiceImpl { db };
    let meta = create_metadata(&non_member_user_id, &non_member_device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::FetchCommitsRequest {
            group_id: group_id.to_string(),
            since_epoch: 0,
        },
    );

    let result = service.fetch_commits(request).await;
    assert!(result.is_err());
    // unwrap_err requires Debug on Ok type, so check manually
    if let Err(e) = result {
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
    }
}
