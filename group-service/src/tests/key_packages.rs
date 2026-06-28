use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db,
};
use crate::service::{GroupHub, GroupServiceImpl};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

#[tokio::test]
async fn test_publish_key_package_success() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&user_id, &device_id);

    let response = service
        .publish_key_package(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::PublishKeyPackageRequest {
                device_id: device_id.clone(),
                key_packages: vec![
                    b"kp-blob-1".to_vec(),
                    b"kp-blob-2".to_vec(),
                    b"kp-blob-3".to_vec(),
                ],
            },
        ))
        .await
        .expect("PublishKeyPackage should succeed");

    let inner = response.into_inner();
    assert_eq!(inner.count, 3);
    assert!(inner.published_at > 0);
}

#[tokio::test]
async fn test_publish_key_package_empty_list_rejected() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&user_id, &device_id);

    let result = service
        .publish_key_package(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::PublishKeyPackageRequest {
                device_id: device_id.clone(),
                key_packages: vec![],
            },
        ))
        .await;

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code(),
        tonic::Code::InvalidArgument,
    );
}

#[tokio::test]
async fn test_publish_key_package_wrong_device_rejected() {
    let db = get_test_db().await;
    let (attacker_user_id, attacker_device_id, _) = create_test_device(&db).await;
    let (_victim_user_id, victim_device_id, _) = create_test_device(&db).await;

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&attacker_user_id, &attacker_device_id);

    let result = service
        .publish_key_package(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::PublishKeyPackageRequest {
                device_id: victim_device_id.clone(),
                key_packages: vec![b"evil-kp".to_vec()],
            },
        ))
        .await;

    assert!(result.is_err(), "Should reject cross-device publish");
    let code = result.unwrap_err().code();
    assert!(
        code == tonic::Code::PermissionDenied || code == tonic::Code::InvalidArgument,
        "Expected PermissionDenied or InvalidArgument, got {code:?}"
    );
}

#[tokio::test]
async fn test_consume_key_package_success() {
    let db = get_test_db().await;
    let (admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let (target_user_id, target_device_id, _) = create_test_device(&db).await;

    let kp_bytes = b"test-key-package-blob".to_vec();
    let kp_ref: Vec<u8> = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&kp_bytes);
        h.finalize().to_vec()
    };
    let now = chrono::Utc::now();
    sqlx::query(
        r#"INSERT INTO group_key_packages
               (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(target_user_id)
    .bind(&target_device_id)
    .bind(&kp_bytes)
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::days(30))
    .execute(db.as_ref())
    .await
    .expect("Failed to insert KeyPackage");

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&admin_user_id, &admin_device_id);

    let response = service
        .consume_key_package(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::ConsumeKeyPackageRequest {
                user_id: target_user_id.to_string(),
                preferred_device_id: None,
            },
        ))
        .await
        .expect("ConsumeKeyPackage should succeed");

    let inner = response.into_inner();
    assert_eq!(inner.key_package, kp_bytes);
    assert_eq!(inner.device_id, target_device_id);
    assert_eq!(inner.key_package_ref, kp_ref);
}

#[tokio::test]
async fn test_consume_key_package_not_found() {
    let db = get_test_db().await;
    let (admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let empty_user_id = Uuid::new_v4();

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&admin_user_id, &admin_device_id);

    let result = service
        .consume_key_package(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::ConsumeKeyPackageRequest {
                user_id: empty_user_id.to_string(),
                preferred_device_id: None,
            },
        ))
        .await;

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code(),
        tonic::Code::NotFound,
    );
}

#[tokio::test]
async fn test_get_key_package_count_zero() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&user_id, &device_id);

    let response = service
        .get_key_package_count(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetKeyPackageCountRequest {
                user_id: user_id.to_string(),
                device_id: None,
            },
        ))
        .await
        .expect("GetKeyPackageCount should succeed even for zero");

    let inner = response.into_inner();
    assert_eq!(inner.count, 0);
    assert!(
        inner.cannot_be_invited,
        "Zero KeyPackages should set cannot_be_invited"
    );
}

#[tokio::test]
async fn test_get_key_package_count_after_publish() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;

    let service = GroupServiceImpl {
        db: db.clone(),
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&user_id, &device_id);

    service
        .publish_key_package(Request::from_parts(
            meta.clone(),
            tonic::Extensions::default(),
            proto::PublishKeyPackageRequest {
                device_id: device_id.clone(),
                key_packages: (0..5)
                    .map(|i| format!("kp-{i}-{user_id}").into_bytes())
                    .collect(),
            },
        ))
        .await
        .expect("PublishKeyPackage should succeed");

    let meta2 = create_metadata(&user_id, &device_id);
    let response = service
        .get_key_package_count(Request::from_parts(
            meta2,
            tonic::Extensions::default(),
            proto::GetKeyPackageCountRequest {
                user_id: user_id.to_string(),
                device_id: Some(device_id.clone()),
            },
        ))
        .await
        .expect("GetKeyPackageCount should succeed");

    let inner = response.into_inner();
    assert_eq!(inner.count, 5);
    assert!(
        !inner.cannot_be_invited,
        "Should be invitable with 5 KeyPackages"
    );
}

#[tokio::test]
async fn test_get_pending_invites_cross_device_rejected() {
    let db = get_test_db().await;
    let (attacker_user_id, attacker_device_id, _) = create_test_device(&db).await;
    let (_victim_user_id, victim_device_id, _) = create_test_device(&db).await;

    let group_id = create_test_group_in_db(&db, &attacker_device_id).await;

    let now = chrono::Utc::now();
    sqlx::query(
        r#"INSERT INTO group_invites
               (invite_id, group_id, target_device_id, mls_welcome, key_package_ref, epoch, expires_at, invited_at)
           VALUES (gen_random_uuid(), $1, $2, $3, $4, 0, $5, $5)"#,
    )
    .bind(group_id)
    .bind(&victim_device_id)
    .bind(b"welcome-blob".to_vec())
    .bind(vec![0u8; 32])
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite for victim");

    let service = GroupServiceImpl {
        db,
        hub: GroupHub::new(),
        notification_client: None,
    };
    let meta = create_metadata(&attacker_user_id, &attacker_device_id);

    let result = service
        .get_pending_invites(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetPendingInvitesRequest {
                device_id: victim_device_id.clone(),
                cursor: None,
                limit: 10,
            },
        ))
        .await;

    assert!(
        result.is_err(),
        "B3: cross-device invite fetch must be rejected"
    );
    let code = result.unwrap_err().code();
    assert!(
        code == tonic::Code::PermissionDenied || code == tonic::Code::NotFound,
        "Expected PermissionDenied or NotFound, got {code:?}"
    );
}
