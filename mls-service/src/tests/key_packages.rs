use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db,
};
use crate::service::{GroupHub, MlsServiceImpl};
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

// ── PublishKeyPackage ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_publish_key_package_success() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
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

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
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
        "Empty key_packages should return INVALID_ARGUMENT"
    );
}

// ── B4 Regression: PublishKeyPackage ownership check ─────────────────────────
// B4: caller must not be able to publish KeyPackages for a device they don't own.

#[tokio::test]
async fn test_publish_key_package_wrong_device_rejected() {
    let db = get_test_db().await;
    // Attacker's device
    let (attacker_user_id, attacker_device_id, _) = create_test_device(&db).await;
    // Victim's device
    let (_victim_user_id, victim_device_id, _) = create_test_device(&db).await;

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
    };
    // Attacker authenticates as themselves but requests to publish for victim's device
    let meta = create_metadata(&attacker_user_id, &attacker_device_id);

    let result = service
        .publish_key_package(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::PublishKeyPackageRequest {
                device_id: victim_device_id.clone(), // attacker claims victim's device_id
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

// ── ConsumeKeyPackage ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_consume_key_package_success() {
    let db = get_test_db().await;
    let (admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let (target_user_id, target_device_id, _) = create_test_device(&db).await;

    // Publish a KeyPackage for target user/device directly
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

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
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
    let empty_user_id = Uuid::new_v4(); // no KeyPackages published

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
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
        "Should return NOT_FOUND when user has no KeyPackages"
    );
}

// ── GetKeyPackageCount ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_key_package_count_zero() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
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

    let service = MlsServiceImpl {
        db: db.clone(),
        hub: GroupHub::new(),
    };
    let meta = create_metadata(&user_id, &device_id);

    // Publish 5 KeyPackages
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

// ── GetPendingInvites: B3 Regression ─────────────────────────────────────────
// B3: if req.device_id is provided, server must verify it belongs to the caller.

#[tokio::test]
async fn test_get_pending_invites_cross_device_rejected() {
    let db = get_test_db().await;
    let (attacker_user_id, attacker_device_id, _) = create_test_device(&db).await;
    let (_victim_user_id, victim_device_id, _) = create_test_device(&db).await;

    let group_id = create_test_group_in_db(&db, &attacker_device_id).await;

    // Create an invite for the victim's device
    let now = chrono::Utc::now();
    sqlx::query(
        r#"INSERT INTO group_invites
               (invite_id, group_id, target_device_id, mls_welcome, epoch, expires_at, invited_at)
           VALUES (gen_random_uuid(), $1, $2, $3, 0, $4, $4)"#,
    )
    .bind(group_id)
    .bind(&victim_device_id)
    .bind(b"welcome-blob".to_vec())
    .bind(now + chrono::Duration::hours(1))
    .execute(db.as_ref())
    .await
    .expect("Failed to create invite for victim");

    let service = MlsServiceImpl {
        db,
        hub: GroupHub::new(),
    };
    // Attacker authenticates as themselves but requests victim's invites
    let meta = create_metadata(&attacker_user_id, &attacker_device_id);

    let result = service
        .get_pending_invites(Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetPendingInvitesRequest {
                device_id: victim_device_id.clone(), // override to victim's device
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
