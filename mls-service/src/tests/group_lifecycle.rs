use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db,
};
use crate::service::MlsServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

// ── CreateGroup ──────────────────────────────────────────────────

#[tokio::test]
async fn test_create_group_success() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let service = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let group_id = Uuid::new_v4();
    let meta = create_metadata(&user_id, &device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateGroupRequest {
            group_id: group_id.to_string(),
            initial_ratchet_tree: vec![1, 2, 3, 4],
            encrypted_group_context: vec![5, 6, 7, 8],
            max_members: 100,
            message_retention_days: 30,
            threads_enabled: true,
        },
    );

    let response = service
        .create_group(request)
        .await
        .expect("CreateGroup should succeed");
    let inner = response.into_inner();

    assert_eq!(inner.group_id, group_id.to_string());
    assert_eq!(inner.epoch, 0);
    assert!(inner.created_at > 0);
}

#[tokio::test]
async fn test_create_group_invalid_group_id() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateGroupRequest {
            group_id: "not-a-uuid".to_string(),
            initial_ratchet_tree: vec![1, 2, 3],
            encrypted_group_context: vec![4, 5, 6],
            max_members: 100,
            message_retention_days: 90,
            threads_enabled: false,
        },
    );

    let result = service.create_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_group_empty_ratchet_tree() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateGroupRequest {
            group_id: Uuid::new_v4().to_string(),
            initial_ratchet_tree: vec![],
            encrypted_group_context: vec![4, 5, 6],
            max_members: 100,
            message_retention_days: 90,
            threads_enabled: false,
        },
    );

    let result = service.create_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_group_max_members_exceeded() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateGroupRequest {
            group_id: Uuid::new_v4().to_string(),
            initial_ratchet_tree: vec![1, 2, 3],
            encrypted_group_context: vec![4, 5, 6],
            max_members: 2049,
            message_retention_days: 90,
            threads_enabled: false,
        },
    );

    let result = service.create_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_group_missing_user_id() {
    let db = get_test_db().await;
    let (_, device_id, _) = create_test_device(&db).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let mut meta = tonic::metadata::MetadataMap::new();
    meta.insert("x-device-id", device_id.parse().unwrap());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateGroupRequest {
            group_id: Uuid::new_v4().to_string(),
            initial_ratchet_tree: vec![1, 2, 3],
            encrypted_group_context: vec![4, 5, 6],
            max_members: 100,
            message_retention_days: 90,
            threads_enabled: false,
        },
    );

    let result = service.create_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
}

// ── GetGroupState ────────────────────────────────────────────────

#[tokio::test]
async fn test_get_group_state_success() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetGroupStateRequest {
            group_id: group_id.to_string(),
            known_epoch: None,
        },
    );

    let response = service
        .get_group_state(request)
        .await
        .expect("GetGroupState should succeed");
    let inner = response.into_inner();

    assert_eq!(inner.epoch, 0);
    assert!(inner.ratchet_tree.is_some());
    assert!(inner.settings.is_some());
    assert_eq!(inner.settings.as_ref().unwrap().member_count, 1);
}

#[tokio::test]
async fn test_get_group_state_non_member() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = Uuid::new_v4();
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetGroupStateRequest {
            group_id: group_id.to_string(),
            known_epoch: None,
        },
    );

    let result = service.get_group_state(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

// ── DissolveGroup ────────────────────────────────────────────────

#[tokio::test]
async fn test_dissolve_group_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;
    let service = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DissolveGroupRequest {
            group_id: group_id.to_string(),
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
        },
    );

    let response = service
        .dissolve_group(request)
        .await
        .expect("DissolveGroup should succeed");
    let inner = response.into_inner();

    assert!(inner.success);
    assert!(inner.dissolved_at > 0);

    let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
            .bind(group_id)
            .fetch_optional(db.as_ref())
            .await
            .expect("Failed to query")
            .flatten();

    assert!(dissolved_at.is_some());
}

#[tokio::test]
async fn test_dissolve_group_invalid_signature() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let wrong_signing_key = SigningKey::generate(&mut OsRng);
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
    let signature = wrong_signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DissolveGroupRequest {
            group_id: group_id.to_string(),
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
        },
    );

    let result = service.dissolve_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_dissolve_group_expired_timestamp() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;
    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let timestamp = Utc::now().timestamp() - 600; // 10 minutes ago
    let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DissolveGroupRequest {
            group_id: group_id.to_string(),
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
        },
    );

    let result = service.dissolve_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_dissolve_group_non_admin() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let (_user_id2, device_id2, _) = create_test_device(&db).await;

    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&device_id2)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add device2 to group");

    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id2);

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DissolveGroupRequest {
            group_id: group_id.to_string(),
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
        },
    );

    let result = service.dissolve_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_dissolve_group_already_dissolved() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    sqlx::query("UPDATE mls_groups SET dissolved_at = NOW() WHERE group_id = $1")
        .bind(group_id)
        .execute(db.as_ref())
        .await
        .expect("Failed to dissolve group");

    let service = MlsServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
    };

    let meta = create_metadata(&user_id, &device_id);

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DissolveGroupRequest {
            group_id: group_id.to_string(),
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
        },
    );

    let result = service.dissolve_group(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
}
