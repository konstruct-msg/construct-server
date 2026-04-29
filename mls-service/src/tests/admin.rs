use chrono::Utc;
use ed25519_dalek::Signer;
use tonic::Request;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db,
};
use crate::service::MlsServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

// ── DelegateAdmin ─────────────────────────────────────────────────

#[tokio::test]
async fn test_delegate_admin_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, admin_signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Create a regular member
    let (_member_user_id, member_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add member");

    let service = MlsServiceImpl { db: db.clone() };
    let meta = create_metadata(&_admin_user_id, &admin_device_id);

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_DELEGATE_ADMIN:{}:{}:{}",
        group_id, member_device_id, timestamp
    );
    let signature = admin_signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DelegateAdminRequest {
            group_id: group_id.to_string(),
            target_device_id: member_device_id.clone(),
            role: proto::AdminRole::Full as i32,
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
            encrypted_admin_token: vec![],
        },
    );

    let response = service
        .delegate_admin(request)
        .await
        .expect("DelegateAdmin should succeed");
    assert!(response.into_inner().success);

    // Verify admin role
    let role: i16 =
        sqlx::query_scalar("SELECT role FROM group_admins WHERE group_id = $1 AND device_id = $2")
            .bind(group_id)
            .bind(&member_device_id)
            .fetch_optional(db.as_ref())
            .await
            .expect("Failed to query")
            .flatten()
            .unwrap_or(0);

    assert_eq!(role, 1); // FULL
}

#[tokio::test]
async fn test_delegate_admin_non_admin() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Create a regular member
    let (member_user_id, member_device_id, member_signing_key) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&member_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add member");

    // Create another member to delegate
    let (_other_user_id, other_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 2, $3)",
    )
    .bind(group_id)
    .bind(&other_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other member");

    let service = MlsServiceImpl { db };
    let meta = create_metadata(&member_user_id, &member_device_id);

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_DELEGATE_ADMIN:{}:{}:{}",
        group_id, other_device_id, timestamp
    );
    let signature = member_signing_key.sign(message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DelegateAdminRequest {
            group_id: group_id.to_string(),
            target_device_id: other_device_id,
            role: proto::AdminRole::Full as i32,
            admin_proof: signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
            encrypted_admin_token: vec![],
        },
    );

    let result = service.delegate_admin(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}

// ── TransferOwnership ─────────────────────────────────────────────

#[tokio::test]
async fn test_transfer_ownership_success() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, admin_signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Create a second admin
    let (_other_admin_user_id, other_admin_device_id, other_admin_signing_key) =
        create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other admin as member");

    sqlx::query(
        "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, false, $3)",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other admin");

    let service = MlsServiceImpl { db: db.clone() };
    let meta = create_metadata(&_admin_user_id, &admin_device_id);

    let timestamp = Utc::now().timestamp();

    // Owner signature
    let owner_message = format!(
        "CONSTRUCT_TRANSFER_OWNERSHIP:{}:{}:{}",
        group_id, other_admin_device_id, timestamp
    );
    let owner_signature = admin_signing_key.sign(owner_message.as_bytes());

    // New owner acceptance
    let acceptance_message = format!(
        "CONSTRUCT_ACCEPT_OWNERSHIP:{}:{}:{}",
        group_id, admin_device_id, timestamp
    );
    let acceptance_signature = other_admin_signing_key.sign(acceptance_message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::TransferOwnershipRequest {
            group_id: group_id.to_string(),
            new_owner_device_id: other_admin_device_id.clone(),
            owner_signature: owner_signature.to_bytes().to_vec(),
            new_owner_acceptance: acceptance_signature.to_bytes().to_vec(),
            signature_timestamp: timestamp,
        },
    );

    let response = service
        .transfer_ownership(request)
        .await
        .expect("TransferOwnership should succeed");
    assert!(response.into_inner().success);

    // Verify old owner is no longer creator
    let old_is_creator: bool = sqlx::query_scalar(
        "SELECT is_creator FROM group_admins WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(&admin_device_id)
    .fetch_optional(db.as_ref())
    .await
    .expect("Failed to query")
    .flatten()
    .unwrap_or(true);

    assert!(!old_is_creator);

    // Verify new owner is creator
    let new_is_creator: bool = sqlx::query_scalar(
        "SELECT is_creator FROM group_admins WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .fetch_optional(db.as_ref())
    .await
    .expect("Failed to query")
    .flatten()
    .unwrap_or(false);

    assert!(new_is_creator);
}

#[tokio::test]
async fn test_transfer_ownership_non_creator() {
    let db = get_test_db().await;
    let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &admin_device_id).await;

    // Create a second admin (not creator)
    let (other_admin_user_id, other_admin_device_id, other_admin_signing_key) =
        create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other admin as member");

    sqlx::query(
        "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, false, $3)",
    )
    .bind(group_id)
    .bind(&other_admin_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .expect("Failed to add other admin");

    let service = MlsServiceImpl { db };
    let meta = create_metadata(&other_admin_user_id, &other_admin_device_id);

    let timestamp = Utc::now().timestamp();

    // Non-creator tries to transfer
    let owner_message = format!(
        "CONSTRUCT_TRANSFER_OWNERSHIP:{}:{}:{}",
        group_id, admin_device_id, timestamp
    );
    let owner_signature = other_admin_signing_key.sign(owner_message.as_bytes());

    let request = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::TransferOwnershipRequest {
            group_id: group_id.to_string(),
            new_owner_device_id: admin_device_id,
            owner_signature: owner_signature.to_bytes().to_vec(),
            new_owner_acceptance: vec![], // Not relevant, will fail before
            signature_timestamp: timestamp,
        },
    );

    let result = service.transfer_ownership(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
}
