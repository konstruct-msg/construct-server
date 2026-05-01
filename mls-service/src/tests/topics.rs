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

// ── CreateTopic ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_topic_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"encrypted_topic_name".to_vec(),
        sort_order: 0,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let response = svc.create_topic(request).await.unwrap();
    let resp = response.into_inner();

    assert!(!resp.topic_id.is_empty());
    assert!(resp.created_at > 0);
}

#[tokio::test]
async fn test_create_topic_non_admin() {
    let db = get_test_db().await;
    let (_user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    // Create another device that's not an admin (just a member)
    let (_, other_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&other_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .unwrap();

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"encrypted_topic_name".to_vec(),
        sort_order: 0,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let (other_user_id, _, _) = create_test_device(&db).await;
    let metadata = create_metadata(&other_user_id, &other_device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.create_topic(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_create_topic_empty_name() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: vec![], // Empty
        sort_order: 0,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.create_topic(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_topic_invalid_sort_order() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"encrypted_topic_name".to_vec(),
        sort_order: 50, // Invalid: must be 0-49
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.create_topic(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_topic_max_limit() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create 50 topics
    for i in 0..50 {
        let timestamp = Utc::now().timestamp();
        let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
        let signature = signing_key.sign(message.as_bytes()).to_bytes();

        let req = proto::CreateTopicRequest {
            group_id: group_id.to_string(),
            encrypted_name: format!("topic_{}", i).into_bytes(),
            sort_order: (i % 50) as u32,
            admin_proof: signature.to_vec(),
            signature_timestamp: timestamp,
        };

        let metadata = create_metadata(&user_id, &device_id);
        let mut request = Request::new(req);
        *request.metadata_mut() = metadata;
        svc.create_topic(request).await.unwrap();
    }

    // Try to create 51st topic
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"topic_51".to_vec(),
        sort_order: 0,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.create_topic(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

// ── ListTopics ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_topics_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create 3 topics
    for i in 0..3 {
        let timestamp = Utc::now().timestamp();
        let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
        let signature = signing_key.sign(message.as_bytes()).to_bytes();

        let req = proto::CreateTopicRequest {
            group_id: group_id.to_string(),
            encrypted_name: format!("topic_{}", i).into_bytes(),
            sort_order: i as u32,
            admin_proof: signature.to_vec(),
            signature_timestamp: timestamp,
        };

        let metadata = create_metadata(&user_id, &device_id);
        let mut request = Request::new(req);
        *request.metadata_mut() = metadata;
        svc.create_topic(request).await.unwrap();
    }

    // List topics
    let list_req = proto::ListTopicsRequest {
        group_id: group_id.to_string(),
        include_archived: false,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(list_req);
    *request.metadata_mut() = metadata;

    let response = svc.list_topics(request).await.unwrap();
    let resp = response.into_inner();

    assert_eq!(resp.topics.len(), 3);
}

#[tokio::test]
async fn test_list_topics_non_member() {
    let db = get_test_db().await;
    let (_user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let (_, other_device_id, _) = create_test_device(&db).await;

    let list_req = proto::ListTopicsRequest {
        group_id: group_id.to_string(),
        include_archived: false,
    };

    let (other_user_id, _, _) = create_test_device(&db).await;
    let metadata = create_metadata(&other_user_id, &other_device_id);
    let mut request = Request::new(list_req);
    *request.metadata_mut() = metadata;

    let result = svc.list_topics(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

// ── ArchiveTopic ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_archive_topic_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create topic
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let create_req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"topic_to_archive".to_vec(),
        sort_order: 0,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(create_req);
    *request.metadata_mut() = metadata;
    let create_resp = svc.create_topic(request).await.unwrap();
    let topic_id = create_resp.into_inner().topic_id;

    // Archive topic
    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_ARCHIVE_TOPIC:{}:{}:{}",
        group_id, topic_id, timestamp
    );
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let archive_req = proto::ArchiveTopicRequest {
        group_id: group_id.to_string(),
        topic_id: topic_id.clone(),
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(archive_req);
    *request.metadata_mut() = metadata;

    let response = svc.archive_topic(request).await.unwrap();
    let resp = response.into_inner();

    assert!(resp.success);
    assert!(resp.archived_at > 0);
}

#[tokio::test]
async fn test_archive_topic_non_admin() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create topic
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let create_req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"topic".to_vec(),
        sort_order: 0,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(create_req);
    *request.metadata_mut() = metadata;
    let create_resp = svc.create_topic(request).await.unwrap();
    let topic_id = create_resp.into_inner().topic_id;

    // Create another device (non-admin member)
    let (_, other_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&other_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .unwrap();

    // Try to archive as non-admin
    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_ARCHIVE_TOPIC:{}:{}:{}",
        group_id, topic_id, timestamp
    );
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let archive_req = proto::ArchiveTopicRequest {
        group_id: group_id.to_string(),
        topic_id: topic_id.clone(),
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let (other_user_id, _, _) = create_test_device(&db).await;
    let metadata = create_metadata(&other_user_id, &other_device_id);
    let mut request = Request::new(archive_req);
    *request.metadata_mut() = metadata;

    let result = svc.archive_topic(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

// ── CreateInviteLink ──────────────────────────────────────────────────

#[tokio::test]
async fn test_create_invite_link_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_INVITE_LINK:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateInviteLinkRequest {
        group_id: group_id.to_string(),
        max_uses: 10,
        expires_in_seconds: 3600,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let response = svc.create_invite_link(request).await.unwrap();
    let resp = response.into_inner();

    assert_eq!(resp.token.len(), 32);
    assert!(resp.created_at > 0);
    assert!(resp.expires_at.is_some());
}

#[tokio::test]
async fn test_create_invite_link_no_limits() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_INVITE_LINK:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateInviteLinkRequest {
        group_id: group_id.to_string(),
        max_uses: 0,           // No limit
        expires_in_seconds: 0, // No expiry
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let response = svc.create_invite_link(request).await.unwrap();
    let resp = response.into_inner();

    assert_eq!(resp.token.len(), 32);
    assert!(resp.expires_at.is_none());
}

#[tokio::test]
async fn test_create_invite_link_non_admin() {
    let db = get_test_db().await;
    let (_user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create member
    let (_, other_device_id, _) = create_test_device(&db).await;
    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
    )
    .bind(group_id)
    .bind(&other_device_id)
    .bind(Utc::now())
    .execute(db.as_ref())
    .await
    .unwrap();

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_INVITE_LINK:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateInviteLinkRequest {
        group_id: group_id.to_string(),
        max_uses: 10,
        expires_in_seconds: 3600,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let (other_user_id, _, _) = create_test_device(&db).await;
    let metadata = create_metadata(&other_user_id, &other_device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.create_invite_link(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

// ── RevokeInviteLink ──────────────────────────────────────────────────

#[tokio::test]
async fn test_revoke_invite_link_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create invite link
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_INVITE_LINK:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let create_req = proto::CreateInviteLinkRequest {
        group_id: group_id.to_string(),
        max_uses: 10,
        expires_in_seconds: 3600,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(create_req);
    *request.metadata_mut() = metadata;
    let create_resp = svc.create_invite_link(request).await.unwrap();
    let token = create_resp.into_inner().token;

    // Revoke invite link
    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_REVOKE_INVITE_LINK:{}:{}:{}",
        group_id, token, timestamp
    );
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let revoke_req = proto::RevokeInviteLinkRequest {
        group_id: group_id.to_string(),
        token: token.clone(),
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(revoke_req);
    *request.metadata_mut() = metadata;

    let response = svc.revoke_invite_link(request).await.unwrap();
    let resp = response.into_inner();

    assert!(resp.success);
    assert!(resp.revoked_at > 0);
}

#[tokio::test]
async fn test_revoke_invite_link_not_found() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let timestamp = Utc::now().timestamp();
    let message = format!(
        "CONSTRUCT_REVOKE_INVITE_LINK:{}:{}:{}",
        group_id, "nonexistent_token_12345678901234567890", timestamp
    );
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::RevokeInviteLinkRequest {
        group_id: group_id.to_string(),
        token: "nonexistent_token_12345678901234567890".to_string(),
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.revoke_invite_link(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

// ── ResolveInviteLink ─────────────────────────────────────────────────

#[tokio::test]
async fn test_resolve_invite_link_valid() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create invite link
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_INVITE_LINK:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let create_req = proto::CreateInviteLinkRequest {
        group_id: group_id.to_string(),
        max_uses: 10,
        expires_in_seconds: 3600,
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(create_req);
    *request.metadata_mut() = metadata;
    let create_resp = svc.create_invite_link(request).await.unwrap();
    let token = create_resp.into_inner().token;

    // Resolve invite link (no auth required)
    let resolve_req = proto::ResolveInviteLinkRequest {
        token: token.clone(),
    };

    let request = Request::new(resolve_req);

    let response = svc.resolve_invite_link(request).await.unwrap();
    let resp = response.into_inner();

    assert_eq!(resp.group_id, group_id.to_string());
    assert_eq!(resp.member_count, 1);
    assert!(resp.valid);
}

#[tokio::test]
async fn test_resolve_invite_link_expired() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Create expired invite link (1 second expiry)
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_INVITE_LINK:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let create_req = proto::CreateInviteLinkRequest {
        group_id: group_id.to_string(),
        max_uses: 10,
        expires_in_seconds: 1, // 1 second
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(create_req);
    *request.metadata_mut() = metadata;
    let create_resp = svc.create_invite_link(request).await.unwrap();
    let token = create_resp.into_inner().token;

    // Wait for expiry
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Resolve invite link
    let resolve_req = proto::ResolveInviteLinkRequest {
        token: token.clone(),
    };

    let request = Request::new(resolve_req);

    let response = svc.resolve_invite_link(request).await.unwrap();
    let resp = response.into_inner();

    assert!(!resp.valid); // Should be invalid due to expiry
}

#[tokio::test]
async fn test_resolve_invite_link_not_found() {
    let db = get_test_db().await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let resolve_req = proto::ResolveInviteLinkRequest {
        token: "nonexistent_token_12345678901234567890".to_string(),
    };

    let request = Request::new(resolve_req);

    let result = svc.resolve_invite_link(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}
