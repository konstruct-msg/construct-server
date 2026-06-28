use chrono::Utc;
use ed25519_dalek::Signer;
use tonic::Request;

use super::test_helpers::{
    create_metadata, create_test_device, create_test_group_in_db, get_test_db,
};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, mls_service_server::MlsService,
};

#[tokio::test]
async fn test_create_topic_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
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

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
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

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: vec![],
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

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_CREATE_TOPIC:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let req = proto::CreateTopicRequest {
        group_id: group_id.to_string(),
        encrypted_name: b"encrypted_topic_name".to_vec(),
        sort_order: 50,
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

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

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

#[tokio::test]
async fn test_list_topics_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

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

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
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

#[tokio::test]
async fn test_archive_topic_success() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

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

    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

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
