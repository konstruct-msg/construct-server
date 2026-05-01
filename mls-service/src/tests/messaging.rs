use tonic::Request;

use super::test_helpers::{create_metadata, create_test_device, create_test_group_in_db, get_test_db};
use construct_server_shared::shared::proto::services::v1 as proto;
use construct_server_shared::shared::proto::services::v1::mls_service_server::MlsService;

use crate::service::MlsServiceImpl;

// ── SendGroupMessage ─────────────────────────────────────────────────

#[tokio::test]
async fn test_send_group_message_success() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let req = proto::SendGroupMessageRequest {
        group_id: group_id.to_string(),
        epoch: 0,
        mls_ciphertext: b"encrypted_message".to_vec(),
        client_message_id: "client_msg_1".to_string(),
        thread_id: None,
        topic_id: None,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let response = svc.send_group_message(request).await.unwrap();
    let resp = response.into_inner();

    assert!(!resp.message_id.is_empty());
    assert_eq!(resp.sequence_number, 1);
    assert!(resp.sent_at > 0);
    assert!(resp.expires_at > resp.sent_at);
}

#[tokio::test]
async fn test_send_group_message_non_member() {
    let db = get_test_db().await;
    let (_user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let (_, other_device_id, _) = create_test_device(&db).await;

    let req = proto::SendGroupMessageRequest {
        group_id: group_id.to_string(),
        epoch: 0,
        mls_ciphertext: b"encrypted_message".to_vec(),
        client_message_id: String::new(),
        thread_id: None,
        topic_id: None,
    };

    let (other_user_id, _, _) = create_test_device(&db).await;
    let metadata = create_metadata(&other_user_id, &other_device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.send_group_message(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_send_group_message_epoch_mismatch() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let req = proto::SendGroupMessageRequest {
        group_id: group_id.to_string(),
        epoch: 999,
        mls_ciphertext: b"encrypted_message".to_vec(),
        client_message_id: String::new(),
        thread_id: None,
        topic_id: None,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.send_group_message(request).await;
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_send_group_message_dissolved_group() {
    let db = get_test_db().await;
    let (user_id, device_id, signing_key) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Dissolve group
    use chrono::Utc;
    use ed25519_dalek::Signer;
    let timestamp = Utc::now().timestamp();
    let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
    let signature = signing_key.sign(message.as_bytes()).to_bytes();

    let dissolve_req = proto::DissolveGroupRequest {
        group_id: group_id.to_string(),
        admin_proof: signature.to_vec(),
        signature_timestamp: timestamp,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(dissolve_req);
    *request.metadata_mut() = metadata.clone();
    svc.dissolve_group(request).await.unwrap();

    // Try to send message
    let req = proto::SendGroupMessageRequest {
        group_id: group_id.to_string(),
        epoch: 0,
        mls_ciphertext: b"encrypted_message".to_vec(),
        client_message_id: String::new(),
        thread_id: None,
        topic_id: None,
    };

    let mut request = Request::new(req);
    *request.metadata_mut() = metadata.clone();

    let result = svc.send_group_message(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_send_group_message_empty_ciphertext() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let req = proto::SendGroupMessageRequest {
        group_id: group_id.to_string(),
        epoch: 0,
        mls_ciphertext: vec![],
        client_message_id: String::new(),
        thread_id: None,
        topic_id: None,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(req);
    *request.metadata_mut() = metadata;

    let result = svc.send_group_message(request).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
}

// ── FetchGroupMessages ────────────────────────────────────────────────

#[tokio::test]
async fn test_fetch_group_messages_success() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    // Send 3 messages
    for i in 0..3 {
        let req = proto::SendGroupMessageRequest {
            group_id: group_id.to_string(),
            epoch: 0,
            mls_ciphertext: format!("message_{}", i).into_bytes(),
            client_message_id: format!("client_{}", i),
            thread_id: None,
            topic_id: None,
        };

        let metadata = create_metadata(&user_id, &device_id);
        let mut request = Request::new(req);
        *request.metadata_mut() = metadata;
        svc.send_group_message(request).await.unwrap();
    }

    let fetch_req = proto::FetchGroupMessagesRequest {
        group_id: group_id.to_string(),
        after_sequence: None,
        limit: 10,
        topic_id: None,
        thread_id: None,
    };

    let metadata = create_metadata(&user_id, &device_id);
    let mut request = Request::new(fetch_req);
    *request.metadata_mut() = metadata.clone();

    let response = svc.fetch_group_messages(request).await.unwrap();
    let mut stream = response.into_inner();

    let mut count = 0;
    use futures_util::StreamExt;
    while let Some(Ok(_)) = stream.next().await {
        count += 1;
    }

    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_fetch_group_messages_pagination() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let metadata = create_metadata(&user_id, &device_id);

    // Send 5 messages
    for i in 0..5 {
        let req = proto::SendGroupMessageRequest {
            group_id: group_id.to_string(),
            epoch: 0,
            mls_ciphertext: format!("msg_{}", i).into_bytes(),
            client_message_id: format!("c_{}", i),
            thread_id: None,
            topic_id: None,
        };

        let mut request = Request::new(req);
        *request.metadata_mut() = metadata.clone();
        svc.send_group_message(request).await.unwrap();
    }

    // Fetch first 2
    let fetch_req = proto::FetchGroupMessagesRequest {
        group_id: group_id.to_string(),
        after_sequence: None,
        limit: 2,
        topic_id: None,
        thread_id: None,
    };
    let mut request = Request::new(fetch_req);
    *request.metadata_mut() = metadata.clone();

    let response = svc.fetch_group_messages(request).await.unwrap();
    let mut stream = response.into_inner();

    let mut count = 0;
    let mut last_seq = 0;
    use futures_util::StreamExt;
    while let Some(Ok(envelope)) = stream.next().await {
        count += 1;
        last_seq = envelope.sequence_number;
    }
    assert_eq!(count, 2);

    // Fetch next 2
    let fetch_req = proto::FetchGroupMessagesRequest {
        group_id: group_id.to_string(),
        after_sequence: Some(last_seq),
        limit: 2,
        topic_id: None,
        thread_id: None,
    };

    let mut request = Request::new(fetch_req);
    *request.metadata_mut() = metadata.clone();

    let response = svc.fetch_group_messages(request).await.unwrap();
    let mut stream = response.into_inner();

    count = 0;
    while let Some(Ok(_)) = stream.next().await {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_fetch_group_messages_non_member() {
    let db = get_test_db().await;
    let (_user_id, device_id, _) = create_test_device(&db).await;
    let group_id = create_test_group_in_db(&db, &device_id).await;

    let svc = MlsServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
    };

    let (_, other_device_id, _) = create_test_device(&db).await;

    let fetch_req = proto::FetchGroupMessagesRequest {
        group_id: group_id.to_string(),
        after_sequence: None,
        limit: 10,
        topic_id: None,
        thread_id: None,
    };

    let (other_user_id, _, _) = create_test_device(&db).await;
    let metadata = create_metadata(&other_user_id, &other_device_id);
    let mut request = Request::new(fetch_req);
    *request.metadata_mut() = metadata;

    let result = svc.fetch_group_messages(request).await;
    match result {
        Err(e) => assert_eq!(e.code(), tonic::Code::PermissionDenied),
        Ok(_) => panic!("Expected error"),
    }
}
