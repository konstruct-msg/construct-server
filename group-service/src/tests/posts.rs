use tonic::Request;

use super::test_helpers::{create_metadata, create_test_device, get_test_db};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_publish_post_by_owner() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&owner_id, &owner_device);
    let create_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 1000,
            retention_days: 30,
        },
    );
    let channel_id = svc
        .create_channel(create_req)
        .await
        .unwrap()
        .into_inner()
        .channel_id;

    let meta = create_metadata(&owner_id, &owner_device);
    let post_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::PublishPostRequest {
            channel_id: channel_id.clone(),
            ciphertext: vec![10, 20, 30],
            thread_id: String::new(),
            client_message_id: String::new(),
        },
    );

    let resp = svc
        .publish_post(post_req)
        .await
        .expect("PublishPost by owner should succeed");
    let inner = resp.into_inner();
    assert!(!inner.post_id.is_empty());
    assert!(inner.sequence_number > 0);
    assert!(inner.sent_at > 0);
    assert!(inner.expires_at > 0);
}

#[tokio::test]
async fn test_publish_post_by_non_admin() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&owner_id, &owner_device);
    let create_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 1000,
            retention_days: 30,
        },
    );
    let channel_id = svc
        .create_channel(create_req)
        .await
        .unwrap()
        .into_inner()
        .channel_id;

    let (user_id, device_id, _) = create_test_device(&db).await;
    let meta = create_metadata(&user_id, &device_id);
    let sub_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::SubscribeChannelRequest {
            channel_id: channel_id.clone(),
            invite_token: String::new(),
        },
    );
    svc.subscribe_channel(sub_req).await.unwrap();

    let meta = create_metadata(&user_id, &device_id);
    let post_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::PublishPostRequest {
            channel_id,
            ciphertext: vec![10, 20],
            thread_id: String::new(),
            client_message_id: String::new(),
        },
    );

    let err = svc.publish_post(post_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_list_posts() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&owner_id, &owner_device);
    let create_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 1000,
            retention_days: 30,
        },
    );
    let channel_id = svc
        .create_channel(create_req)
        .await
        .unwrap()
        .into_inner()
        .channel_id;

    let meta = create_metadata(&owner_id, &owner_device);
    let post_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::PublishPostRequest {
            channel_id: channel_id.clone(),
            ciphertext: vec![1, 2, 3],
            thread_id: String::new(),
            client_message_id: String::new(),
        },
    );
    svc.publish_post(post_req).await.unwrap();

    let meta = create_metadata(&owner_id, &owner_device);
    let list_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ListPostsRequest {
            channel_id: channel_id.clone(),
            after_sequence: 0,
            limit: 10,
            thread_id: String::new(),
            since_timestamp: 0,
            until_timestamp: 0,
        },
    );

    let resp = svc
        .list_posts(list_req)
        .await
        .expect("ListPosts should succeed");
    let inner = resp.into_inner();
    assert!(!inner.posts.is_empty());
    assert_eq!(inner.posts[0].ciphertext, vec![1, 2, 3]);
}

#[tokio::test]
async fn test_get_post() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&owner_id, &owner_device);
    let create_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 1000,
            retention_days: 30,
        },
    );
    svc.create_channel(create_req).await.unwrap();

    let channel = construct_db::channel::create_channel(
        svc.db.as_ref(),
        &owner_device,
        "PUBLIC",
        &[1],
        1000,
        30,
    )
    .await
    .unwrap();

    construct_db::channel::subscribe_to_channel(
        svc.db.as_ref(),
        channel.channel_id,
        &owner_device,
        true,
    )
    .await
    .unwrap();

    let post = construct_db::channel::insert_channel_post(
        svc.db.as_ref(),
        channel.channel_id,
        &owner_device,
        &[7, 7, 7],
        None,
        None,
        chrono::Utc::now() + chrono::Duration::days(30),
    )
    .await
    .unwrap();

    let meta = create_metadata(&owner_id, &owner_device);
    let get_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetPostRequest {
            post_id: post.post_id.to_string(),
        },
    );

    let resp = svc.get_post(get_req).await.expect("GetPost should succeed");
    let inner = resp.into_inner();
    assert!(inner.post.is_some());
    assert_eq!(inner.post.as_ref().unwrap().ciphertext, vec![7, 7, 7]);
}

#[tokio::test]
async fn test_delete_post() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&owner_id, &owner_device);
    let create_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 1000,
            retention_days: 30,
        },
    );
    let channel_id = svc
        .create_channel(create_req)
        .await
        .unwrap()
        .into_inner()
        .channel_id;

    let meta = create_metadata(&owner_id, &owner_device);
    let post_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::PublishPostRequest {
            channel_id,
            ciphertext: vec![9, 9],
            thread_id: String::new(),
            client_message_id: String::new(),
        },
    );
    let post_id = svc
        .publish_post(post_req)
        .await
        .unwrap()
        .into_inner()
        .post_id;

    let meta = create_metadata(&owner_id, &owner_device);
    let del_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DeletePostRequest {
            post_id: post_id.clone(),
        },
    );

    let resp = svc
        .delete_post(del_req)
        .await
        .expect("DeletePost by admin should succeed");
    assert!(resp.into_inner().success);
}
