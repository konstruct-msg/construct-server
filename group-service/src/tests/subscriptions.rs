use tonic::Request;

use super::test_helpers::{create_metadata, create_test_device, get_test_db};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_subscribe_public_channel() {
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
            encrypted_metadata: vec![1, 2, 3],
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

    let resp = svc
        .subscribe_channel(sub_req)
        .await
        .expect("Subscribe should succeed for PUBLIC channel");
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_subscribe_private_no_token() {
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
            visibility: proto::ChannelVisibility::Private as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 100,
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
            channel_id,
            invite_token: String::new(),
        },
    );

    let err = svc.subscribe_channel(sub_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_unsubscribe_success() {
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
    let unsub_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::UnsubscribeChannelRequest {
            channel_id: channel_id.clone(),
            rotate_sender_key: false,
        },
    );

    let resp = svc
        .unsubscribe_channel(unsub_req)
        .await
        .expect("Unsubscribe should succeed");
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_owner_cannot_unsubscribe() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let create_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 100,
            retention_days: 30,
        },
    );
    let channel_id = svc
        .create_channel(create_req)
        .await
        .unwrap()
        .into_inner()
        .channel_id;

    let meta = create_metadata(&user_id, &device_id);
    let unsub_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::UnsubscribeChannelRequest {
            channel_id,
            rotate_sender_key: false,
        },
    );

    let err = svc.unsubscribe_channel(unsub_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn test_list_subscriptions() {
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

    let meta = create_metadata(&owner_id, &owner_device);
    let list_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ListSubscriptionsRequest {
            cursor: String::new(),
            limit: 10,
        },
    );

    let resp = svc
        .list_subscriptions(list_req)
        .await
        .expect("ListSubscriptions should succeed");
    assert!(!resp.into_inner().channels.is_empty());
}

#[tokio::test]
async fn test_get_subscriber_count() {
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

    let req = Request::new(proto::GetSubscriberCountRequest { channel_id });

    let resp = svc.get_subscriber_count(req).await.unwrap();
    assert!(resp.into_inner().count >= 1);
}
