use tonic::Request;

use super::test_helpers::{create_metadata, create_test_device, get_test_db, get_test_redis};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_add_and_list_admins() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
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

    let meta = create_metadata(&owner_id, &owner_device);
    let add_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::AddAdminRequest {
            channel_id: channel_id.clone(),
            subscriber_device_id: device_id.clone(),
        },
    );
    let resp = svc
        .add_admin(add_req)
        .await
        .expect("AddAdmin should succeed");
    assert!(resp.into_inner().success);

    let meta = create_metadata(&owner_id, &owner_device);
    let list_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ListAdminsRequest {
            channel_id: channel_id.clone(),
        },
    );
    let resp = svc.list_admins(list_req).await.unwrap();
    let admin_ids = resp.into_inner().admin_device_ids;
    assert!(admin_ids.contains(&owner_device));
    assert!(admin_ids.contains(&device_id));
}

#[tokio::test]
async fn test_remove_admin() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
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

    let meta = create_metadata(&owner_id, &owner_device);
    let add_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::AddAdminRequest {
            channel_id: channel_id.clone(),
            subscriber_device_id: device_id.clone(),
        },
    );
    svc.add_admin(add_req).await.unwrap();

    let meta = create_metadata(&owner_id, &owner_device);
    let rem_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::RemoveAdminRequest {
            channel_id: channel_id.clone(),
            subscriber_device_id: device_id.clone(),
        },
    );
    let resp = svc
        .remove_admin(rem_req)
        .await
        .expect("RemoveAdmin should succeed");
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_add_admin_not_owner() {
    let db = get_test_db().await;
    let (owner_id, owner_device, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
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

    let (_third_id, third_device, _) = create_test_device(&db).await;
    let meta = create_metadata(&user_id, &device_id);
    let add_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::AddAdminRequest {
            channel_id,
            subscriber_device_id: third_device,
        },
    );

    let err = svc.add_admin(add_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
