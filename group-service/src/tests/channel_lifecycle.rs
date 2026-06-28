use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{create_metadata, create_test_device, get_test_db};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_create_channel_public() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1, 2, 3],
            max_subscribers: 1000,
            retention_days: 30,
        },
    );

    let resp = svc
        .create_channel(req)
        .await
        .expect("CreateChannel should succeed");
    let inner = resp.into_inner();
    assert!(!inner.channel_id.is_empty());
    assert!(Uuid::parse_str(&inner.channel_id).is_ok());
}

#[tokio::test]
async fn test_create_channel_private() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db: db.clone(),
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Private as i32,
            encrypted_metadata: vec![1, 2, 3],
            max_subscribers: 0,
            retention_days: 0,
        },
    );

    let resp = svc
        .create_channel(req)
        .await
        .expect("CreateChannel should succeed");
    assert!(!resp.into_inner().channel_id.is_empty());
}

#[tokio::test]
async fn test_create_channel_empty_metadata() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![],
            max_subscribers: 100,
            retention_days: 30,
        },
    );

    let err = svc.create_channel(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_create_channel_exceeds_max_subscribers() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::CreateChannelRequest {
            visibility: proto::ChannelVisibility::Public as i32,
            encrypted_metadata: vec![1],
            max_subscribers: 200000,
            retention_days: 30,
        },
    );

    let err = svc.create_channel(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_get_channel_success() {
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
            encrypted_metadata: vec![5, 6, 7, 8],
            max_subscribers: 500,
            retention_days: 60,
        },
    );
    let channel_id = svc
        .create_channel(create_req)
        .await
        .unwrap()
        .into_inner()
        .channel_id;

    let meta = create_metadata(&user_id, &device_id);
    let get_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetChannelRequest {
            channel_id: channel_id.clone(),
        },
    );

    let resp = svc
        .get_channel(get_req)
        .await
        .expect("GetChannel should succeed");
    let inner = resp.into_inner();
    assert_eq!(inner.channel_id, channel_id);
    assert_eq!(inner.visibility, proto::ChannelVisibility::Public as i32);
    assert_eq!(inner.encrypted_metadata, vec![5, 6, 7, 8]);
    assert_eq!(inner.subscriber_count, 1);
    assert!(inner.is_subscribed);
    assert!(inner.is_admin);
}

#[tokio::test]
async fn test_get_channel_not_found() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetChannelRequest {
            channel_id: Uuid::new_v4().to_string(),
        },
    );

    let err = svc.get_channel(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_update_channel_success() {
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
    let update_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::UpdateChannelRequest {
            channel_id: channel_id.clone(),
            encrypted_metadata: vec![9, 9, 9],
        },
    );

    let resp = svc
        .update_channel(update_req)
        .await
        .expect("UpdateChannel should succeed");
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_update_channel_not_owner() {
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

    let (other_id, other_device, _) = create_test_device(&db).await;
    let meta = create_metadata(&other_id, &other_device);
    let update_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::UpdateChannelRequest {
            channel_id,
            encrypted_metadata: vec![9, 9, 9],
        },
    );

    let err = svc.update_channel(update_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn test_set_channel_visibility() {
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
    let set_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::SetChannelVisibilityRequest {
            channel_id: channel_id.clone(),
            visibility: proto::ChannelVisibility::Private as i32,
        },
    );

    let resp = svc
        .set_channel_visibility(set_req)
        .await
        .expect("SetChannelVisibility should succeed");
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_delete_channel_success() {
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
    let del_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DeleteChannelRequest {
            channel_id: channel_id.clone(),
        },
    );

    let resp = svc
        .delete_channel(del_req)
        .await
        .expect("DeleteChannel should succeed");
    assert!(resp.into_inner().success);
}

#[tokio::test]
async fn test_delete_channel_not_owner() {
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

    let (other_id, other_device, _) = create_test_device(&db).await;
    let meta = create_metadata(&other_id, &other_device);
    let del_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::DeleteChannelRequest { channel_id },
    );

    let err = svc.delete_channel(del_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
