use tonic::Request;

use super::test_helpers::{create_metadata, create_test_device, get_test_db, get_test_redis};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_create_invite_link() {
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
            visibility: proto::ChannelVisibility::Private as i32,
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
    let invite_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ChannelServiceCreateInviteLinkRequest {
            channel_id: channel_id.clone(),
            max_uses: 10,
            expires_in_seconds: 3600,
        },
    );

    let resp = svc
        .create_invite_link(invite_req)
        .await
        .expect("CreateInviteLink should succeed");
    let inner = resp.into_inner();
    assert_eq!(inner.token.len(), 32);
    assert!(inner.expires_at > 0);
}

#[tokio::test]
async fn test_resolve_invite_link() {
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
            visibility: proto::ChannelVisibility::Private as i32,
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

    let meta = create_metadata(&owner_id, &owner_device);
    let invite_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ChannelServiceCreateInviteLinkRequest {
            channel_id: channel_id.clone(),
            max_uses: 5,
            expires_in_seconds: 86400,
        },
    );
    let token = svc
        .create_invite_link(invite_req)
        .await
        .unwrap()
        .into_inner()
        .token;

    let resolve_req = Request::new(proto::ChannelServiceResolveInviteLinkRequest {
        token: token.clone(),
    });

    let resp = svc
        .resolve_invite_link(resolve_req)
        .await
        .expect("ResolveInviteLink should succeed");
    let inner = resp.into_inner();
    assert_eq!(inner.channel_id, channel_id);
    assert!(inner.valid);
}

#[tokio::test]
async fn test_revoke_invite_link() {
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
            visibility: proto::ChannelVisibility::Private as i32,
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
    let invite_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ChannelServiceCreateInviteLinkRequest {
            channel_id: channel_id.clone(),
            max_uses: 0,
            expires_in_seconds: 0,
        },
    );
    let token = svc
        .create_invite_link(invite_req)
        .await
        .unwrap()
        .into_inner()
        .token;

    let meta = create_metadata(&owner_id, &owner_device);
    let revoke_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ChannelServiceRevokeInviteLinkRequest {
            channel_id: channel_id.clone(),
            token: token.clone(),
        },
    );

    let resp = svc.revoke_invite_link(revoke_req).await.unwrap();
    assert!(resp.into_inner().success);

    let resolve_req = Request::new(proto::ChannelServiceResolveInviteLinkRequest { token });
    let resp = svc.resolve_invite_link(resolve_req).await.unwrap();
    assert!(!resp.into_inner().valid);
}

#[tokio::test]
async fn test_subscribe_private_with_invite_link() {
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
            visibility: proto::ChannelVisibility::Private as i32,
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
    let invite_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::ChannelServiceCreateInviteLinkRequest {
            channel_id: channel_id.clone(),
            max_uses: 0,
            expires_in_seconds: 0,
        },
    );
    let token = svc
        .create_invite_link(invite_req)
        .await
        .unwrap()
        .into_inner()
        .token;

    let (user_id, device_id, _) = create_test_device(&db).await;
    let meta = create_metadata(&user_id, &device_id);
    let sub_req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::SubscribeChannelRequest {
            channel_id: channel_id.clone(),
            invite_token: token,
        },
    );

    let resp = svc
        .subscribe_channel(sub_req)
        .await
        .expect("Subscribe via invite link should succeed");
    assert!(resp.into_inner().success);
}
