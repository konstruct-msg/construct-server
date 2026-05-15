use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{create_metadata, create_test_device, get_test_db};
use crate::service::ChannelServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_get_comment_group_nonexistent_without_mls() {
    let db = get_test_db().await;
    let (owner_id, owner_device) = create_test_device(&db).await;
    let svc = ChannelServiceImpl {
        db: db.clone(),
        mls_client: None,
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

    let _meta = create_metadata(&owner_id, &owner_device);

    // Create post via DB directly
    let channel_id = Uuid::new_v4();
    construct_db::channel::create_channel(svc.db.as_ref(), &owner_device, "PUBLIC", &[1], 1000, 30)
        .await
        .unwrap();

    let post = construct_db::channel::insert_channel_post(
        svc.db.as_ref(),
        channel_id,
        &owner_device,
        &[1, 2, 3],
        None,
        None,
        chrono::Utc::now() + chrono::Duration::days(30),
    )
    .await
    .unwrap();

    // Try get_comment_group without MLS client
    let meta = create_metadata(&owner_id, &owner_device);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetCommentGroupRequest {
            post_id: post.post_id.to_string(),
            initial_ratchet_tree: vec![1, 2, 3],
            encrypted_group_context: vec![4, 5, 6],
        },
    );

    let err = svc.get_comment_group(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn test_get_comment_group_post_not_found() {
    let db = get_test_db().await;
    let (user_id, device_id) = create_test_device(&db).await;
    let svc = ChannelServiceImpl {
        db,
        mls_client: None,
    };

    let meta = create_metadata(&user_id, &device_id);
    let req = Request::from_parts(
        meta,
        tonic::Extensions::default(),
        proto::GetCommentGroupRequest {
            post_id: Uuid::new_v4().to_string(),
            initial_ratchet_tree: vec![],
            encrypted_group_context: vec![],
        },
    );

    let err = svc.get_comment_group(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}
