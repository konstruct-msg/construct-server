use tonic::Request;
use uuid::Uuid;

use super::test_helpers::{create_metadata, create_test_device, get_test_db, get_test_redis};
use crate::service::GroupServiceImpl;
use construct_server_shared::shared::proto::services::v1::{
    self as proto, channel_service_server::ChannelService,
};

#[tokio::test]
async fn test_get_comment_group_post_not_found() {
    let db = get_test_db().await;
    let (user_id, device_id, _) = create_test_device(&db).await;
    let svc = GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
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
