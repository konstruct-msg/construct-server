use construct_db::channel as db_channel;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{check_channel_subscriber_or_admin, extract_device_id, extract_user_id};
use crate::service::ChannelServiceImpl;

pub(crate) async fn get_comment_group(
    svc: &ChannelServiceImpl,
    request: Request<proto::GetCommentGroupRequest>,
) -> Result<Response<proto::GetCommentGroupResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let post_id =
        Uuid::parse_str(&req.post_id).map_err(|_| Status::invalid_argument("Invalid post_id"))?;

    // Verify the post exists and caller is subscriber/admin
    let post = db_channel::get_channel_post_by_id(svc.db.as_ref(), post_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        .ok_or_else(|| Status::not_found("Post not found"))?;

    check_channel_subscriber_or_admin(svc.db.as_ref(), post.channel_id, &device_id).await?;

    // Check if comment group already exists
    let existing_group = db_channel::get_post_comment_group(svc.db.as_ref(), post_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if let Some(group_id) = existing_group {
        return Ok(Response::new(proto::GetCommentGroupResponse {
            group_id: group_id.to_string(),
            created: false,
        }));
    }

    // Create new MLS group for comments
    let mls_client = svc.mls_client.as_ref().ok_or_else(|| {
        Status::unavailable("MLS service not configured; comment groups unavailable")
    })?;

    // Validate required fields for group creation
    if req.initial_ratchet_tree.is_empty() {
        return Err(Status::invalid_argument(
            "initial_ratchet_tree is required for first commenter",
        ));
    }
    if req.encrypted_group_context.is_empty() {
        return Err(Status::invalid_argument(
            "encrypted_group_context is required for first commenter",
        ));
    }

    let group_id = Uuid::new_v4();

    let created_group_id = mls_client
        .create_group(
            &device_id,
            &user_id,
            &group_id,
            &req.initial_ratchet_tree,
            &req.encrypted_group_context,
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to create comment MLS group: {}", e)))?;

    // Verify the returned group_id matches
    let returned_id = Uuid::parse_str(&created_group_id)
        .map_err(|_| Status::internal("MLS service returned invalid group_id"))?;

    // Link post to comment group
    db_channel::create_post_comment_group(svc.db.as_ref(), post_id, returned_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to link comment group: {}", e)))?;

    Ok(Response::new(proto::GetCommentGroupResponse {
        group_id: returned_id.to_string(),
        created: true,
    }))
}
