use chrono::{Duration, Utc};
use construct_db::channel as db_channel;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{check_channel_subscriber_or_admin, extract_device_id, extract_user_id};
use crate::service::GroupServiceImpl;

pub(crate) async fn publish_post(
    svc: &GroupServiceImpl,
    request: Request<proto::PublishPostRequest>,
) -> Result<Response<proto::PublishPostResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    crate::helpers::check_warmup_rate_limit(
        &mut svc.redis.clone(),
        svc.db.as_ref(),
        user_id,
        "publish_post",
        (50, 1),
        (500, 1),
    )
    .await?;

    let is_admin = db_channel::is_channel_admin(svc.db.as_ref(), channel_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !is_admin {
        return Err(Status::permission_denied(
            "Only channel admins can publish posts",
        ));
    }

    if req.ciphertext.is_empty() {
        return Err(Status::invalid_argument("ciphertext is required"));
    }

    let thread_id = if req.thread_id.is_empty() {
        None
    } else {
        Some(
            Uuid::parse_str(&req.thread_id)
                .map_err(|_| Status::invalid_argument("Invalid thread_id"))?,
        )
    };

    let channel = db_channel::get_channel_by_id(svc.db.as_ref(), channel_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        .ok_or_else(|| Status::not_found("Channel not found"))?;

    let expires_at = Utc::now() + Duration::days(channel.retention_days as i64);

    let client_message_id = if req.client_message_id.is_empty() {
        None
    } else {
        Some(req.client_message_id.as_str())
    };

    let timer = std::time::Instant::now();

    let post = db_channel::insert_channel_post(
        svc.db.as_ref(),
        channel_id,
        &device_id,
        &req.ciphertext,
        thread_id,
        client_message_id,
        expires_at,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to publish post: {}", e)))?;

    let latency = timer.elapsed();
    crate::metrics::observe_channel_post_latency(latency.as_secs_f64());
    crate::metrics::inc_channel_posts_published(1);

    Ok(Response::new(proto::PublishPostResponse {
        post_id: post.post_id.to_string(),
        sent_at: post.sent_at.timestamp(),
        sequence_number: post.sequence_number as u64,
        expires_at: post.expires_at.timestamp(),
    }))
}

pub(crate) async fn list_posts(
    svc: &GroupServiceImpl,
    request: Request<proto::ListPostsRequest>,
) -> Result<Response<proto::ListPostsResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let _user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    check_channel_subscriber_or_admin(svc.db.as_ref(), channel_id, &device_id).await?;

    let after_sequence = if req.after_sequence == 0 {
        None
    } else {
        Some(req.after_sequence as i64)
    };

    let limit = if req.limit == 0 { 50 } else { req.limit as i64 };

    let thread_id = if req.thread_id.is_empty() {
        None
    } else {
        Some(
            Uuid::parse_str(&req.thread_id)
                .map_err(|_| Status::invalid_argument("Invalid thread_id"))?,
        )
    };

    let since = if req.since_timestamp > 0 {
        Some(chrono::DateTime::from_timestamp(req.since_timestamp, 0).unwrap_or_default())
    } else {
        None
    };
    let until = if req.until_timestamp > 0 {
        Some(chrono::DateTime::from_timestamp(req.until_timestamp, 0).unwrap_or_default())
    } else {
        None
    };

    let posts = db_channel::list_channel_posts(
        svc.db.as_ref(),
        channel_id,
        after_sequence,
        limit,
        thread_id,
        since,
        until,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to list posts: {}", e)))?;

    let has_more = posts.len() as i64 == limit;
    let next_sequence = posts.last().map(|p| p.sequence_number as u64).unwrap_or(0);

    let post_infos: Vec<proto::PostInfo> = posts
        .into_iter()
        .map(|p| proto::PostInfo {
            post_id: p.post_id.to_string(),
            channel_id: p.channel_id.to_string(),
            ciphertext: p.ciphertext,
            sequence_number: p.sequence_number as u64,
            sent_at: p.sent_at.timestamp(),
            expires_at: p.expires_at.timestamp(),
            thread_id: p.thread_id.map(|t| t.to_string()).unwrap_or_default(),
            sender_device_id: p.sender_device_id,
        })
        .collect();

    Ok(Response::new(proto::ListPostsResponse {
        posts: post_infos,
        next_sequence,
        has_more,
    }))
}

pub(crate) async fn get_post(
    svc: &GroupServiceImpl,
    request: Request<proto::GetPostRequest>,
) -> Result<Response<proto::GetPostResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let _user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let post_id =
        Uuid::parse_str(&req.post_id).map_err(|_| Status::invalid_argument("Invalid post_id"))?;

    let post = db_channel::get_channel_post_by_id(svc.db.as_ref(), post_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        .ok_or_else(|| Status::not_found("Post not found or expired"))?;

    check_channel_subscriber_or_admin(svc.db.as_ref(), post.channel_id, &device_id).await?;

    Ok(Response::new(proto::GetPostResponse {
        post: Some(proto::PostInfo {
            post_id: post.post_id.to_string(),
            channel_id: post.channel_id.to_string(),
            ciphertext: post.ciphertext,
            sequence_number: post.sequence_number as u64,
            sent_at: post.sent_at.timestamp(),
            expires_at: post.expires_at.timestamp(),
            thread_id: post.thread_id.map(|t| t.to_string()).unwrap_or_default(),
            sender_device_id: post.sender_device_id,
        }),
    }))
}

pub(crate) async fn delete_post(
    svc: &GroupServiceImpl,
    request: Request<proto::DeletePostRequest>,
) -> Result<Response<proto::DeletePostResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let _user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let post_id =
        Uuid::parse_str(&req.post_id).map_err(|_| Status::invalid_argument("Invalid post_id"))?;

    let success = db_channel::soft_delete_channel_post(svc.db.as_ref(), post_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete post: {}", e)))?;

    if !success {
        return Err(Status::permission_denied(
            "Not a channel admin or post not found",
        ));
    }

    Ok(Response::new(proto::DeletePostResponse { success: true }))
}
