use construct_db::channel as db_channel;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::helpers::{check_channel_owner, extract_device_id, extract_user_id};
use crate::service::GroupServiceImpl;

pub(crate) async fn create_channel(
    svc: &GroupServiceImpl,
    request: Request<proto::CreateChannelRequest>,
) -> Result<Response<proto::CreateChannelResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    crate::helpers::check_warmup_rate_limit(
        svc.db.as_ref(),
        user_id,
        "create_channel",
        1,
        24,
        10,
        24,
    )
    .await?;

    let visibility = match req.visibility() {
        proto::ChannelVisibility::Public => "PUBLIC",
        proto::ChannelVisibility::Private => "PRIVATE",
        _ => return Err(Status::invalid_argument("Invalid channel visibility")),
    };

    let max_subscribers = if req.max_subscribers == 0 {
        0
    } else if req.max_subscribers > 100000 {
        return Err(Status::invalid_argument(
            "max_subscribers cannot exceed 100000",
        ));
    } else {
        req.max_subscribers as i32
    };

    let retention_days = if req.retention_days == 0 {
        90
    } else if req.retention_days > 365 {
        return Err(Status::invalid_argument("retention_days cannot exceed 365"));
    } else {
        req.retention_days as i32
    };

    if req.encrypted_metadata.is_empty() {
        return Err(Status::invalid_argument("encrypted_metadata is required"));
    }

    let record = db_channel::create_channel(
        svc.db.as_ref(),
        &device_id,
        visibility,
        &req.encrypted_metadata,
        max_subscribers,
        retention_days,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to create channel: {}", e)))?;

    let _ = db_channel::subscribe_to_channel(svc.db.as_ref(), record.channel_id, &device_id, true)
        .await
        .map_err(|e| Status::internal(format!("Failed to subscribe owner: {}", e)))?;

    let _ =
        db_channel::add_channel_admin(svc.db.as_ref(), record.channel_id, &device_id, &device_id)
            .await;

    info!(
        channel_id = %record.channel_id,
        owner_device_id = %device_id,
        visibility = %visibility,
        "Channel created",
    );

    crate::metrics::inc_channels_created();

    Ok(Response::new(proto::CreateChannelResponse {
        channel_id: record.channel_id.to_string(),
        created_at: record.created_at.timestamp(),
    }))
}

pub(crate) async fn get_channel(
    svc: &GroupServiceImpl,
    request: Request<proto::GetChannelRequest>,
) -> Result<Response<proto::GetChannelResponse>, Status> {
    let device_id = extract_device_id(request.metadata())
        .ok()
        .unwrap_or_default();
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    let record = db_channel::get_channel_by_id(svc.db.as_ref(), channel_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        .ok_or_else(|| Status::not_found("Channel not found"))?;

    let visibility = match record.visibility.as_str() {
        "PUBLIC" => proto::ChannelVisibility::Public,
        "PRIVATE" => proto::ChannelVisibility::Private,
        _ => proto::ChannelVisibility::Public,
    };

    let is_subscribed = if device_id.is_empty() {
        false
    } else {
        db_channel::is_channel_subscriber(svc.db.as_ref(), channel_id, &device_id)
            .await
            .unwrap_or(false)
    };
    let is_admin = if device_id.is_empty() {
        false
    } else {
        db_channel::is_channel_admin(svc.db.as_ref(), channel_id, &device_id)
            .await
            .unwrap_or(false)
    };

    Ok(Response::new(proto::GetChannelResponse {
        channel_id: record.channel_id.to_string(),
        visibility: visibility as i32,
        encrypted_metadata: record.encrypted_metadata,
        subscriber_count: record.subscriber_count as u32,
        created_at: record.created_at.timestamp(),
        updated_at: record.updated_at.timestamp(),
        is_subscribed,
        is_admin,
    }))
}

pub(crate) async fn update_channel(
    svc: &GroupServiceImpl,
    request: Request<proto::UpdateChannelRequest>,
) -> Result<Response<proto::UpdateChannelResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let _user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    if req.encrypted_metadata.is_empty() {
        return Err(Status::invalid_argument("encrypted_metadata is required"));
    }

    let updated_at = db_channel::update_channel_metadata(
        svc.db.as_ref(),
        channel_id,
        &req.encrypted_metadata,
        &device_id,
    )
    .await
    .map_err(|_| Status::permission_denied("Not the channel owner or channel not found"))?;

    Ok(Response::new(proto::UpdateChannelResponse {
        success: true,
        updated_at: updated_at.timestamp(),
    }))
}

pub(crate) async fn set_channel_visibility(
    svc: &GroupServiceImpl,
    request: Request<proto::SetChannelVisibilityRequest>,
) -> Result<Response<proto::SetChannelVisibilityResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let _user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    let visibility = match req.visibility() {
        proto::ChannelVisibility::Public => "PUBLIC",
        proto::ChannelVisibility::Private => "PRIVATE",
        _ => return Err(Status::invalid_argument("Invalid channel visibility")),
    };

    db_channel::set_channel_visibility(svc.db.as_ref(), channel_id, visibility, &device_id)
        .await
        .map_err(|_| Status::permission_denied("Not the channel owner or channel not found"))?;

    Ok(Response::new(proto::SetChannelVisibilityResponse {
        success: true,
    }))
}

pub(crate) async fn delete_channel(
    svc: &GroupServiceImpl,
    request: Request<proto::DeleteChannelRequest>,
) -> Result<Response<proto::DeleteChannelResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let _user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    check_channel_owner(svc.db.as_ref(), channel_id, &device_id).await?;

    db_channel::soft_delete_channel(svc.db.as_ref(), channel_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete channel: {}", e)))?;

    crate::metrics::inc_channels_deleted();
    info!(channel_id = %channel_id, "Channel soft-deleted");

    Ok(Response::new(proto::DeleteChannelResponse {
        success: true,
    }))
}
