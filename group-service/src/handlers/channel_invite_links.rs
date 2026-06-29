use chrono::{Duration, Utc};
use construct_db::channel as db_channel;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use rand::Rng;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{
    check_channel_admin, check_channel_owner, extract_device_id, extract_user_id,
};
use crate::service::GroupServiceImpl;

fn generate_invite_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

pub(crate) async fn create_invite_link(
    svc: &GroupServiceImpl,
    request: Request<proto::ChannelServiceCreateInviteLinkRequest>,
) -> Result<Response<proto::ChannelServiceCreateInviteLinkResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    crate::helpers::check_warmup_rate_limit(
        svc.db.as_ref(),
        user_id,
        "create_channel_invite",
        5,
        24,
        50,
        24,
    )
    .await?;

    check_channel_owner(svc.db.as_ref(), channel_id, &device_id).await?;

    let max_uses = if req.max_uses == 0 {
        None
    } else {
        Some(req.max_uses as i32)
    };

    let expires_at = if req.expires_in_seconds == 0 {
        None
    } else {
        Some(Utc::now() + Duration::seconds(req.expires_in_seconds as i64))
    };

    let token = generate_invite_token();

    let link = db_channel::create_channel_invite_link(
        svc.db.as_ref(),
        &token,
        channel_id,
        &device_id,
        max_uses,
        expires_at,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to create invite link: {}", e)))?;

    crate::metrics::inc_channel_invite_links_created();

    Ok(Response::new(
        proto::ChannelServiceCreateInviteLinkResponse {
            token,
            created_at: link.created_at.timestamp(),
            expires_at: link.expires_at.map(|t| t.timestamp()).unwrap_or(0),
        },
    ))
}

pub(crate) async fn revoke_invite_link(
    svc: &GroupServiceImpl,
    request: Request<proto::ChannelServiceRevokeInviteLinkRequest>,
) -> Result<Response<proto::ChannelServiceRevokeInviteLinkResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    check_channel_admin(svc.db.as_ref(), channel_id, &device_id).await?;

    let revoked_at =
        db_channel::revoke_channel_invite_link(svc.db.as_ref(), channel_id, &req.token)
            .await
            .map_err(|_| Status::not_found("Invite link not found or already revoked"))?;

    Ok(Response::new(
        proto::ChannelServiceRevokeInviteLinkResponse {
            success: true,
            revoked_at: revoked_at.timestamp(),
        },
    ))
}

pub(crate) async fn resolve_invite_link(
    svc: &GroupServiceImpl,
    request: Request<proto::ChannelServiceResolveInviteLinkRequest>,
) -> Result<Response<proto::ChannelServiceResolveInviteLinkResponse>, Status> {
    let req = request.into_inner();

    let link = db_channel::resolve_channel_invite_link(svc.db.as_ref(), &req.token)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        .ok_or_else(|| Status::not_found("Invite link not found"))?;

    let now = Utc::now();
    let valid = link.revoked_at.is_none()
        && link.expires_at.is_none_or(|exp| exp > now)
        && link.max_uses.is_none_or(|max| link.use_count < max);

    let channel = db_channel::get_channel_by_id(svc.db.as_ref(), link.channel_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    let encrypted_metadata = channel
        .as_ref()
        .map(|c| c.encrypted_metadata.clone())
        .unwrap_or_default();
    let subscriber_count = channel
        .as_ref()
        .map(|c| c.subscriber_count as u32)
        .unwrap_or(0);

    Ok(Response::new(
        proto::ChannelServiceResolveInviteLinkResponse {
            channel_id: link.channel_id.to_string(),
            encrypted_metadata,
            subscriber_count,
            valid,
            expires_at: link.expires_at.map(|t| t.timestamp()).unwrap_or(0),
        },
    ))
}
