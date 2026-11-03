use construct_db::channel as db_channel;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{check_device_belongs_to_user, extract_device_id, extract_user_id};
use crate::service::GroupServiceImpl;

pub(crate) async fn subscribe_channel(
    svc: &GroupServiceImpl,
    request: Request<proto::SubscribeChannelRequest>,
) -> Result<Response<proto::SubscribeChannelResponse>, Status> {
    let device_id = extract_device_id(svc, request.metadata())?;
    let user_id = extract_user_id(svc, request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    let belongs = check_device_belongs_to_user(svc.db.as_ref(), &device_id, user_id).await?;
    if !belongs {
        return Err(Status::permission_denied("Device does not belong to user"));
    }

    crate::helpers::check_warmup_rate_limit(
        &mut svc.redis.clone(),
        svc.db.as_ref(),
        user_id,
        "subscribe_channel",
        (20, 1),
        (200, 1),
    )
    .await?;

    use db_channel::ChannelSubscription as S;
    let outcome = db_channel::subscribe_channel_atomic(
        svc.db.as_ref(),
        channel_id,
        &device_id,
        &req.invite_token,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to subscribe: {e}")))?;
    let subscribed_at = match outcome {
        S::Subscribed(at) => at,
        S::NotFound => return Err(Status::not_found("Channel not found")),
        S::Full => return Err(Status::resource_exhausted("Channel is full")),
        S::InviteRequired => {
            return Err(Status::permission_denied(
                "PRIVATE channel requires an invite token",
            ));
        }
        S::InviteNotFound => return Err(Status::not_found("Invite link not found")),
        S::WrongChannel => {
            return Err(Status::permission_denied(
                "Invite link belongs to another channel",
            ));
        }
        S::InviteRevoked => return Err(Status::permission_denied("Invite link has been revoked")),
        S::InviteExpired => return Err(Status::permission_denied("Invite link has expired")),
        S::InviteExhausted => return Err(Status::resource_exhausted("Invite link fully used")),
    };

    let encrypted_sender_key =
        db_channel::get_channel_sender_key(svc.db.as_ref(), channel_id, &device_id)
            .await
            .unwrap_or(None)
            .unwrap_or_default();

    crate::metrics::inc_channel_subscribe_operations();

    Ok(Response::new(proto::SubscribeChannelResponse {
        success: true,
        encrypted_sender_key,
        subscribed_at: subscribed_at.timestamp(),
    }))
}

pub(crate) async fn unsubscribe_channel(
    svc: &GroupServiceImpl,
    request: Request<proto::UnsubscribeChannelRequest>,
) -> Result<Response<proto::UnsubscribeChannelResponse>, Status> {
    let device_id = extract_device_id(svc, request.metadata())?;
    let user_id = extract_user_id(svc, request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    let belongs = check_device_belongs_to_user(svc.db.as_ref(), &device_id, user_id).await?;
    if !belongs {
        return Err(Status::permission_denied("Device does not belong to user"));
    }

    let removed = db_channel::unsubscribe_from_channel(svc.db.as_ref(), channel_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to unsubscribe: {}", e)))?;

    if !removed {
        let is_owner = db_channel::is_channel_owner(svc.db.as_ref(), channel_id, &device_id)
            .await
            .unwrap_or(false);
        if is_owner {
            return Err(Status::failed_precondition(
                "Channel owner cannot unsubscribe. Transfer ownership or delete the channel instead.",
            ));
        }
        return Err(Status::not_found("Subscription not found"));
    }

    if req.rotate_sender_key {
        let _ =
            db_channel::rotate_channel_sender_key(svc.db.as_ref(), channel_id, &device_id).await;
    }

    crate::metrics::inc_channel_unsubscribe_operations();

    Ok(Response::new(proto::UnsubscribeChannelResponse {
        success: true,
    }))
}

pub(crate) async fn list_subscriptions(
    svc: &GroupServiceImpl,
    request: Request<proto::ListSubscriptionsRequest>,
) -> Result<Response<proto::ListSubscriptionsResponse>, Status> {
    let device_id = extract_device_id(svc, request.metadata())?;
    let _user_id = extract_user_id(svc, request.metadata())?;
    let req = request.into_inner();

    let cursor = if req.cursor.is_empty() {
        None
    } else {
        Some(Uuid::parse_str(&req.cursor).map_err(|_| Status::invalid_argument("Invalid cursor"))?)
    };

    let limit = if req.limit == 0 { 50 } else { req.limit as i64 };

    let channels_list =
        db_channel::list_channel_subscriptions(svc.db.as_ref(), &device_id, cursor, limit)
            .await
            .map_err(|e| Status::internal(format!("Failed to list subscriptions: {}", e)))?;

    let next_cursor = channels_list
        .last()
        .map(|c| c.channel_id.to_string())
        .unwrap_or_default();

    let channels: Vec<proto::ChannelInfo> = channels_list
        .into_iter()
        .map(|c| {
            let visibility = match c.visibility.as_str() {
                "PUBLIC" => proto::ChannelVisibility::Public,
                "PRIVATE" => proto::ChannelVisibility::Private,
                _ => proto::ChannelVisibility::Public,
            };
            proto::ChannelInfo {
                channel_id: c.channel_id.to_string(),
                visibility: visibility as i32,
                encrypted_metadata: c.encrypted_metadata,
                subscriber_count: c.subscriber_count as u32,
                subscribed_at: 0,
            }
        })
        .collect();

    Ok(Response::new(proto::ListSubscriptionsResponse {
        channels,
        next_cursor,
    }))
}

pub(crate) async fn get_subscriber_count(
    svc: &GroupServiceImpl,
    request: Request<proto::GetSubscriberCountRequest>,
) -> Result<Response<proto::GetSubscriberCountResponse>, Status> {
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    let count = db_channel::get_channel_subscriber_count(svc.db.as_ref(), channel_id)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    Ok(Response::new(proto::GetSubscriberCountResponse {
        count: count as u32,
    }))
}
