use construct_db::channel as db_channel;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{check_channel_owner, check_channel_subscriber, extract_device_id};
use crate::service::GroupServiceImpl;

pub(crate) async fn add_admin(
    svc: &GroupServiceImpl,
    request: Request<proto::AddAdminRequest>,
) -> Result<Response<proto::AddAdminResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    check_channel_owner(svc.db.as_ref(), channel_id, &device_id).await?;

    check_channel_subscriber(svc.db.as_ref(), channel_id, &req.subscriber_device_id).await?;

    let _granted_at = db_channel::add_channel_admin(
        svc.db.as_ref(),
        channel_id,
        &req.subscriber_device_id,
        &device_id,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to add admin: {}", e)))?;

    Ok(Response::new(proto::AddAdminResponse { success: true }))
}

pub(crate) async fn remove_admin(
    svc: &GroupServiceImpl,
    request: Request<proto::RemoveAdminRequest>,
) -> Result<Response<proto::RemoveAdminResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    check_channel_owner(svc.db.as_ref(), channel_id, &device_id).await?;

    let removed =
        db_channel::remove_channel_admin(svc.db.as_ref(), channel_id, &req.subscriber_device_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove admin: {}", e)))?;

    if !removed {
        return Err(Status::not_found("Admin not found or is the channel owner"));
    }

    Ok(Response::new(proto::RemoveAdminResponse { success: true }))
}

pub(crate) async fn list_admins(
    svc: &GroupServiceImpl,
    request: Request<proto::ListAdminsRequest>,
) -> Result<Response<proto::ListAdminsResponse>, Status> {
    let req = request.into_inner();

    let channel_id = Uuid::parse_str(&req.channel_id)
        .map_err(|_| Status::invalid_argument("Invalid channel_id"))?;

    let admin_ids = db_channel::list_channel_admins(svc.db.as_ref(), channel_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to list admins: {}", e)))?;

    Ok(Response::new(proto::ListAdminsResponse {
        admin_device_ids: admin_ids,
    }))
}
