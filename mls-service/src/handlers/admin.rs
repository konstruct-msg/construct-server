use construct_db::mls as db_mls;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::helpers::{
    check_group_admin, check_group_member, extract_device_id, get_group_dissolved_at,
    verify_admin_proof,
};
use crate::service::MlsServiceImpl;

pub(crate) async fn delegate_admin(
    svc: &MlsServiceImpl,
    request: Request<proto::DelegateAdminRequest>,
) -> Result<Response<proto::DelegateAdminResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    // 2. Verify caller is FULL admin (role=1) or creator
    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;

    if !is_creator && !is_admin {
        return Err(Status::permission_denied("NOT_ADMIN"));
    }

    // 3. Verify admin proof
    let signature_timestamp = req.signature_timestamp;
    let message = format!(
        "CONSTRUCT_DELEGATE_ADMIN:{}:{}:{}",
        req.group_id, req.target_device_id, signature_timestamp
    );

    verify_admin_proof(
        svc.db.as_ref(),
        &device_id,
        "CONSTRUCT_DELEGATE_ADMIN",
        &req.admin_proof,
        signature_timestamp,
        &message,
    )
    .await?;

    // 4. Check group not dissolved
    if get_group_dissolved_at(svc.db.as_ref(), group_id)
        .await?
        .is_some()
    {
        return Err(Status::not_found("Group dissolved"));
    }

    // 5. Verify target is a member
    let target_is_member =
        check_group_member(svc.db.as_ref(), group_id, &req.target_device_id).await?;

    if !target_is_member {
        return Err(Status::not_found("Target is not a member of this group"));
    }

    // 6. Validate role
    let role_value = match req.role() {
        proto::AdminRole::Full => 1i16,
        proto::AdminRole::Moderator => 2i16,
        _ => return Err(Status::invalid_argument("Invalid admin role")),
    };

    // 7. Cannot change creator's role
    let (target_is_creator, _) =
        check_group_admin(svc.db.as_ref(), group_id, &req.target_device_id).await?;

    if target_is_creator {
        return Err(Status::failed_precondition("Cannot change creator's role"));
    }

    // 8. Insert or update admin role
    let now = chrono::Utc::now();

    db_mls::upsert_group_admin_role(
        svc.db.as_ref(),
        group_id,
        &req.target_device_id,
        role_value,
        if req.encrypted_admin_token.is_empty() {
            None
        } else {
            Some(req.encrypted_admin_token.as_slice())
        },
        &device_id,
        now,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to delegate admin: {}", e)))?;

    info!(
        group_id = %group_id,
        admin_device_id = %device_id,
        target_device_id = %req.target_device_id,
        role = role_value,
        "Admin role delegated"
    );

    Ok(Response::new(proto::DelegateAdminResponse {
        success: true,
        delegated_at: now.timestamp(),
    }))
}

pub(crate) async fn transfer_ownership(
    svc: &MlsServiceImpl,
    request: Request<proto::TransferOwnershipRequest>,
) -> Result<Response<proto::TransferOwnershipResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    // 2. Verify caller is creator
    let (is_creator, _) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;

    if !is_creator {
        return Err(Status::permission_denied(
            "Only creator can transfer ownership",
        ));
    }

    // 3. Verify target is FULL admin (not moderator)
    let (target_is_creator, target_is_admin) =
        check_group_admin(svc.db.as_ref(), group_id, &req.new_owner_device_id).await?;

    if target_is_creator {
        return Err(Status::invalid_argument("Target is already creator"));
    }

    if !target_is_admin {
        return Err(Status::permission_denied(
            "Target must be FULL admin to receive ownership",
        ));
    }

    // 4. Verify owner signature
    let signature_timestamp = req.signature_timestamp;
    let owner_message = format!(
        "CONSTRUCT_TRANSFER_OWNERSHIP:{}:{}:{}",
        req.group_id, req.new_owner_device_id, signature_timestamp
    );

    verify_admin_proof(
        svc.db.as_ref(),
        &device_id,
        "CONSTRUCT_TRANSFER_OWNERSHIP",
        &req.owner_signature,
        signature_timestamp,
        &owner_message,
    )
    .await?;

    // 5. Verify new owner acceptance signature
    let acceptance_message = format!(
        "CONSTRUCT_ACCEPT_OWNERSHIP:{}:{}:{}",
        req.group_id, device_id, signature_timestamp
    );

    verify_admin_proof(
        svc.db.as_ref(),
        &req.new_owner_device_id,
        "CONSTRUCT_ACCEPT_OWNERSHIP",
        &req.new_owner_acceptance,
        signature_timestamp,
        &acceptance_message,
    )
    .await?;

    // 6. Atomic transaction: transfer ownership
    let now = chrono::Utc::now();
    let mut tx = svc
        .db
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Failed to start transaction: {}", e)))?;

    db_mls::transfer_group_ownership(&mut tx, group_id, &device_id, &req.new_owner_device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to transfer ownership: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    info!(
        group_id = %group_id,
        old_owner = %device_id,
        new_owner = %req.new_owner_device_id,
        "Ownership transferred"
    );

    Ok(Response::new(proto::TransferOwnershipResponse {
        success: true,
        transferred_at: now.timestamp(),
    }))
}
