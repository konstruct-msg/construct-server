use construct_db::mls as db_mls;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::helpers::{
    check_device_belongs_to_user, check_group_admin, check_group_member, extract_device_id,
    extract_user_id, get_group_dissolved_at, get_group_epoch, get_group_max_members,
    get_group_member_count, verify_admin_proof,
};
use crate::service::MlsServiceImpl;

pub(crate) async fn invite_to_group(
    svc: &MlsServiceImpl,
    request: Request<proto::InviteToGroupRequest>,
) -> Result<Response<proto::InviteToGroupResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id = Uuid::parse_str(&req.group_id)
        .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

    // 2. Verify caller is admin of the group
    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;

    if !is_creator && !is_admin {
        return Err(Status::permission_denied("NOT_ADMIN"));
    }

    // 3. Check group not dissolved
    if get_group_dissolved_at(svc.db.as_ref(), group_id)
        .await?
        .is_some()
    {
        return Err(Status::not_found("Group dissolved"));
    }

    // 4. Validate mls_welcome is not empty
    if req.mls_welcome.is_empty() {
        return Err(Status::invalid_argument("mls_welcome is required"));
    }

    // 5. Validate key_package_ref is not empty
    if req.key_package_ref.is_empty() {
        return Err(Status::invalid_argument("key_package_ref is required"));
    }

    // 6. Validate expires_in_seconds (max 7 days = 604800 seconds)
    let expires_in_seconds = if req.expires_in_seconds == 0 {
        604800 // default: 7 days
    } else if req.expires_in_seconds > 604800 {
        return Err(Status::invalid_argument(
            "expires_in_seconds cannot exceed 604800 (7 days)",
        ));
    } else {
        req.expires_in_seconds
    };

    // 7. Extract target_device_id from the key_package_ref
    // The client must send the target device's ID in the mls_welcome or key_package_ref.
    // For now, we need to look it up from the consumed KeyPackage.
    // Since we're using key_package_ref as SHA-256 hash, we can find the device_id from that.
    let target_device_id =
        db_mls::get_key_package_device_by_ref(svc.db.as_ref(), &req.key_package_ref)
            .await
            .map_err(|e| Status::internal(format!("Failed to resolve key package: {}", e)))?
            .ok_or_else(|| {
                Status::not_found(
                    "KeyPackage not found or expired; target must publish a KeyPackage first",
                )
            })?;

    // 8. Check if device is already a member
    let already_member = check_group_member(svc.db.as_ref(), group_id, &target_device_id).await?;

    if already_member {
        return Err(Status::already_exists(
            "Device is already a member of this group",
        ));
    }

    // 9. Check max_members limit
    let member_count = get_group_member_count(svc.db.as_ref(), group_id).await?;
    let max_members = get_group_max_members(svc.db.as_ref(), group_id).await?;

    if member_count >= max_members as i64 {
        return Err(Status::resource_exhausted(
            "GROUP_FULL: max_members reached",
        ));
    }

    // 10. Check if there's already a pending invite for this device
    let existing_invite =
        db_mls::has_pending_group_invite(svc.db.as_ref(), group_id, &target_device_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to check pending invite: {}", e)))?;

    if existing_invite {
        return Err(Status::already_exists(
            "Device already has a pending invite for this group",
        ));
    }

    // 11. Insert invite
    let invite_id = Uuid::new_v4();
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(expires_in_seconds as i64);

    db_mls::insert_group_invite(
        svc.db.as_ref(),
        db_mls::NewGroupInvite {
            invite_id,
            group_id,
            target_device_id: &target_device_id,
            mls_welcome: &req.mls_welcome,
            key_package_ref: &req.key_package_ref,
            epoch: req.epoch as i64,
            invited_at: now,
            expires_at,
        },
    )
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            Status::already_exists("Device already has a pending invite for this group")
        } else {
            Status::internal(format!("Failed to create invite: {}", e))
        }
    })?;

    info!(
        group_id = %group_id,
        invite_id = %invite_id,
        target_device_id = %target_device_id,
        admin_device_id = %device_id,
        expires_at = %expires_at,
        "Group invite created"
    );

    Ok(Response::new(proto::InviteToGroupResponse {
        invite_id: invite_id.to_string(),
        expires_at: expires_at.timestamp(),
    }))
}

pub(crate) async fn accept_group_invite(
    svc: &MlsServiceImpl,
    request: Request<proto::AcceptGroupInviteRequest>,
) -> Result<Response<proto::AcceptGroupInviteResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id and invite_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;
    let invite_id = Uuid::parse_str(&req.invite_id)
        .map_err(|_| Status::invalid_argument("Invalid invite_id"))?;

    // 2. Fetch invite
    let db_mls::InviteAcceptanceRecord {
        target_device_id,
        mls_welcome: _mls_welcome,
        key_package_ref: _key_package_ref,
        epoch: invite_epoch,
    } = db_mls::get_group_invite_for_accept(svc.db.as_ref(), invite_id, group_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to load invite: {}", e)))?
        .ok_or_else(|| Status::not_found("Invite not found or expired"))?;

    // 3. Verify invite belongs to the calling device
    if target_device_id != device_id {
        return Err(Status::permission_denied(
            "Invite belongs to a different device",
        ));
    }

    // 3.5: Early epoch guard — reject stale invites before doing crypto work.
    let current_epoch_early = get_group_epoch(svc.db.as_ref(), group_id).await?;
    if invite_epoch != current_epoch_early {
        return Err(Status::failed_precondition(
            "EPOCH_MISMATCH: invite epoch is stale; group has advanced",
        ));
    }

    // 4. Validate mls_commit and new_ratchet_tree are present (B1 fix)
    if req.mls_commit.is_empty() {
        return Err(Status::invalid_argument("mls_commit is required"));
    }
    if req.new_ratchet_tree.is_empty() {
        return Err(Status::invalid_argument("new_ratchet_tree is required"));
    }

    // 5. Validate acceptance signature
    let signature_timestamp = req.signature_timestamp;

    // Message: "CONSTRUCT_GROUP_JOIN:{group_id}:{invite_id}:{timestamp}"
    let message = format!(
        "CONSTRUCT_GROUP_JOIN:{}:{}:{}",
        req.group_id, req.invite_id, signature_timestamp
    );

    verify_admin_proof(
        svc.db.as_ref(),
        &device_id,
        "CONSTRUCT_GROUP_JOIN",
        &req.acceptance_signature,
        signature_timestamp,
        &message,
    )
    .await?;

    // 6. Verify device belongs to user
    if !check_device_belongs_to_user(svc.db.as_ref(), &device_id, user_id).await? {
        return Err(Status::permission_denied(
            "Device does not belong to authenticated user",
        ));
    }

    // 7. Check if already a member
    let already_member = check_group_member(svc.db.as_ref(), group_id, &device_id).await?;
    if already_member {
        return Err(Status::already_exists("Already a member of this group"));
    }

    // 8. Get next leaf_index
    let next_leaf_index = db_mls::get_next_group_leaf_index(svc.db.as_ref(), group_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to get next leaf index: {}", e)))?;

    // 9. Insert member
    let now = chrono::Utc::now();

    db_mls::insert_group_member(
        svc.db.as_ref(),
        db_mls::NewGroupMember {
            group_id,
            device_id: &device_id,
            leaf_index: next_leaf_index,
            acceptance_signature: Some(&req.acceptance_signature),
            joined_at: now,
        },
    )
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            Status::already_exists("Device is already a member of this group")
        } else {
            Status::internal(format!("Failed to add member: {}", e))
        }
    })?;

    // 10. Atomically: validate epoch CAS, store join commit, advance epoch + ratchet tree
    let mut tx = svc
        .db
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Failed to start transaction: {}", e)))?;

    let current_epoch = db_mls::lock_group_epoch_for_update(&mut tx, group_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to lock group epoch: {}", e)))?;

    // Validate the invite's epoch matches the current group epoch (staleness check)
    if invite_epoch != current_epoch {
        tx.rollback().await.ok();
        return Err(Status::failed_precondition(
            "EPOCH_MISMATCH: invite epoch is stale; group has advanced",
        ));
    }

    let new_epoch = current_epoch + 1;
    let commit_expires = now + chrono::Duration::days(30);

    db_mls::insert_group_commit(
        &mut tx,
        db_mls::NewGroupCommit {
            group_id,
            epoch_from: current_epoch,
            epoch_to: new_epoch,
            mls_commit: &req.mls_commit,
            ratchet_tree_snapshot: &req.new_ratchet_tree,
            committed_at: now,
            expires_at: commit_expires,
        },
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to store join commit: {}", e)))?;

    db_mls::update_group_epoch_and_ratchet_tree(
        &mut tx,
        group_id,
        &req.new_ratchet_tree,
        new_epoch,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to advance group epoch: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    // 11. Delete invite (hard delete — no history)
    db_mls::delete_group_invite(svc.db.as_ref(), invite_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete invite: {}", e)))?;

    info!(
        group_id = %group_id,
        device_id = %device_id,
        user_id = %user_id,
        leaf_index = next_leaf_index,
        old_epoch = current_epoch,
        new_epoch = new_epoch,
        "Group invite accepted, epoch advanced"
    );

    Ok(Response::new(proto::AcceptGroupInviteResponse {
        success: true,
        new_epoch: new_epoch as u64,
        joined_at: now.timestamp(),
    }))
}

pub(crate) async fn decline_group_invite(
    svc: &MlsServiceImpl,
    request: Request<proto::DeclineGroupInviteRequest>,
) -> Result<Response<proto::DeclineGroupInviteResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id and invite_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;
    let invite_id = Uuid::parse_str(&req.invite_id)
        .map_err(|_| Status::invalid_argument("Invalid invite_id"))?;

    // 2. Fetch invite and verify it belongs to the calling device
    let target_device_id =
        db_mls::get_group_invite_target_device(svc.db.as_ref(), invite_id, group_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to load invite target: {}", e)))?;

    match target_device_id {
        None => return Err(Status::not_found("Invite not found")),
        Some(ref target) if *target != device_id => {
            return Err(Status::permission_denied(
                "Invite belongs to a different device",
            ));
        }
        _ => {}
    }

    // 3. Hard delete invite (no history stored)
    db_mls::delete_group_invite(svc.db.as_ref(), invite_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete invite: {}", e)))?;

    info!(
        group_id = %group_id,
        invite_id = %invite_id,
        device_id = %device_id,
        "Group invite declined"
    );

    Ok(Response::new(proto::DeclineGroupInviteResponse {
        success: true,
    }))
}

pub(crate) async fn get_pending_invites(
    svc: &MlsServiceImpl,
    request: Request<proto::GetPendingInvitesRequest>,
) -> Result<Response<proto::GetPendingInvitesResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    // B3 fix: if req.device_id is provided, verify it belongs to the authenticated user.
    // Without this check, any user could fetch pending invites for any device.
    let target_device_id = if req.device_id.is_empty() {
        device_id
    } else {
        if !check_device_belongs_to_user(svc.db.as_ref(), &req.device_id, user_id).await? {
            return Err(Status::permission_denied(
                "device_id does not belong to authenticated user",
            ));
        }
        req.device_id
    };

    // 1. Determine limit (default 50, max 100)
    let limit = if req.limit == 0 {
        50
    } else {
        req.limit.min(100)
    };

    // 2. Query invites (with optional cursor)
    let cursor = req.cursor.as_deref();
    let cursor_uuid = cursor
        .map(|cursor_id| {
            Uuid::parse_str(cursor_id).map_err(|_| Status::invalid_argument("Invalid cursor"))
        })
        .transpose()?;

    let invites = db_mls::list_pending_group_invites(
        svc.db.as_ref(),
        &target_device_id,
        cursor_uuid,
        limit as i64,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to list pending invites: {}", e)))?;

    // 3. Build next_cursor
    let next_cursor = if invites.len() == limit as usize {
        invites.last().map(|invite| invite.invite_id.to_string())
    } else {
        None
    };

    // 4. Convert to proto
    let proto_invites: Vec<proto::PendingGroupInvite> = invites
        .into_iter()
        .map(|invite| proto::PendingGroupInvite {
            invite_id: invite.invite_id.to_string(),
            group_id: invite.group_id.to_string(),
            mls_welcome: invite.mls_welcome,
            expires_at: invite.expires_at.timestamp(),
            invited_at: invite.invited_at.timestamp(),
        })
        .collect();

    Ok(Response::new(proto::GetPendingInvitesResponse {
        invites: proto_invites,
        next_cursor,
    }))
}

pub(crate) async fn leave_group(
    svc: &MlsServiceImpl,
    request: Request<proto::LeaveGroupRequest>,
) -> Result<Response<proto::LeaveGroupResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    // 2. Check group not dissolved
    if get_group_dissolved_at(svc.db.as_ref(), group_id)
        .await?
        .is_some()
    {
        return Err(Status::not_found("Group dissolved"));
    }

    // 3. Verify membership
    let is_member = check_group_member(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    // 4. Check if member is creator (creator cannot leave — they must dissolve)
    let (is_creator, _) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;
    if is_creator {
        return Err(Status::failed_precondition(
            "Creator cannot leave group; use DissolveGroup instead",
        ));
    }

    // 5. Validate remove proposal is present (B2 fix: required for other members to update ratchet tree)
    if req.mls_remove_proposal.is_empty() {
        return Err(Status::invalid_argument(
            "mls_remove_proposal is required; clients must submit a signed Remove Proposal",
        ));
    }

    // 6. Hard delete from group_members (no history)
    let now = chrono::Utc::now();

    db_mls::remove_group_member(svc.db.as_ref(), group_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove member: {}", e)))?;

    // 6. Also remove from group_admins if present
    db_mls::remove_group_admin_role(svc.db.as_ref(), group_id, &device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove admin role: {}", e)))?;

    info!(
        group_id = %group_id,
        device_id = %device_id,
        "Member left group"
    );

    Ok(Response::new(proto::LeaveGroupResponse {
        success: true,
        left_at: now.timestamp(),
    }))
}

pub(crate) async fn remove_member(
    svc: &MlsServiceImpl,
    request: Request<proto::RemoveMemberRequest>,
) -> Result<Response<proto::RemoveMemberResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    // 2. Verify caller is admin
    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;

    if !is_creator && !is_admin {
        return Err(Status::permission_denied("NOT_ADMIN"));
    }

    // 3. Verify admin proof
    let signature_timestamp = req.signature_timestamp;
    let message = format!(
        "CONSTRUCT_REMOVE_MEMBER:{}:{}:{}",
        req.group_id, req.target_device_id, signature_timestamp
    );

    verify_admin_proof(
        svc.db.as_ref(),
        &device_id,
        "CONSTRUCT_REMOVE_MEMBER",
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

    // 6. Cannot remove creator
    let (target_is_creator, _) =
        check_group_admin(svc.db.as_ref(), group_id, &req.target_device_id).await?;

    if target_is_creator {
        return Err(Status::failed_precondition("Cannot remove group creator"));
    }

    // 7. Validate remove proposal is present (B2 fix: required for other members to update ratchet tree)
    if req.mls_remove_proposal.is_empty() {
        return Err(Status::invalid_argument(
            "mls_remove_proposal is required; admin must supply a signed Remove Proposal",
        ));
    }

    // 7. Hard delete from group_members
    let now = chrono::Utc::now();

    db_mls::remove_group_member(svc.db.as_ref(), group_id, &req.target_device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove member: {}", e)))?;

    // 8. Also remove from group_admins
    db_mls::remove_group_admin_role(svc.db.as_ref(), group_id, &req.target_device_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to remove admin role: {}", e)))?;

    // 9. Get current epoch
    let current_epoch = get_group_epoch(svc.db.as_ref(), group_id).await?;

    info!(
        group_id = %group_id,
        admin_device_id = %device_id,
        removed_device_id = %req.target_device_id,
        epoch = current_epoch,
        "Member removed from group"
    );

    Ok(Response::new(proto::RemoveMemberResponse {
        success: true,
        new_epoch: current_epoch as u64,
        removed_at: now.timestamp(),
    }))
}
