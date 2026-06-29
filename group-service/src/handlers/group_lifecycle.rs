use construct_db::mls as db_mls;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::helpers::{
    check_device_belongs_to_user, check_group_admin, check_group_member, extract_device_id,
    extract_user_id, get_group_dissolved_at, get_group_max_members, get_group_member_count,
    verify_admin_proof,
};
use crate::service::GroupServiceImpl;

pub(crate) async fn create_group(
    svc: &GroupServiceImpl,
    request: Request<proto::CreateGroupRequest>,
) -> Result<Response<proto::CreateGroupResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    let rl_key = format!("rl:group_create:{}", user_id);
    let allowed = construct_rate_limit::sliding_window_check_and_record(
        &mut svc.redis.clone(),
        &rl_key,
        10,
        24 * 3600,
    )
    .await
    .map_err(|e| Status::internal(format!("Rate limit error: {e}")))?;
    if !allowed {
        return Err(Status::resource_exhausted(
            "Rate limit exceeded: maximum 10 groups per day",
        ));
    }

    let group_id = Uuid::parse_str(&req.group_id)
        .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

    if req.initial_ratchet_tree.is_empty() {
        return Err(Status::invalid_argument("initial_ratchet_tree is required"));
    }

    if req.max_members > 2048 {
        return Err(Status::invalid_argument("max_members cannot exceed 2048"));
    }
    if req.max_members == 0 {
        return Err(Status::invalid_argument("max_members must be at least 1"));
    }

    let retention_days = if req.message_retention_days == 0 {
        90
    } else if req.message_retention_days > 365 {
        return Err(Status::invalid_argument(
            "message_retention_days cannot exceed 365",
        ));
    } else {
        req.message_retention_days
    };

    if !check_device_belongs_to_user(svc.db.as_ref(), &device_id, user_id).await? {
        return Err(Status::permission_denied(
            "Device does not belong to authenticated user",
        ));
    }

    let now = chrono::Utc::now();

    db_mls::create_group_with_creator(
        svc.db.as_ref(),
        db_mls::NewGroup {
            group_id,
            creator_device_id: &device_id,
            initial_ratchet_tree: &req.initial_ratchet_tree,
            encrypted_group_context: &req.encrypted_group_context,
            max_members: req.max_members as i16,
            message_retention_days: retention_days as i16,
            threads_enabled: req.threads_enabled,
            created_at: now,
        },
    )
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            Status::already_exists("Group with this ID already exists")
        } else {
            Status::internal(format!("Failed to create group: {}", e))
        }
    })?;

    info!(
        group_id = %group_id,
        device_id = %device_id,
        user_id = %user_id,
        max_members = req.max_members,
        threads_enabled = req.threads_enabled,
        "Group created"
    );

    crate::metrics::inc_groups_created();
    crate::metrics::observe_group_size(1);

    Ok(Response::new(proto::CreateGroupResponse {
        group_id: group_id.to_string(),
        epoch: 0,
        created_at: now.timestamp(),
    }))
}

pub(crate) async fn get_group_state(
    svc: &GroupServiceImpl,
    request: Request<proto::GetGroupStateRequest>,
) -> Result<Response<proto::GetGroupStateResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    let group_id = Uuid::parse_str(&req.group_id)
        .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

    let is_member = check_group_member(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    let group_row = db_mls::get_active_group_state(svc.db.as_ref(), group_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to fetch group state: {}", e)))?;

    let (
        epoch,
        ratchet_tree,
        _encrypted_group_context,
        retention_days,
        threads_enabled,
        created_at,
    ) = group_row
        .map(
            |db_mls::GroupStateRecord {
                 epoch,
                 ratchet_tree,
                 encrypted_group_context,
                 message_retention_days,
                 threads_enabled,
                 created_at,
             }| {
                (
                    epoch,
                    ratchet_tree,
                    encrypted_group_context,
                    message_retention_days,
                    threads_enabled,
                    created_at,
                )
            },
        )
        .ok_or_else(|| Status::not_found("Group not found or dissolved"))?;

    let member_count = get_group_member_count(svc.db.as_ref(), group_id).await?;
    let max_members = get_group_max_members(svc.db.as_ref(), group_id).await?;

    let settings = proto::GroupSettings {
        max_members: max_members as u32,
        member_count: member_count as u32,
        message_retention_days: retention_days as u32,
        threads_enabled,
        created_at: created_at.timestamp(),
        messages_deleted_before: 0,
    };

    let response = if let Some(known_epoch) = req.known_epoch {
        if known_epoch < epoch as u64 {
            let commits =
                db_mls::get_pending_commits_since(svc.db.as_ref(), group_id, known_epoch as i64)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("Failed to fetch pending commits: {}", e))
                    })?;

            let pending_commits: Vec<proto::CommitEnvelope> = commits
                .into_iter()
                .map(|commit| proto::CommitEnvelope {
                    group_id: group_id.to_string(),
                    epoch_from: commit.epoch_from as u64,
                    epoch_to: commit.epoch_to as u64,
                    mls_commit: commit.mls_commit,
                    ratchet_tree: commit.ratchet_tree_snapshot,
                    mls_welcome: None,
                    committed_at: 0,
                })
                .collect();

            proto::GetGroupStateResponse {
                epoch: epoch as u64,
                ratchet_tree: None,
                pending_commits,
                settings: Some(settings),
            }
        } else {
            proto::GetGroupStateResponse {
                epoch: epoch as u64,
                ratchet_tree: None,
                pending_commits: vec![],
                settings: Some(settings),
            }
        }
    } else {
        proto::GetGroupStateResponse {
            epoch: epoch as u64,
            ratchet_tree: Some(ratchet_tree),
            pending_commits: vec![],
            settings: Some(settings),
        }
    };

    Ok(Response::new(response))
}

pub(crate) async fn dissolve_group(
    svc: &GroupServiceImpl,
    request: Request<proto::DissolveGroupRequest>,
) -> Result<Response<proto::DissolveGroupResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    let group_id = Uuid::parse_str(&req.group_id)
        .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;

    if !is_creator && !is_admin {
        return Err(Status::permission_denied("NOT_ADMIN"));
    }

    let signature_timestamp = req.signature_timestamp;
    let message = format!(
        "CONSTRUCT_DISSOLVE_GROUP:{}:{}",
        req.group_id, signature_timestamp
    );

    verify_admin_proof(
        svc.db.as_ref(),
        &device_id,
        "CONSTRUCT_DISSOLVE_GROUP",
        &req.admin_proof,
        signature_timestamp,
        &message,
    )
    .await?;

    if get_group_dissolved_at(svc.db.as_ref(), group_id)
        .await?
        .is_some()
    {
        return Err(Status::not_found("Group already dissolved"));
    }

    let now = chrono::Utc::now();
    db_mls::set_group_dissolved_at(svc.db.as_ref(), group_id, now)
        .await
        .map_err(|e| Status::internal(format!("Failed to dissolve group: {}", e)))?;

    if let Some(ref notification_client) = svc.notification_client {
        let client = notification_client.clone();
        let db = svc.db.clone();
        let gid = group_id;
        tokio::spawn(async move {
            if let Ok(member_devices) = db_mls::get_group_member_device_ids(&db, gid).await {
                for device_id in &member_devices {
                    if let Ok(Some(user_id)) = db_mls::get_user_id_for_device(&db, device_id).await
                    {
                        let mut nc = client.get();
                        let _ = nc
                            .send_blind_notification(
                                construct_server_shared::shared::proto::services::v1::SendBlindNotificationRequest {
                                    user_id: user_id.to_string(),
                                    badge_count: None,
                                    activity_type: Some("group_dissolved".to_string()),
                                    conversation_id: Some(gid.to_string()),
                                },
                            )
                            .await;
                    }
                }
            }
        });
    }

    let member_count = get_group_member_count(svc.db.as_ref(), group_id).await?;

    crate::metrics::inc_groups_dissolved();
    crate::metrics::observe_group_size(member_count as u64);

    info!(
        group_id = %group_id,
        device_id = %device_id,
        member_count = member_count,
        "Group dissolved (soft-delete, hard-delete after 24h)"
    );

    Ok(Response::new(proto::DissolveGroupResponse {
        success: true,
        dissolved_at: now.timestamp(),
    }))
}
