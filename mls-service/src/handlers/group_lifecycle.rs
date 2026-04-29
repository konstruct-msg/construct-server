use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use crate::helpers::{
    check_group_admin, check_group_member, extract_device_id, extract_user_id, verify_admin_proof,
};
use crate::service::MlsServiceImpl;

type GroupStateRow = (
    i64,
    Vec<u8>,
    Vec<u8>,
    i16,
    bool,
    chrono::DateTime<chrono::Utc>,
);

type PendingCommitRow = (i64, i64, Vec<u8>, Vec<u8>);

pub(crate) async fn create_group(
    svc: &MlsServiceImpl,
    request: Request<proto::CreateGroupRequest>,
) -> Result<Response<proto::CreateGroupResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let user_id = extract_user_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Validate group_id (must be valid UUID)
    let group_id = Uuid::parse_str(&req.group_id)
        .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

    // 2. Validate initial_ratchet_tree is not empty
    if req.initial_ratchet_tree.is_empty() {
        return Err(Status::invalid_argument("initial_ratchet_tree is required"));
    }

    // 3. Validate max_members (1-2048)
    if req.max_members > 2048 {
        return Err(Status::invalid_argument("max_members cannot exceed 2048"));
    }
    if req.max_members == 0 {
        return Err(Status::invalid_argument("max_members must be at least 1"));
    }

    // 4. Validate message_retention_days (1-365)
    let retention_days = if req.message_retention_days == 0 {
        90 // default
    } else if req.message_retention_days > 365 {
        return Err(Status::invalid_argument(
            "message_retention_days cannot exceed 365",
        ));
    } else {
        req.message_retention_days
    };

    // 5. Check device_id belongs to user_id (security: prevent impersonation)
    let device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1 AND user_id = $2)",
    )
    .bind(&device_id)
    .bind(user_id)
    .fetch_one(svc.db.as_ref())
    .await
    .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    if !device_exists {
        return Err(Status::permission_denied(
            "Device does not belong to authenticated user",
        ));
    }

    let now = chrono::Utc::now();

    // 6. Insert group into mls_groups
    sqlx::query(
        r#"
            INSERT INTO mls_groups
                (group_id, epoch, ratchet_tree, encrypted_group_context,
                 max_members, message_retention_days, threads_enabled, created_at)
            VALUES ($1, 0, $2, $3, $4, $5, $6, $7)
            "#,
    )
    .bind(group_id)
    .bind(&req.initial_ratchet_tree)
    .bind(&req.encrypted_group_context)
    .bind(req.max_members as i16)
    .bind(retention_days as i16)
    .bind(req.threads_enabled)
    .bind(now)
    .execute(svc.db.as_ref())
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate key") {
            Status::already_exists("Group with this ID already exists")
        } else {
            Status::internal(format!("Failed to create group: {}", e))
        }
    })?;

    // 7. Insert creator as first member
    sqlx::query(
        r#"
            INSERT INTO group_members (group_id, device_id, leaf_index, joined_at)
            VALUES ($1, $2, 0, $3)
            "#,
    )
    .bind(group_id)
    .bind(&device_id)
    .bind(now)
    .execute(svc.db.as_ref())
    .await
    .map_err(|e| Status::internal(format!("Failed to add creator to group: {}", e)))?;

    // 8. Insert creator as admin (creator role)
    sqlx::query(
        r#"
            INSERT INTO group_admins
                (group_id, device_id, role, is_creator, granted_by_device_id, granted_at)
            VALUES ($1, $2, 1, TRUE, NULL, $3)
            "#,
    )
    .bind(group_id)
    .bind(&device_id)
    .bind(now)
    .execute(svc.db.as_ref())
    .await
    .map_err(|e| Status::internal(format!("Failed to set creator as admin: {}", e)))?;

    info!(
        group_id = %group_id,
        device_id = %device_id,
        user_id = %user_id,
        max_members = req.max_members,
        threads_enabled = req.threads_enabled,
        "Group created"
    );

    Ok(Response::new(proto::CreateGroupResponse {
        group_id: group_id.to_string(),
        epoch: 0,
        created_at: now.timestamp(),
    }))
}

pub(crate) async fn get_group_state(
    svc: &MlsServiceImpl,
    request: Request<proto::GetGroupStateRequest>,
) -> Result<Response<proto::GetGroupStateResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id = Uuid::parse_str(&req.group_id)
        .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

    // 2. Verify caller is a member of the group
    let is_member = check_group_member(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    // 3. Fetch group state (only non-dissolved groups)
    let group_row: Option<GroupStateRow> = sqlx::query_as(
        r#"
                SELECT epoch, ratchet_tree, encrypted_group_context,
                       message_retention_days, threads_enabled, created_at
                FROM mls_groups
                WHERE group_id = $1 AND dissolved_at IS NULL
                "#,
    )
    .bind(group_id)
    .fetch_optional(svc.db.as_ref())
    .await
    .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    let (
        epoch,
        ratchet_tree,
        _encrypted_group_context,
        retention_days,
        threads_enabled,
        created_at,
    ) = group_row.ok_or_else(|| Status::not_found("Group not found or dissolved"))?;

    // 4. Get member count
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    // 5. Build settings
    let settings = proto::GroupSettings {
        max_members: 2048,
        member_count: member_count as u32,
        message_retention_days: retention_days as u32,
        threads_enabled,
        created_at: created_at.timestamp(),
        messages_deleted_before: 0,
    };

    // 6. If known_epoch provided and recent enough, return commits instead
    let response = if let Some(known_epoch) = req.known_epoch {
        if known_epoch < epoch as u64 {
            let commits: Vec<PendingCommitRow> = sqlx::query_as(
                r#"
                    SELECT epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot
                    FROM group_commits
                    WHERE group_id = $1 AND epoch_from >= $2 AND expires_at > NOW()
                    ORDER BY epoch_from ASC
                    "#,
            )
            .bind(group_id)
            .bind(known_epoch as i64)
            .fetch_all(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

            let pending_commits: Vec<proto::CommitEnvelope> = commits
                .into_iter()
                .map(|(from, to, commit, tree)| proto::CommitEnvelope {
                    group_id: group_id.to_string(),
                    epoch_from: from as u64,
                    epoch_to: to as u64,
                    mls_commit: commit,
                    ratchet_tree: tree,
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
    svc: &MlsServiceImpl,
    request: Request<proto::DissolveGroupRequest>,
) -> Result<Response<proto::DissolveGroupResponse>, Status> {
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

    // 3. Verify admin proof signature
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

    // 4. Check group not already dissolved
    let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
            .bind(group_id)
            .fetch_optional(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?
            .flatten();

    if dissolved_at.is_some() {
        return Err(Status::not_found("Group already dissolved"));
    }

    // 5. Soft-delete (set dissolved_at)
    let now = chrono::Utc::now();
    sqlx::query("UPDATE mls_groups SET dissolved_at = $1 WHERE group_id = $2")
        .bind(now)
        .bind(group_id)
        .execute(svc.db.as_ref())
        .await
        .map_err(|e| Status::internal(format!("Failed to dissolve group: {}", e)))?;

    // 6. Log the dissolve
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

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
