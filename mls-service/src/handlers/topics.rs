use construct_db::mls::{
    archive_topic_record, count_active_topics, create_invite_link_record, create_topic_record,
    list_topic_records, resolve_invite_link_record, revoke_invite_link_record,
};
use construct_server_shared::shared::proto::services::v1::{self as proto};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::helpers::{
    check_group_admin, check_group_member, extract_device_id, extract_user_id,
    get_group_dissolved_at, get_group_member_count, verify_admin_proof,
};
use crate::service::MlsServiceImpl;

// ============================================================================
// CreateTopic
// ============================================================================

pub(crate) async fn create_topic(
    svc: &MlsServiceImpl,
    request: Request<proto::CreateTopicRequest>,
) -> Result<Response<proto::CreateTopicResponse>, Status> {
    let meta = request.metadata();
    let user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    if req.encrypted_name.is_empty() {
        return Err(Status::invalid_argument("encrypted_name must not be empty"));
    }
    if req.sort_order > 49 {
        return Err(Status::invalid_argument("sort_order must be 0–49"));
    }

    if get_group_dissolved_at(&svc.db, group_id).await?.is_some() {
        return Err(Status::failed_precondition("Group has been dissolved"));
    }

    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_creator && !is_admin {
        return Err(Status::permission_denied(
            "Only group admins can create topics",
        ));
    }

    let message = format!(
        "CONSTRUCT_CREATE_TOPIC:{}:{}",
        group_id, req.signature_timestamp
    );
    verify_admin_proof(
        &svc.db,
        &device_id,
        "CONSTRUCT_CREATE_TOPIC",
        &req.admin_proof,
        req.signature_timestamp,
        &message,
    )
    .await?;

    // Enforce max 50 active topics per group.
    let active_count = count_active_topics(&svc.db, group_id)
        .await
        .map_err(|e| Status::internal(format!("Topic count failed: {e}")))?;
    if active_count >= 50 {
        return Err(Status::resource_exhausted(
            "Group has reached the maximum of 50 active topics",
        ));
    }

    let row = create_topic_record(
        &svc.db,
        group_id,
        &req.encrypted_name,
        req.sort_order as i16,
        &device_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            group_id = %group_id,
            user_id  = %user_id,
            "create_topic_record failed: {e}"
        );
        Status::internal("Failed to create topic")
    })?;

    Ok(Response::new(proto::CreateTopicResponse {
        topic_id: row.topic_id.to_string(),
        created_at: row.created_at.timestamp(),
    }))
}

// ============================================================================
// ListTopics
// ============================================================================

pub(crate) async fn list_topics(
    svc: &MlsServiceImpl,
    request: Request<proto::ListTopicsRequest>,
) -> Result<Response<proto::ListTopicsResponse>, Status> {
    let meta = request.metadata();
    let _user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    let is_member = check_group_member(&svc.db, group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    let rows = list_topic_records(&svc.db, group_id, req.include_archived)
        .await
        .map_err(|e| Status::internal(format!("Failed to list topics: {e}")))?;

    let topics = rows
        .into_iter()
        .map(|r| proto::TopicInfo {
            topic_id: r.topic_id.to_string(),
            group_id: r.group_id.to_string(),
            encrypted_name: r.encrypted_name,
            sort_order: r.sort_order as u32,
            created_at: r.created_at.timestamp(),
            archived_at: r.archived_at.map(|t| t.timestamp()),
        })
        .collect();

    Ok(Response::new(proto::ListTopicsResponse { topics }))
}

// ============================================================================
// ArchiveTopic
// ============================================================================

pub(crate) async fn archive_topic(
    svc: &MlsServiceImpl,
    request: Request<proto::ArchiveTopicRequest>,
) -> Result<Response<proto::ArchiveTopicResponse>, Status> {
    let meta = request.metadata();
    let _user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;
    let topic_id = req
        .topic_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid topic_id"))?;

    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_creator && !is_admin {
        return Err(Status::permission_denied(
            "Only group admins can archive topics",
        ));
    }

    let message = format!(
        "CONSTRUCT_ARCHIVE_TOPIC:{}:{}:{}",
        group_id, topic_id, req.signature_timestamp
    );
    verify_admin_proof(
        &svc.db,
        &device_id,
        "CONSTRUCT_ARCHIVE_TOPIC",
        &req.admin_proof,
        req.signature_timestamp,
        &message,
    )
    .await?;

    let archived_at = archive_topic_record(&svc.db, group_id, topic_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("not found") || e.to_string().contains("wrong group") {
                Status::not_found("Topic not found or already archived")
            } else {
                Status::internal(format!("Failed to archive topic: {e}"))
            }
        })?;

    Ok(Response::new(proto::ArchiveTopicResponse {
        success: true,
        archived_at: archived_at.timestamp(),
    }))
}

// ============================================================================
// CreateInviteLink
// ============================================================================

pub(crate) async fn create_invite_link(
    svc: &MlsServiceImpl,
    request: Request<proto::CreateInviteLinkRequest>,
) -> Result<Response<proto::CreateInviteLinkResponse>, Status> {
    let meta = request.metadata();
    let _user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    if get_group_dissolved_at(&svc.db, group_id).await?.is_some() {
        return Err(Status::failed_precondition("Group has been dissolved"));
    }

    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_creator && !is_admin {
        return Err(Status::permission_denied(
            "Only group admins can create invite links",
        ));
    }

    let message = format!(
        "CONSTRUCT_CREATE_INVITE_LINK:{}:{}",
        group_id, req.signature_timestamp
    );
    verify_admin_proof(
        &svc.db,
        &device_id,
        "CONSTRUCT_CREATE_INVITE_LINK",
        &req.admin_proof,
        req.signature_timestamp,
        &message,
    )
    .await?;

    let max_uses = if req.max_uses == 0 {
        None
    } else {
        Some(req.max_uses as i32)
    };

    let expires_at = if req.expires_in_seconds == 0 {
        None
    } else {
        Some(chrono::Utc::now() + chrono::Duration::seconds(req.expires_in_seconds as i64))
    };

    let row = {
        // Generate 32-char hex token (mls-service already depends on rand + hex).
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        create_invite_link_record(&svc.db, &token, group_id, &device_id, max_uses, expires_at)
            .await
            .map_err(|e| Status::internal(format!("Failed to create invite link: {e}")))?
    };

    Ok(Response::new(proto::CreateInviteLinkResponse {
        token: row.token,
        created_at: row.created_at.timestamp(),
        expires_at: row.expires_at.map(|t| t.timestamp()),
    }))
}

// ============================================================================
// RevokeInviteLink
// ============================================================================

pub(crate) async fn revoke_invite_link(
    svc: &MlsServiceImpl,
    request: Request<proto::RevokeInviteLinkRequest>,
) -> Result<Response<proto::RevokeInviteLinkResponse>, Status> {
    let meta = request.metadata();
    let _user_id = extract_user_id(meta)?;
    let device_id = extract_device_id(meta)?;
    let req = request.into_inner();

    let group_id = req
        .group_id
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    if req.token.len() != 32 {
        return Err(Status::invalid_argument("Token must be 32 hex characters"));
    }

    let (is_creator, is_admin) = check_group_admin(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_creator && !is_admin {
        return Err(Status::permission_denied(
            "Only group admins can revoke invite links",
        ));
    }

    let message = format!(
        "CONSTRUCT_REVOKE_INVITE_LINK:{}:{}:{}",
        group_id, req.token, req.signature_timestamp
    );
    verify_admin_proof(
        &svc.db,
        &device_id,
        "CONSTRUCT_REVOKE_INVITE_LINK",
        &req.admin_proof,
        req.signature_timestamp,
        &message,
    )
    .await?;

    let revoked_at = revoke_invite_link_record(&svc.db, group_id, &req.token)
        .await
        .map_err(|e| {
            if e.to_string().contains("not found")
                || e.to_string().contains("wrong group")
                || e.to_string().contains("already revoked")
            {
                Status::not_found("Invite link not found or already revoked")
            } else {
                Status::internal(format!("Failed to revoke invite link: {e}"))
            }
        })?;

    Ok(Response::new(proto::RevokeInviteLinkResponse {
        success: true,
        revoked_at: revoked_at.timestamp(),
    }))
}

// ============================================================================
// ResolveInviteLink  (public — no auth required)
// ============================================================================

pub(crate) async fn resolve_invite_link(
    svc: &MlsServiceImpl,
    request: Request<proto::ResolveInviteLinkRequest>,
) -> Result<Response<proto::ResolveInviteLinkResponse>, Status> {
    let req = request.into_inner();

    if req.token.len() != 32 {
        return Err(Status::invalid_argument("Token must be 32 hex characters"));
    }

    let row = resolve_invite_link_record(&svc.db, &req.token)
        .await
        .map_err(|e| Status::internal(format!("Failed to resolve invite link: {e}")))?
        .ok_or_else(|| Status::not_found("Invite link not found"))?;

    let now = chrono::Utc::now();

    let valid = row.revoked_at.is_none()
        && row.expires_at.is_none_or(|exp| exp > now)
        && row.max_uses.is_none_or(|max| row.use_count < max);

    let member_count = get_group_member_count(&svc.db, row.group_id)
        .await
        .map_err(|e| Status::internal(format!("Member count lookup failed: {e}")))?;

    Ok(Response::new(proto::ResolveInviteLinkResponse {
        group_id: row.group_id.to_string(),
        member_count: member_count as u32,
        valid,
        expires_at: row.expires_at.map(|t| t.timestamp()),
    }))
}
