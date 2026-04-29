// ============================================================================
// MLS Service - RFC 9420 Group Messaging
// ============================================================================
//
// Phase 1: KeyPackage management fully implemented.
// Phase 2: Group lifecycle (CreateGroup, GetGroupState, DissolveGroup).
// All other RPCs (membership, messaging) are stubs pending Phase 3+.
//
// Port: 50058
// ============================================================================

use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    mls_service_server::{MlsService, MlsServiceServer},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// ============================================================================
// Service State
// ============================================================================

#[derive(Clone)]
pub(crate) struct MlsServiceImpl {
    pub(crate) db: Arc<sqlx::PgPool>,
}

// ============================================================================
// Helpers
// ============================================================================

fn get_metadata_str<'a>(meta: &'a tonic::metadata::MetadataMap, key: &str) -> Option<&'a str> {
    meta.get(key).and_then(|v| v.to_str().ok())
}

fn extract_user_id(meta: &tonic::metadata::MetadataMap) -> Result<Uuid, Status> {
    get_metadata_str(meta, "x-user-id")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| Status::unauthenticated("Missing or invalid x-user-id"))
}

/// Extract device_id from gRPC metadata
fn extract_device_id(meta: &tonic::metadata::MetadataMap) -> Result<String, Status> {
    get_metadata_str(meta, "x-device-id")
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-device-id"))
}

/// Validate Ed25519 admin proof signature with timestamp freshness check.
///
/// Verifies: Ed25519.verify(verifying_key, signature, message)
/// where message = "{operation}:{params...}:{timestamp}"
/// Timestamp must be within ±5 minutes of server time.
async fn verify_admin_proof(
    db: &sqlx::PgPool,
    device_id: &str,
    operation_prefix: &str,
    signature_bytes: &[u8],
    timestamp: i64,
    message: &str,
) -> Result<(), Status> {
    // 1. Timestamp freshness (±5 minutes)
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > 300 {
        return Err(Status::invalid_argument(
            "Signature timestamp expired or invalid",
        ));
    }

    // 2. Load device verifying key from DB
    let verifying_key_bytes: Vec<u8> =
        sqlx::query_scalar("SELECT verifying_key FROM devices WHERE device_id = $1")
            .bind(device_id)
            .fetch_optional(db)
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?
            .ok_or_else(|| Status::not_found("Device not found"))?;

    // 3. Parse Ed25519 public key
    let key_bytes: [u8; 32] = verifying_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Status::invalid_argument("Invalid verifying_key length"))?;

    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Status::invalid_argument(format!("Invalid Ed25519 key: {}", e)))?;

    // 4. Parse signature
    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("Signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_bytes);

    // 5. Verify
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| {
            warn!(
                device_id = %device_id,
                operation = %operation_prefix,
                error = %e,
                "Admin proof signature verification failed"
            );
            Status::permission_denied("Invalid admin proof signature")
        })
}

/// Check if device is admin/creator of a group
async fn check_group_admin(
    db: &sqlx::PgPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<(bool, bool), Status> {
    // Returns (is_creator, is_full_admin)
    let row: Option<(bool, i16)> = sqlx::query_as(
        "SELECT is_creator, role FROM group_admins WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(db)
    .await
    .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    match row {
        Some((is_creator, role)) => Ok((is_creator, role == 1)), // role=1 is FULL
        None => Ok((false, false)),
    }
}

/// Check if device is a member of a group
async fn check_group_member(
    db: &sqlx::PgPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<bool, Status> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2)",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_one(db)
    .await
    .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    Ok(exists)
}

// ============================================================================
// Service Implementation
// ============================================================================

#[tonic::async_trait]
impl MlsService for MlsServiceImpl {
    // ── Group Lifecycle ───────────────────────────────────────────────────

    async fn create_group(
        &self,
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
        .fetch_one(self.db.as_ref())
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
        .execute(self.db.as_ref())
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
        .execute(self.db.as_ref())
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
        .execute(self.db.as_ref())
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

    async fn get_group_state(
        &self,
        request: Request<proto::GetGroupStateRequest>,
    ) -> Result<Response<proto::GetGroupStateResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let req = request.into_inner();

        // 1. Parse group_id
        let group_id = Uuid::parse_str(&req.group_id)
            .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

        // 2. Verify caller is a member of the group
        let is_member = check_group_member(self.db.as_ref(), group_id, &device_id).await?;
        if !is_member {
            return Err(Status::permission_denied("NOT_MEMBER"));
        }

        // 3. Fetch group state (only non-dissolved groups)
        let group_row: Option<(
            i64,
            Vec<u8>,
            Vec<u8>,
            i16,
            bool,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            r#"
                SELECT epoch, ratchet_tree, encrypted_group_context,
                       message_retention_days, threads_enabled, created_at
                FROM mls_groups
                WHERE group_id = $1 AND dissolved_at IS NULL
                "#,
        )
        .bind(group_id)
        .fetch_optional(self.db.as_ref())
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
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        // 5. Build settings
        let settings = proto::GroupSettings {
            max_members: 2048, // Default, or could be from DB if needed
            member_count: member_count as u32,
            message_retention_days: retention_days as u32,
            threads_enabled,
            created_at: created_at.timestamp(),
            messages_deleted_before: 0, // Set by cleanup job
        };

        // 6. If known_epoch provided and recent enough, return commits instead
        let response = if let Some(known_epoch) = req.known_epoch {
            if known_epoch < epoch as u64 {
                // Fetch commits since known_epoch
                let commits: Vec<(i64, i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
                    r#"
                    SELECT epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot
                    FROM group_commits
                    WHERE group_id = $1 AND epoch_from >= $2 AND expires_at > NOW()
                    ORDER BY epoch_from ASC
                    "#,
                )
                .bind(group_id)
                .bind(known_epoch as i64)
                .fetch_all(self.db.as_ref())
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
                        committed_at: 0, // TODO: store committed_at
                    })
                    .collect();

                proto::GetGroupStateResponse {
                    epoch: epoch as u64,
                    ratchet_tree: None, // Not needed if commits are available
                    pending_commits,
                    settings: Some(settings),
                }
            } else {
                // Known epoch is current or ahead — no updates needed
                proto::GetGroupStateResponse {
                    epoch: epoch as u64,
                    ratchet_tree: None,
                    pending_commits: vec![],
                    settings: Some(settings),
                }
            }
        } else {
            // No known_epoch — return full state
            proto::GetGroupStateResponse {
                epoch: epoch as u64,
                ratchet_tree: Some(ratchet_tree),
                pending_commits: vec![],
                settings: Some(settings),
            }
        };

        Ok(Response::new(response))
    }

    async fn dissolve_group(
        &self,
        request: Request<proto::DissolveGroupRequest>,
    ) -> Result<Response<proto::DissolveGroupResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let req = request.into_inner();

        // 1. Parse group_id
        let group_id = Uuid::parse_str(&req.group_id)
            .map_err(|_| Status::invalid_argument("Invalid group_id (must be UUID)"))?;

        // 2. Verify caller is admin of the group
        let (is_creator, is_admin) =
            check_group_admin(self.db.as_ref(), group_id, &device_id).await?;

        if !is_creator && !is_admin {
            return Err(Status::permission_denied("NOT_ADMIN"));
        }

        // 3. Verify admin proof signature
        let signature_timestamp = req.signature_timestamp;

        // Expected message: "CONSTRUCT_DISSOLVE_GROUP:{group_id}:{timestamp}"
        let message = format!(
            "CONSTRUCT_DISSOLVE_GROUP:{}:{}",
            req.group_id, signature_timestamp
        );

        verify_admin_proof(
            self.db.as_ref(),
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
                .fetch_optional(self.db.as_ref())
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
            .execute(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("Failed to dissolve group: {}", e)))?;

        // 6. TODO: Push notification to all members via stream (Phase 5+)
        // For now, log the dissolve
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(self.db.as_ref())
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

    // ── Membership ────────────────────────────────────────────────────────

    async fn invite_to_group(
        &self,
        _request: Request<proto::InviteToGroupRequest>,
    ) -> Result<Response<proto::InviteToGroupResponse>, Status> {
        Err(Status::unimplemented("InviteToGroup — Phase 3"))
    }

    async fn accept_group_invite(
        &self,
        _request: Request<proto::AcceptGroupInviteRequest>,
    ) -> Result<Response<proto::AcceptGroupInviteResponse>, Status> {
        Err(Status::unimplemented("AcceptGroupInvite — Phase 3"))
    }

    async fn decline_group_invite(
        &self,
        _request: Request<proto::DeclineGroupInviteRequest>,
    ) -> Result<Response<proto::DeclineGroupInviteResponse>, Status> {
        Err(Status::unimplemented("DeclineGroupInvite — Phase 3"))
    }

    async fn get_pending_invites(
        &self,
        _request: Request<proto::GetPendingInvitesRequest>,
    ) -> Result<Response<proto::GetPendingInvitesResponse>, Status> {
        Err(Status::unimplemented("GetPendingInvites — Phase 3"))
    }

    async fn leave_group(
        &self,
        _request: Request<proto::LeaveGroupRequest>,
    ) -> Result<Response<proto::LeaveGroupResponse>, Status> {
        Err(Status::unimplemented("LeaveGroup — Phase 3"))
    }

    async fn remove_member(
        &self,
        _request: Request<proto::RemoveMemberRequest>,
    ) -> Result<Response<proto::RemoveMemberResponse>, Status> {
        Err(Status::unimplemented("RemoveMember — Phase 3"))
    }

    // ── Admin ─────────────────────────────────────────────────────────────

    async fn delegate_admin(
        &self,
        _request: Request<proto::DelegateAdminRequest>,
    ) -> Result<Response<proto::DelegateAdminResponse>, Status> {
        Err(Status::unimplemented("DelegateAdmin — Phase 4"))
    }

    // ── MLS Sync ──────────────────────────────────────────────────────────

    async fn submit_commit(
        &self,
        _request: Request<proto::SubmitCommitRequest>,
    ) -> Result<Response<proto::SubmitCommitResponse>, Status> {
        Err(Status::unimplemented("SubmitCommit — Phase 4"))
    }

    type FetchCommitsStream = tonic::codegen::BoxStream<proto::CommitEnvelope>;

    async fn fetch_commits(
        &self,
        _request: Request<proto::FetchCommitsRequest>,
    ) -> Result<Response<Self::FetchCommitsStream>, Status> {
        Err(Status::unimplemented("FetchCommits — Phase 4"))
    }

    // ── Messaging ─────────────────────────────────────────────────────────

    async fn send_group_message(
        &self,
        _request: Request<proto::SendGroupMessageRequest>,
    ) -> Result<Response<proto::SendGroupMessageResponse>, Status> {
        Err(Status::unimplemented("SendGroupMessage — Phase 5"))
    }

    type FetchGroupMessagesStream = tonic::codegen::BoxStream<proto::GroupMessageEnvelope>;

    async fn fetch_group_messages(
        &self,
        _request: Request<proto::FetchGroupMessagesRequest>,
    ) -> Result<Response<Self::FetchGroupMessagesStream>, Status> {
        Err(Status::unimplemented("FetchGroupMessages — Phase 5"))
    }

    type MessageStreamStream = tonic::codegen::BoxStream<proto::GroupStreamResponse>;

    async fn message_stream(
        &self,
        _request: Request<tonic::Streaming<proto::GroupStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        Err(Status::unimplemented("MessageStream — Phase 5"))
    }

    // ── KeyPackages ───────────────────────────────────────────────────────

    async fn publish_key_package(
        &self,
        request: Request<proto::PublishKeyPackageRequest>,
    ) -> Result<Response<proto::PublishKeyPackageResponse>, Status> {
        let user_id = extract_user_id(request.metadata())?;
        let req = request.into_inner();

        let device_id = req.device_id;
        if device_id.is_empty() {
            return Err(Status::invalid_argument("device_id is required"));
        }
        if req.key_packages.is_empty() {
            return Err(Status::invalid_argument(
                "at least one key_package required",
            ));
        }

        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::days(30);

        // Bulk insert — each KeyPackage is single-use (like one-time pre-keys)
        for kp in &req.key_packages {
            let kp_ref = sha256_bytes(kp);
            sqlx::query(
                r#"
                INSERT INTO group_key_packages
                    (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (key_package_ref) DO NOTHING
                "#,
            )
            .bind(user_id)
            .bind(&device_id)
            .bind(kp.as_slice())
            .bind(kp_ref.as_slice())
            .bind(now)
            .bind(expires_at)
            .execute(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        }

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM group_key_packages
            WHERE device_id = $1
              AND expires_at > NOW()
            "#,
        )
        .bind(&device_id)
        .fetch_one(self.db.as_ref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        info!(
            device_id = %device_id,
            user_id = %user_id,
            published = req.key_packages.len(),
            total = count,
            "KeyPackages published"
        );

        Ok(Response::new(proto::PublishKeyPackageResponse {
            count: count as u32,
            published_at: now.timestamp(),
        }))
    }

    async fn consume_key_package(
        &self,
        request: Request<proto::ConsumeKeyPackageRequest>,
    ) -> Result<Response<proto::ConsumeKeyPackageResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        // Atomic consume: DELETE ... RETURNING (single-use guarantee)
        let row: Option<(Vec<u8>, String, Vec<u8>)> =
            if let Some(ref preferred) = req.preferred_device_id {
                // Prefer a specific device if requested
                sqlx::query_as(
                    r#"
                DELETE FROM group_key_packages
                WHERE id = (
                    SELECT id FROM group_key_packages
                    WHERE user_id = $1
                      AND device_id = $2
                      AND expires_at > NOW()
                    ORDER BY published_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING key_package, device_id, key_package_ref
                "#,
                )
                .bind(user_id)
                .bind(preferred)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            } else {
                sqlx::query_as(
                    r#"
                DELETE FROM group_key_packages
                WHERE id = (
                    SELECT id FROM group_key_packages
                    WHERE user_id = $1
                      AND expires_at > NOW()
                    ORDER BY published_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING key_package, device_id, key_package_ref
                "#,
                )
                .bind(user_id)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            };

        match row {
            None => Err(Status::not_found(
                "no KeyPackage available for this user; they must publish more",
            )),
            Some((key_package, device_id, key_package_ref)) => {
                info!(
                    target_user_id = %user_id,
                    device_id = %device_id,
                    "KeyPackage consumed"
                );
                Ok(Response::new(proto::ConsumeKeyPackageResponse {
                    key_package,
                    device_id,
                    key_package_ref,
                }))
            }
        }
    }

    async fn get_key_package_count(
        &self,
        request: Request<proto::GetKeyPackageCountRequest>,
    ) -> Result<Response<proto::GetKeyPackageCountResponse>, Status> {
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let (count, last_published_at): (i64, Option<chrono::DateTime<chrono::Utc>>) =
            if let Some(ref device_id) = req.device_id {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*), MAX(published_at)
                    FROM group_key_packages
                    WHERE user_id = $1
                      AND device_id = $2
                      AND expires_at > NOW()
                    "#,
                )
                .bind(user_id)
                .bind(device_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            } else {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*), MAX(published_at)
                    FROM group_key_packages
                    WHERE user_id = $1
                      AND expires_at > NOW()
                    "#,
                )
                .bind(user_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            };

        Ok(Response::new(proto::GetKeyPackageCountResponse {
            count: count as u32,
            recommended_minimum: 20,
            last_published_at: last_published_at.map(|t| t.timestamp()).unwrap_or(0),
            cannot_be_invited: count == 0,
        }))
    }

    // ── Topics ────────────────────────────────────────────────────────────

    async fn create_topic(
        &self,
        _request: Request<proto::CreateTopicRequest>,
    ) -> Result<Response<proto::CreateTopicResponse>, Status> {
        Err(Status::unimplemented("CreateTopic — Phase 6"))
    }

    async fn list_topics(
        &self,
        _request: Request<proto::ListTopicsRequest>,
    ) -> Result<Response<proto::ListTopicsResponse>, Status> {
        Err(Status::unimplemented("ListTopics — Phase 6"))
    }

    async fn archive_topic(
        &self,
        _request: Request<proto::ArchiveTopicRequest>,
    ) -> Result<Response<proto::ArchiveTopicResponse>, Status> {
        Err(Status::unimplemented("ArchiveTopic — Phase 6"))
    }

    // ── Invite Links ──────────────────────────────────────────────────────

    async fn create_invite_link(
        &self,
        _request: Request<proto::CreateInviteLinkRequest>,
    ) -> Result<Response<proto::CreateInviteLinkResponse>, Status> {
        Err(Status::unimplemented("CreateInviteLink — Phase 6"))
    }

    async fn revoke_invite_link(
        &self,
        _request: Request<proto::RevokeInviteLinkRequest>,
    ) -> Result<Response<proto::RevokeInviteLinkResponse>, Status> {
        Err(Status::unimplemented("RevokeInviteLink — Phase 6"))
    }

    async fn resolve_invite_link(
        &self,
        _request: Request<proto::ResolveInviteLinkRequest>,
    ) -> Result<Response<proto::ResolveInviteLinkResponse>, Status> {
        Err(Status::unimplemented("ResolveInviteLink — Phase 6"))
    }
}

// ============================================================================
// SHA-256 helper (KeyPackage ref)
// ============================================================================

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mls_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db = sqlx::PgPool::connect(&database_url).await?;

    // Run pending migrations on startup
    sqlx::migrate!("../shared/migrations").run(&db).await?;

    let db = Arc::new(db);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "50058".to_string())
        .parse()?;
    let grpc_bind_addr = format!("0.0.0.0:{}", port);
    let grpc_incoming = construct_server_shared::mptcp_incoming(&grpc_bind_addr).await?;

    info!("MLSService listening on {}", grpc_bind_addr);

    // Small HTTP server for /health and /metrics
    let http_port: u16 = std::env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8097".into())
        .parse()?;
    let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port).parse()?;
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route(
                "/metrics",
                axum::routing::get(construct_server_shared::metrics::metrics_handler),
            );
        let listener = construct_server_shared::mptcp_or_tcp_listener(&http_addr.to_string())
            .await
            .unwrap();
        info!("MLSService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    Server::builder()
        .add_service(MlsServiceServer::new(MlsServiceImpl { db }))
        .serve_with_incoming_shutdown(grpc_incoming, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    /// Create a test database connection pool
    async fn get_test_db() -> Arc<sqlx::PgPool> {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        Arc::new(
            sqlx::PgPool::connect(&db_url)
                .await
                .expect("Failed to connect"),
        )
    }

    /// Create a test user and device with Ed25519 keypair
    async fn create_test_device(db: &sqlx::PgPool) -> (Uuid, String, SigningKey) {
        let user_id = Uuid::new_v4();
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Insert user
        sqlx::query(
            "INSERT INTO users (id, username, created_at) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
        )
        .bind(user_id)
        .bind(format!("test_{}", user_id.simple()))
        .bind(Utc::now())
        .execute(db)
        .await
        .expect("Failed to insert test user");

        // Generate device_id: SHA256 of verifying_key, first 16 bytes
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.as_bytes());
        let hash = hasher.finalize();
        let device_id = hex::encode(&hash[..16]);

        // Insert device
        sqlx::query(
            r#"
            INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                                 identity_public, signed_prekey_public, registered_at)
            VALUES ($1, $2, 'test.local', $3, $4, $5, $6)
            ON CONFLICT (device_id) DO UPDATE SET user_id = EXCLUDED.user_id
            "#,
        )
        .bind(&device_id)
        .bind(user_id)
        .bind(verifying_key.as_bytes().to_vec())
        .bind(vec![0u8; 32])
        .bind(vec![0u8; 32])
        .bind(Utc::now())
        .execute(db)
        .await
        .expect("Failed to insert test device");

        (user_id, device_id, signing_key)
    }

    /// Create a test group directly in DB
    async fn create_test_group_in_db(db: &sqlx::PgPool, device_id: &str) -> Uuid {
        let group_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO mls_groups
                (group_id, epoch, ratchet_tree, encrypted_group_context,
                 max_members, message_retention_days, threads_enabled, created_at)
            VALUES ($1, 0, $2, $3, 2048, 90, false, $4)
            "#,
        )
        .bind(group_id)
        .bind(vec![0u8; 32])
        .bind(vec![0u8; 32])
        .bind(now)
        .execute(db)
        .await
        .expect("Failed to insert test group");

        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 0, $3)",
        )
        .bind(group_id)
        .bind(device_id)
        .bind(now)
        .execute(db)
        .await
        .expect("Failed to add creator to group");

        sqlx::query(
            "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, true, $3)",
        )
        .bind(group_id)
        .bind(device_id)
        .bind(now)
        .execute(db)
        .await
        .expect("Failed to add creator as admin");

        group_id
    }

    fn create_metadata(user_id: &Uuid, device_id: &str) -> tonic::metadata::MetadataMap {
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("x-user-id", user_id.to_string().parse().unwrap());
        meta.insert("x-device-id", device_id.parse().unwrap());
        meta
    }

    // ── CreateGroup ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_group_success() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let service = MlsServiceImpl { db: db.clone() };

        let group_id = Uuid::new_v4();
        let meta = create_metadata(&user_id, &device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::CreateGroupRequest {
                group_id: group_id.to_string(),
                initial_ratchet_tree: vec![1, 2, 3, 4],
                encrypted_group_context: vec![5, 6, 7, 8],
                max_members: 100,
                message_retention_days: 30,
                threads_enabled: true,
            },
        );

        let response = service
            .create_group(request)
            .await
            .expect("CreateGroup should succeed");
        let inner = response.into_inner();

        assert_eq!(inner.group_id, group_id.to_string());
        assert_eq!(inner.epoch, 0);
        assert!(inner.created_at > 0);
    }

    #[tokio::test]
    async fn test_create_group_invalid_group_id() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::CreateGroupRequest {
                group_id: "not-a-uuid".to_string(),
                initial_ratchet_tree: vec![1, 2, 3],
                encrypted_group_context: vec![4, 5, 6],
                max_members: 100,
                message_retention_days: 90,
                threads_enabled: false,
            },
        );

        let result = service.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_create_group_empty_ratchet_tree() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::CreateGroupRequest {
                group_id: Uuid::new_v4().to_string(),
                initial_ratchet_tree: vec![],
                encrypted_group_context: vec![4, 5, 6],
                max_members: 100,
                message_retention_days: 90,
                threads_enabled: false,
            },
        );

        let result = service.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_create_group_max_members_exceeded() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::CreateGroupRequest {
                group_id: Uuid::new_v4().to_string(),
                initial_ratchet_tree: vec![1, 2, 3],
                encrypted_group_context: vec![4, 5, 6],
                max_members: 2049,
                message_retention_days: 90,
                threads_enabled: false,
            },
        );

        let result = service.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_create_group_missing_user_id() {
        let db = get_test_db().await;
        let (_, device_id, _) = create_test_device(&db).await;
        let service = MlsServiceImpl { db };

        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("x-device-id", device_id.parse().unwrap());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::CreateGroupRequest {
                group_id: Uuid::new_v4().to_string(),
                initial_ratchet_tree: vec![1, 2, 3],
                encrypted_group_context: vec![4, 5, 6],
                max_members: 100,
                message_retention_days: 90,
                threads_enabled: false,
            },
        );

        let result = service.create_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    // ── GetGroupState ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_group_state_success() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &device_id).await;
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetGroupStateRequest {
                group_id: group_id.to_string(),
                known_epoch: None,
            },
        );

        let response = service
            .get_group_state(request)
            .await
            .expect("GetGroupState should succeed");
        let inner = response.into_inner();

        assert_eq!(inner.epoch, 0);
        assert!(inner.ratchet_tree.is_some());
        assert!(inner.settings.is_some());
        assert_eq!(inner.settings.as_ref().unwrap().member_count, 1);
    }

    #[tokio::test]
    async fn test_get_group_state_non_member() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let group_id = Uuid::new_v4();
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetGroupStateRequest {
                group_id: group_id.to_string(),
                known_epoch: None,
            },
        );

        let result = service.get_group_state(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }

    // ── DissolveGroup ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_dissolve_group_success() {
        let db = get_test_db().await;
        let (user_id, device_id, signing_key) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &device_id).await;
        let service = MlsServiceImpl { db: db.clone() };

        let meta = create_metadata(&user_id, &device_id);

        let timestamp = Utc::now().timestamp();
        let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DissolveGroupRequest {
                group_id: group_id.to_string(),
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
            },
        );

        let response = service
            .dissolve_group(request)
            .await
            .expect("DissolveGroup should succeed");
        let inner = response.into_inner();

        assert!(inner.success);
        assert!(inner.dissolved_at > 0);

        let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_optional(db.as_ref())
                .await
                .expect("Failed to query")
                .flatten();

        assert!(dissolved_at.is_some());
    }

    #[tokio::test]
    async fn test_dissolve_group_invalid_signature() {
        let db = get_test_db().await;
        let (user_id, device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &device_id).await;
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let wrong_signing_key = SigningKey::generate(&mut OsRng);
        let timestamp = Utc::now().timestamp();
        let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
        let signature = wrong_signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DissolveGroupRequest {
                group_id: group_id.to_string(),
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
            },
        );

        let result = service.dissolve_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn test_dissolve_group_expired_timestamp() {
        let db = get_test_db().await;
        let (user_id, device_id, signing_key) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &device_id).await;
        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let timestamp = Utc::now().timestamp() - 600; // 10 minutes ago
        let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DissolveGroupRequest {
                group_id: group_id.to_string(),
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
            },
        );

        let result = service.dissolve_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_dissolve_group_non_admin() {
        let db = get_test_db().await;
        let (user_id, device_id, signing_key) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &device_id).await;

        let (_user_id2, device_id2, _) = create_test_device(&db).await;

        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
        )
        .bind(group_id)
        .bind(&device_id2)
        .bind(Utc::now())
        .execute(db.as_ref())
        .await
        .expect("Failed to add device2 to group");

        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id2);

        let timestamp = Utc::now().timestamp();
        let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DissolveGroupRequest {
                group_id: group_id.to_string(),
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
            },
        );

        let result = service.dissolve_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn test_dissolve_group_already_dissolved() {
        let db = get_test_db().await;
        let (user_id, device_id, signing_key) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &device_id).await;

        sqlx::query("UPDATE mls_groups SET dissolved_at = NOW() WHERE group_id = $1")
            .bind(group_id)
            .execute(db.as_ref())
            .await
            .expect("Failed to dissolve group");

        let service = MlsServiceImpl { db };

        let meta = create_metadata(&user_id, &device_id);

        let timestamp = Utc::now().timestamp();
        let message = format!("CONSTRUCT_DISSOLVE_GROUP:{}:{}", group_id, timestamp);
        let signature = signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DissolveGroupRequest {
                group_id: group_id.to_string(),
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
            },
        );

        let result = service.dissolve_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
    }
}
