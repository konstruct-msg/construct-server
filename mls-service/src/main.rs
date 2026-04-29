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
        request: Request<proto::InviteToGroupRequest>,
    ) -> Result<Response<proto::InviteToGroupResponse>, Status> {
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

        // 3. Check group not dissolved
        let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?
                .flatten();

        if dissolved_at.is_some() {
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
        let consumed: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT device_id, user_id::text FROM group_key_packages
            WHERE key_package_ref = $1 AND expires_at > NOW()
            "#,
        )
        .bind(&req.key_package_ref)
        .fetch_optional(self.db.as_ref())
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        let (target_device_id, _target_user_id) = consumed.ok_or_else(|| {
            Status::not_found(
                "KeyPackage not found or expired; target must publish a KeyPackage first",
            )
        })?;

        // 8. Check if device is already a member
        let already_member =
            check_group_member(self.db.as_ref(), group_id, &target_device_id).await?;

        if already_member {
            return Err(Status::already_exists(
                "Device is already a member of this group",
            ));
        }

        // 9. Check max_members limit
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        let max_members: i16 =
            sqlx::query_scalar("SELECT max_members FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        if member_count >= max_members as i64 {
            return Err(Status::resource_exhausted(
                "GROUP_FULL: max_members reached",
            ));
        }

        // 10. Check if there's already a pending invite for this device
        let existing_invite: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM group_invites
                WHERE group_id = $1 AND target_device_id = $2 AND expires_at > NOW()
            )
            "#,
        )
        .bind(group_id)
        .bind(&target_device_id)
        .fetch_one(self.db.as_ref())
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        if existing_invite {
            return Err(Status::already_exists(
                "Device already has a pending invite for this group",
            ));
        }

        // 11. Insert invite
        let invite_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::seconds(expires_in_seconds as i64);

        sqlx::query(
            r#"
            INSERT INTO group_invites
                (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                 epoch, invited_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .bind(&target_device_id)
        .bind(&req.mls_welcome)
        .bind(&req.key_package_ref)
        .bind(req.epoch as i64)
        .bind(now)
        .bind(expires_at)
        .execute(self.db.as_ref())
        .await
        .map_err(|e| {
            if e.to_string().contains("group_invites_unique_pending") {
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

    async fn accept_group_invite(
        &self,
        request: Request<proto::AcceptGroupInviteRequest>,
    ) -> Result<Response<proto::AcceptGroupInviteResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let user_id = extract_user_id(request.metadata())?;
        let req = request.into_inner();

        // 1. Parse group_id and invite_id
        let group_id = Uuid::parse_str(&req.group_id)
            .map_err(|_| Status::invalid_argument("Invalid group_id"))?;
        let invite_id = Uuid::parse_str(&req.invite_id)
            .map_err(|_| Status::invalid_argument("Invalid invite_id"))?;

        // 2. Fetch invite
        let invite_row: Option<(String, String, Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
            r#"
            SELECT invite_id::text, target_device_id, mls_welcome, key_package_ref, epoch
            FROM group_invites
            WHERE invite_id = $1 AND group_id = $2 AND expires_at > NOW()
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .fetch_optional(self.db.as_ref())
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        let (_invite_id_str, target_device_id, _mls_welcome, _key_package_ref, _epoch) =
            invite_row.ok_or_else(|| Status::not_found("Invite not found or expired"))?;

        // 3. Verify invite belongs to the calling device
        if target_device_id != device_id {
            return Err(Status::permission_denied(
                "Invite belongs to a different device",
            ));
        }

        // 4. Validate acceptance signature
        let signature_timestamp = req.signature_timestamp;

        // Message: "CONSTRUCT_GROUP_JOIN:{group_id}:{invite_id}:{timestamp}"
        let message = format!(
            "CONSTRUCT_GROUP_JOIN:{}:{}:{}",
            req.group_id, req.invite_id, signature_timestamp
        );

        verify_admin_proof(
            self.db.as_ref(),
            &device_id,
            "CONSTRUCT_GROUP_JOIN",
            &req.acceptance_signature,
            signature_timestamp,
            &message,
        )
        .await?;

        // 5. Verify device belongs to user
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

        // 6. Check if already a member
        let already_member = check_group_member(self.db.as_ref(), group_id, &device_id).await?;

        if already_member {
            return Err(Status::already_exists("Already a member of this group"));
        }

        // 7. Get next leaf_index
        let max_leaf_index: Option<i32> =
            sqlx::query_scalar("SELECT MAX(leaf_index) FROM group_members WHERE group_id = $1")
                .bind(group_id)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        let next_leaf_index = max_leaf_index.map(|v| v + 1).unwrap_or(0);

        // 8. Insert into group_members with acceptance signature
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO group_members
                (group_id, device_id, leaf_index, acceptance_signature, joined_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(group_id)
        .bind(&device_id)
        .bind(next_leaf_index)
        .bind(&req.acceptance_signature)
        .bind(now)
        .execute(self.db.as_ref())
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                Status::already_exists("Device is already a member of this group")
            } else {
                Status::internal(format!("Failed to add member: {}", e))
            }
        })?;

        // 9. Delete invite (hard delete — no history)
        sqlx::query("DELETE FROM group_invites WHERE invite_id = $1")
            .bind(invite_id)
            .execute(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("Failed to delete invite: {}", e)))?;

        // 10. Get current epoch
        let current_epoch: i64 =
            sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

        info!(
            group_id = %group_id,
            device_id = %device_id,
            user_id = %user_id,
            leaf_index = next_leaf_index,
            epoch = current_epoch,
            "Group invite accepted"
        );

        Ok(Response::new(proto::AcceptGroupInviteResponse {
            success: true,
            new_epoch: current_epoch as u64,
            joined_at: now.timestamp(),
        }))
    }

    async fn decline_group_invite(
        &self,
        request: Request<proto::DeclineGroupInviteRequest>,
    ) -> Result<Response<proto::DeclineGroupInviteResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let req = request.into_inner();

        // 1. Parse group_id and invite_id
        let group_id = Uuid::parse_str(&req.group_id)
            .map_err(|_| Status::invalid_argument("Invalid group_id"))?;
        let invite_id = Uuid::parse_str(&req.invite_id)
            .map_err(|_| Status::invalid_argument("Invalid invite_id"))?;

        // 2. Fetch invite and verify it belongs to the calling device
        let target_device_id: Option<String> = sqlx::query_scalar(
            "SELECT target_device_id FROM group_invites WHERE invite_id = $1 AND group_id = $2",
        )
        .bind(invite_id)
        .bind(group_id)
        .fetch_optional(self.db.as_ref())
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

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
        sqlx::query("DELETE FROM group_invites WHERE invite_id = $1")
            .bind(invite_id)
            .execute(self.db.as_ref())
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

    async fn get_pending_invites(
        &self,
        request: Request<proto::GetPendingInvitesRequest>,
    ) -> Result<Response<proto::GetPendingInvitesResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let req = request.into_inner();

        // Use device_id from request if provided, otherwise from metadata
        let target_device_id = if req.device_id.is_empty() {
            device_id
        } else {
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
        let invites: Vec<(
            Uuid,
            Uuid,
            Vec<u8>,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        )> = if let Some(cursor_id) = cursor {
            let cursor_uuid = Uuid::parse_str(cursor_id)
                .map_err(|_| Status::invalid_argument("Invalid cursor"))?;

            sqlx::query_as(
                r#"
                    SELECT invite_id, group_id, mls_welcome, expires_at, invited_at
                    FROM group_invites
                    WHERE target_device_id = $1
                      AND expires_at > NOW()
                      AND invite_id > $2
                    ORDER BY invite_id ASC
                    LIMIT $3
                    "#,
            )
            .bind(&target_device_id)
            .bind(cursor_uuid)
            .bind(limit as i64)
            .fetch_all(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        } else {
            sqlx::query_as(
                r#"
                    SELECT invite_id, group_id, mls_welcome, expires_at, invited_at
                    FROM group_invites
                    WHERE target_device_id = $1
                      AND expires_at > NOW()
                    ORDER BY invite_id ASC
                    LIMIT $2
                    "#,
            )
            .bind(&target_device_id)
            .bind(limit as i64)
            .fetch_all(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        };

        // 3. Build next_cursor
        let next_cursor = if invites.len() == limit as usize {
            invites.last().map(|(id, _, _, _, _)| id.to_string())
        } else {
            None
        };

        // 4. Convert to proto
        let proto_invites: Vec<proto::PendingGroupInvite> = invites
            .into_iter()
            .map(
                |(invite_id, group_id, mls_welcome, expires_at, invited_at)| {
                    proto::PendingGroupInvite {
                        invite_id: invite_id.to_string(),
                        group_id: group_id.to_string(),
                        mls_welcome,
                        expires_at: expires_at.timestamp(),
                        invited_at: invited_at.timestamp(),
                    }
                },
            )
            .collect();

        Ok(Response::new(proto::GetPendingInvitesResponse {
            invites: proto_invites,
            next_cursor,
        }))
    }

    async fn leave_group(
        &self,
        request: Request<proto::LeaveGroupRequest>,
    ) -> Result<Response<proto::LeaveGroupResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let req = request.into_inner();

        // 1. Parse group_id
        let group_id = Uuid::parse_str(&req.group_id)
            .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

        // 2. Check group not dissolved
        let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?
                .flatten();

        if dissolved_at.is_some() {
            return Err(Status::not_found("Group dissolved"));
        }

        // 3. Verify membership
        let is_member = check_group_member(self.db.as_ref(), group_id, &device_id).await?;
        if !is_member {
            return Err(Status::permission_denied("NOT_MEMBER"));
        }

        // 4. Check if member is creator (creator cannot leave — they must dissolve)
        let (is_creator, _) = check_group_admin(self.db.as_ref(), group_id, &device_id).await?;
        if is_creator {
            return Err(Status::failed_precondition(
                "Creator cannot leave group; use DissolveGroup instead",
            ));
        }

        // 5. Hard delete from group_members (no history)
        let now = chrono::Utc::now();

        sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND device_id = $2")
            .bind(group_id)
            .bind(&device_id)
            .execute(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("Failed to remove member: {}", e)))?;

        // 6. Also remove from group_admins if present
        sqlx::query("DELETE FROM group_admins WHERE group_id = $1 AND device_id = $2")
            .bind(group_id)
            .bind(&device_id)
            .execute(self.db.as_ref())
            .await
            .ok(); // Ignore if not admin

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

    async fn remove_member(
        &self,
        request: Request<proto::RemoveMemberRequest>,
    ) -> Result<Response<proto::RemoveMemberResponse>, Status> {
        let device_id = extract_device_id(request.metadata())?;
        let req = request.into_inner();

        // 1. Parse group_id
        let group_id = Uuid::parse_str(&req.group_id)
            .map_err(|_| Status::invalid_argument("Invalid group_id"))?;

        // 2. Verify caller is admin
        let (is_creator, is_admin) =
            check_group_admin(self.db.as_ref(), group_id, &device_id).await?;

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
            self.db.as_ref(),
            &device_id,
            "CONSTRUCT_REMOVE_MEMBER",
            &req.admin_proof,
            signature_timestamp,
            &message,
        )
        .await?;

        // 4. Check group not dissolved
        let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_optional(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?
                .flatten();

        if dissolved_at.is_some() {
            return Err(Status::not_found("Group dissolved"));
        }

        // 5. Verify target is a member
        let target_is_member =
            check_group_member(self.db.as_ref(), group_id, &req.target_device_id).await?;

        if !target_is_member {
            return Err(Status::not_found("Target is not a member of this group"));
        }

        // 6. Cannot remove creator
        let (target_is_creator, _) =
            check_group_admin(self.db.as_ref(), group_id, &req.target_device_id).await?;

        if target_is_creator {
            return Err(Status::failed_precondition("Cannot remove group creator"));
        }

        // 7. Hard delete from group_members
        let now = chrono::Utc::now();

        sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND device_id = $2")
            .bind(group_id)
            .bind(&req.target_device_id)
            .execute(self.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("Failed to remove member: {}", e)))?;

        // 8. Also remove from group_admins
        sqlx::query("DELETE FROM group_admins WHERE group_id = $1 AND device_id = $2")
            .bind(group_id)
            .bind(&req.target_device_id)
            .execute(self.db.as_ref())
            .await
            .ok();

        // 9. Get current epoch
        let current_epoch: i64 =
            sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE group_id = $1")
                .bind(group_id)
                .fetch_one(self.db.as_ref())
                .await
                .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

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

    // ── Admin ─────────────────────────────────────────────────────────────

    async fn delegate_admin(
        &self,
        _request: Request<proto::DelegateAdminRequest>,
    ) -> Result<Response<proto::DelegateAdminResponse>, Status> {
        Err(Status::unimplemented("DelegateAdmin — Phase 4"))
    }

    async fn transfer_ownership(
        &self,
        _request: Request<proto::TransferOwnershipRequest>,
    ) -> Result<Response<proto::TransferOwnershipResponse>, Status> {
        Err(Status::unimplemented("TransferOwnership — Phase 4"))
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

    // ═══════════════════════════════════════════════════════════════════
    // Phase 3: Membership Management Tests
    // ═══════════════════════════════════════════════════════════════════

    /// Helper: publish a KeyPackage for a device and return key_package_ref
    async fn publish_test_key_package(
        db: &sqlx::PgPool,
        user_id: Uuid,
        device_id: &str,
    ) -> Vec<u8> {
        let kp = vec![1u8, 2, 3, 4, 5]; // dummy key package
        let kp_ref = sha256_bytes(&kp);
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO group_key_packages
                (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(user_id)
        .bind(device_id)
        .bind(&kp)
        .bind(&kp_ref)
        .bind(now)
        .bind(now + chrono::Duration::days(30))
        .execute(db)
        .await
        .expect("Failed to publish test KeyPackage");

        kp_ref
    }

    // ── InviteToGroup ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_invite_to_group_success() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create invitee
        let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
        let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

        let service = MlsServiceImpl { db };
        let meta = create_metadata(&invitee_user_id, &admin_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::InviteToGroupRequest {
                group_id: group_id.to_string(),
                mls_welcome: vec![10, 20, 30],
                key_package_ref: kp_ref,
                epoch: 0,
                expires_in_seconds: 3600, // 1 hour
            },
        );

        let response = service
            .invite_to_group(request)
            .await
            .expect("InviteToGroup should succeed");
        let inner = response.into_inner();

        assert!(!inner.invite_id.is_empty());
        assert!(inner.expires_at > 0);
    }

    #[tokio::test]
    async fn test_invite_to_group_non_admin() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create non-admin member
        let (member_user_id, member_device_id, _) = create_test_device(&db).await;
        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
        )
        .bind(group_id)
        .bind(&member_device_id)
        .bind(Utc::now())
        .execute(db.as_ref())
        .await
        .expect("Failed to add member");

        let kp_ref = publish_test_key_package(&db, member_user_id, &member_device_id).await;

        let service = MlsServiceImpl { db };
        let meta = create_metadata(&member_user_id, &member_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::InviteToGroupRequest {
                group_id: group_id.to_string(),
                mls_welcome: vec![10, 20, 30],
                key_package_ref: kp_ref,
                epoch: 0,
                expires_in_seconds: 3600,
            },
        );

        let result = service.invite_to_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ── AcceptGroupInvite ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_accept_group_invite_success() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create invitee
        let (invitee_user_id, invitee_device_id, invitee_signing_key) =
            create_test_device(&db).await;
        let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

        // Create invite directly in DB
        let invite_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO group_invites
                (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                 epoch, invited_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .bind(&invitee_device_id)
        .bind(vec![10, 20, 30])
        .bind(&kp_ref)
        .bind(now)
        .bind(now + chrono::Duration::hours(1))
        .execute(db.as_ref())
        .await
        .expect("Failed to create invite");

        // Sign acceptance
        let timestamp = Utc::now().timestamp();
        let message = format!(
            "CONSTRUCT_GROUP_JOIN:{}:{}:{}",
            group_id, invite_id, timestamp
        );
        let signature = invitee_signing_key.sign(message.as_bytes());

        let service = MlsServiceImpl { db };
        let meta = create_metadata(&invitee_user_id, &invitee_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::AcceptGroupInviteRequest {
                group_id: group_id.to_string(),
                invite_id: invite_id.to_string(),
                acceptance_signature: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
                mls_commit: vec![],
                new_ratchet_tree: vec![],
            },
        );

        let response = service
            .accept_group_invite(request)
            .await
            .expect("AcceptGroupInvite should succeed");
        let inner = response.into_inner();

        assert!(inner.success);
        assert!(inner.joined_at > 0);
    }

    #[tokio::test]
    async fn test_accept_group_invite_wrong_device() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create invitee
        let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
        let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

        // Create a second device (wrong one)
        let (_, wrong_device_id, wrong_signing_key) = create_test_device(&db).await;

        // Create invite for invitee_device_id
        let invite_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO group_invites
                (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                 epoch, invited_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .bind(&invitee_device_id) // invite is for invitee
        .bind(vec![10, 20, 30])
        .bind(&kp_ref)
        .bind(now)
        .bind(now + chrono::Duration::hours(1))
        .execute(db.as_ref())
        .await
        .expect("Failed to create invite");

        // Sign with wrong key
        let timestamp = Utc::now().timestamp();
        let message = format!(
            "CONSTRUCT_GROUP_JOIN:{}:{}:{}",
            group_id, invite_id, timestamp
        );
        let signature = wrong_signing_key.sign(message.as_bytes());

        let service = MlsServiceImpl { db };
        // Use wrong_device_id in metadata
        let meta = create_metadata(&invitee_user_id, &wrong_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::AcceptGroupInviteRequest {
                group_id: group_id.to_string(),
                invite_id: invite_id.to_string(),
                acceptance_signature: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
                mls_commit: vec![],
                new_ratchet_tree: vec![],
            },
        );

        let result = service.accept_group_invite(request).await;
        assert!(result.is_err());
        // Should fail because wrong_device_id is not the invitee
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ── DeclineGroupInvite ────────────────────────────────────────────

    #[tokio::test]
    async fn test_decline_group_invite_success() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create invitee
        let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
        let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

        // Create invite
        let invite_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO group_invites
                (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                 epoch, invited_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .bind(&invitee_device_id)
        .bind(vec![10, 20, 30])
        .bind(&kp_ref)
        .bind(now)
        .bind(now + chrono::Duration::hours(1))
        .execute(db.as_ref())
        .await
        .expect("Failed to create invite");

        let service = MlsServiceImpl { db: db.clone() };
        let meta = create_metadata(&invitee_user_id, &invitee_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DeclineGroupInviteRequest {
                group_id: group_id.to_string(),
                invite_id: invite_id.to_string(),
            },
        );

        let response = service
            .decline_group_invite(request)
            .await
            .expect("DeclineGroupInvite should succeed");
        assert!(response.into_inner().success);

        // Verify invite is deleted
        let invite_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM group_invites WHERE invite_id = $1)")
                .bind(invite_id)
                .fetch_optional(db.as_ref())
                .await
                .expect("Failed to query")
                .flatten()
                .unwrap_or(false);

        assert!(!invite_exists);
    }

    #[tokio::test]
    async fn test_decline_group_invite_wrong_device() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create invitee
        let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
        let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

        // Create a different device
        let (other_user_id, other_device_id, _) = create_test_device(&db).await;

        // Create invite for invitee
        let invite_id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO group_invites
                (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                 epoch, invited_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
            "#,
        )
        .bind(invite_id)
        .bind(group_id)
        .bind(&invitee_device_id) // invite for invitee
        .bind(vec![10, 20, 30])
        .bind(&kp_ref)
        .bind(now)
        .bind(now + chrono::Duration::hours(1))
        .execute(db.as_ref())
        .await
        .expect("Failed to create invite");

        let service = MlsServiceImpl { db };
        // Use other device to decline
        let meta = create_metadata(&other_user_id, &other_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::DeclineGroupInviteRequest {
                group_id: group_id.to_string(),
                invite_id: invite_id.to_string(),
            },
        );

        let result = service.decline_group_invite(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    // ── GetPendingInvites ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_pending_invites_success() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create invitee
        let (invitee_user_id, invitee_device_id, _) = create_test_device(&db).await;
        let kp_ref = publish_test_key_package(&db, invitee_user_id, &invitee_device_id).await;

        // Create 3 invites
        for i in 0..3 {
            let invite_id = Uuid::new_v4();
            let now = Utc::now() + chrono::Duration::seconds(i);

            sqlx::query(
                r#"
                INSERT INTO group_invites
                    (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
                     epoch, invited_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
                "#,
            )
            .bind(invite_id)
            .bind(group_id)
            .bind(&invitee_device_id)
            .bind(vec![10, 20, 30])
            .bind(&kp_ref)
            .bind(now)
            .bind(now + chrono::Duration::hours(1))
            .execute(db.as_ref())
            .await
            .expect("Failed to create invite");
        }

        let service = MlsServiceImpl { db };
        let meta = create_metadata(&invitee_user_id, &invitee_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::GetPendingInvitesRequest {
                device_id: "".to_string(), // empty = use from metadata
                cursor: None,
                limit: 50,
            },
        );

        let response = service
            .get_pending_invites(request)
            .await
            .expect("GetPendingInvites should succeed");
        let inner = response.into_inner();

        assert_eq!(inner.invites.len(), 3);
        assert!(inner.next_cursor.is_none());
    }

    // ── LeaveGroup ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_leave_group_success() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create a regular member
        let (member_user_id, member_device_id, _) = create_test_device(&db).await;
        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
        )
        .bind(group_id)
        .bind(&member_device_id)
        .bind(Utc::now())
        .execute(db.as_ref())
        .await
        .expect("Failed to add member");

        let service = MlsServiceImpl { db: db.clone() };
        let meta = create_metadata(&member_user_id, &member_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::LeaveGroupRequest {
                group_id: group_id.to_string(),
                mls_remove_proposal: vec![],
            },
        );

        let response = service
            .leave_group(request)
            .await
            .expect("LeaveGroup should succeed");
        assert!(response.into_inner().success);

        // Verify member is removed
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2)",
        )
        .bind(group_id)
        .bind(&member_device_id)
        .fetch_optional(db.as_ref())
        .await
        .expect("Failed to query")
        .flatten()
        .unwrap_or(false);

        assert!(!is_member);
    }

    #[tokio::test]
    async fn test_leave_group_creator_cannot_leave() {
        let db = get_test_db().await;
        let (admin_user_id, admin_device_id, _) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        let service = MlsServiceImpl { db };
        let meta = create_metadata(&admin_user_id, &admin_device_id);

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::LeaveGroupRequest {
                group_id: group_id.to_string(),
                mls_remove_proposal: vec![],
            },
        );

        let result = service.leave_group(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    // ── RemoveMember ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_member_success() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, admin_signing_key) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create a regular member
        let (_member_user_id, member_device_id, _) = create_test_device(&db).await;
        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
        )
        .bind(group_id)
        .bind(&member_device_id)
        .bind(Utc::now())
        .execute(db.as_ref())
        .await
        .expect("Failed to add member");

        let service = MlsServiceImpl { db: db.clone() };
        let meta = create_metadata(&_admin_user_id, &admin_device_id);

        // Sign admin proof
        let timestamp = Utc::now().timestamp();
        let message = format!(
            "CONSTRUCT_REMOVE_MEMBER:{}:{}:{}",
            group_id, member_device_id, timestamp
        );
        let signature = admin_signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::RemoveMemberRequest {
                group_id: group_id.to_string(),
                target_device_id: member_device_id.clone(),
                mls_remove_proposal: vec![],
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
                encrypted_reason: None,
            },
        );

        let response = service
            .remove_member(request)
            .await
            .expect("RemoveMember should succeed");
        assert!(response.into_inner().success);

        // Verify member is removed
        let is_member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2)",
        )
        .bind(group_id)
        .bind(&member_device_id)
        .fetch_optional(db.as_ref())
        .await
        .expect("Failed to query")
        .flatten()
        .unwrap_or(false);

        assert!(!is_member);
    }

    #[tokio::test]
    async fn test_remove_member_cannot_remove_creator() {
        let db = get_test_db().await;
        let (_admin_user_id, admin_device_id, admin_signing_key) = create_test_device(&db).await;
        let group_id = create_test_group_in_db(&db, &admin_device_id).await;

        // Create a second admin
        let (other_admin_user_id, other_admin_device_id, _) = create_test_device(&db).await;
        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 1, $3)",
        )
        .bind(group_id)
        .bind(&other_admin_device_id)
        .bind(Utc::now())
        .execute(db.as_ref())
        .await
        .expect("Failed to add other admin as member");

        sqlx::query(
            "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, false, $3)",
        )
        .bind(group_id)
        .bind(&other_admin_device_id)
        .bind(Utc::now())
        .execute(db.as_ref())
        .await
        .expect("Failed to add other admin");

        let service = MlsServiceImpl { db };
        let meta = create_metadata(&other_admin_user_id, &other_admin_device_id);

        // Try to remove creator
        let timestamp = Utc::now().timestamp();
        let message = format!(
            "CONSTRUCT_REMOVE_MEMBER:{}:{}:{}",
            group_id, admin_device_id, timestamp
        );
        let signature = admin_signing_key.sign(message.as_bytes());

        let request = Request::from_parts(
            meta,
            tonic::Extensions::default(),
            proto::RemoveMemberRequest {
                group_id: group_id.to_string(),
                target_device_id: admin_device_id.clone(),
                mls_remove_proposal: vec![],
                admin_proof: signature.to_bytes().to_vec(),
                signature_timestamp: timestamp,
                encrypted_reason: None,
            },
        );

        let result = service.remove_member(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }
}
