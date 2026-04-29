use construct_server_shared::shared::proto::services::v1::{self as proto};
use futures_util::stream::iter;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use crate::helpers::{check_group_member, extract_device_id};
use crate::service::MlsServiceImpl;

pub(crate) type FetchCommitsStream = tonic::codegen::BoxStream<proto::CommitEnvelope>;
type CommitRow = (i64, i64, Vec<u8>, Vec<u8>, chrono::DateTime<chrono::Utc>);

pub(crate) async fn submit_commit(
    svc: &MlsServiceImpl,
    request: Request<proto::SubmitCommitRequest>,
) -> Result<Response<proto::SubmitCommitResponse>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    // 2. Verify membership
    let is_member = check_group_member(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    // 3. Validate inputs
    if req.mls_commit.is_empty() {
        return Err(Status::invalid_argument("mls_commit is required"));
    }

    if req.new_ratchet_tree.is_empty() {
        return Err(Status::invalid_argument("new_ratchet_tree is required"));
    }

    // 4. Check group not dissolved
    let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
            .bind(group_id)
            .fetch_optional(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?
            .flatten();

    if dissolved_at.is_some() {
        return Err(Status::not_found("Group dissolved"));
    }

    // 5. Atomic transaction: validate epoch + update
    let now = chrono::Utc::now();
    let mut tx = svc
        .db
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Failed to start transaction: {}", e)))?;

    // Lock group row for update (CAS)
    let current_epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE group_id = $1 FOR UPDATE")
            .bind(group_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    // Validate epoch continuity
    if req.epoch != current_epoch as u64 {
        tx.rollback().await.ok();
        return Err(Status::aborted("EPOCH_MISMATCH"));
    }

    let new_epoch = current_epoch + 1;

    // 6. Store commit in group_commits (30-day TTL)
    let commit_expires = now + chrono::Duration::days(30);

    sqlx::query(
        r#"
        INSERT INTO group_commits
            (group_id, epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot, committed_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(group_id)
    .bind(current_epoch)
    .bind(new_epoch)
    .bind(&req.mls_commit)
    .bind(&req.new_ratchet_tree)
    .bind(now)
    .bind(commit_expires)
    .execute(&mut *tx)
    .await
    .map_err(|e| Status::internal(format!("Failed to store commit: {}", e)))?;

    // 7. Update group state (ratchet_tree + epoch)
    sqlx::query("UPDATE mls_groups SET ratchet_tree = $1, epoch = $2 WHERE group_id = $3")
        .bind(&req.new_ratchet_tree)
        .bind(new_epoch)
        .bind(group_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| Status::internal(format!("Failed to update group state: {}", e)))?;

    // 8. Process Welcome deliveries (if commit adds members)
    for delivery in &req.welcome_deliveries {
        // Verify the KeyPackage ref is valid and belongs to target device
        let kp_valid: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM group_key_packages
                WHERE key_package_ref = $1 AND device_id = $2 AND expires_at > NOW()
            )
            "#,
        )
        .bind(&delivery.key_package_ref)
        .bind(&delivery.device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Status::internal(format!("DB error: {}", e)))?
        .flatten()
        .unwrap_or(false);

        if !kp_valid {
            warn!(
                group_id = %group_id,
                target_device = %delivery.device_id,
                "Welcome delivery: KeyPackage not found or expired"
            );
        }
        // Note: Welcome delivery itself is handled client-side after this commit
    }

    tx.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit: {}", e)))?;

    info!(
        group_id = %group_id,
        device_id = %device_id,
        old_epoch = current_epoch,
        new_epoch = new_epoch,
        "Commit submitted"
    );

    Ok(Response::new(proto::SubmitCommitResponse {
        success: true,
        new_epoch: new_epoch as u64,
        committed_at: now.timestamp(),
    }))
}

pub(crate) async fn fetch_commits(
    svc: &MlsServiceImpl,
    request: Request<proto::FetchCommitsRequest>,
) -> Result<Response<FetchCommitsStream>, Status> {
    let device_id = extract_device_id(request.metadata())?;
    let req = request.into_inner();

    // 1. Parse group_id
    let group_id =
        Uuid::parse_str(&req.group_id).map_err(|_| Status::invalid_argument("Invalid group_id"))?;

    // 2. Verify membership
    let is_member = check_group_member(svc.db.as_ref(), group_id, &device_id).await?;
    if !is_member {
        return Err(Status::permission_denied("NOT_MEMBER"));
    }

    // 3. Check group not dissolved
    let dissolved_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
            .bind(group_id)
            .fetch_optional(svc.db.as_ref())
            .await
            .map_err(|e| Status::internal(format!("DB error: {}", e)))?
            .flatten();

    if dissolved_at.is_some() {
        return Err(Status::not_found("Group dissolved"));
    }

    // 4. Fetch commits since given epoch
    let since_epoch = req.since_epoch as i64;

    let commits: Vec<CommitRow> = sqlx::query_as(
        r#"
            SELECT epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot, committed_at
            FROM group_commits
            WHERE group_id = $1 AND epoch_from >= $2 AND expires_at > NOW()
            ORDER BY epoch_from ASC
            "#,
    )
    .bind(group_id)
    .bind(since_epoch)
    .fetch_all(svc.db.as_ref())
    .await
    .map_err(|e| Status::internal(format!("DB error: {}", e)))?;

    // 5. Convert to proto stream
    let envelopes: Vec<Result<proto::CommitEnvelope, Status>> = commits
        .into_iter()
        .map(|(from, to, commit, tree, committed_at)| {
            Ok(proto::CommitEnvelope {
                group_id: group_id.to_string(),
                epoch_from: from as u64,
                epoch_to: to as u64,
                mls_commit: commit,
                ratchet_tree: tree,
                mls_welcome: None,
                committed_at: committed_at.timestamp(),
            })
        })
        .collect();

    info!(
        group_id = %group_id,
        device_id = %device_id,
        since_epoch = since_epoch,
        commits_count = envelopes.len(),
        "FetchCommits completed"
    );

    // Return as stream
    Ok(Response::new(Box::pin(iter(envelopes))))
}
