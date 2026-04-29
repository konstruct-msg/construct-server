use construct_db::mls as db_mls;
use construct_server_shared::shared::proto::services::v1::{self as proto};
use futures_util::stream::iter;
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use uuid::Uuid;

use crate::helpers::{check_group_member, extract_device_id, get_group_dissolved_at};
use crate::service::MlsServiceImpl;

pub(crate) type FetchCommitsStream = tonic::codegen::BoxStream<proto::CommitEnvelope>;

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
    if get_group_dissolved_at(svc.db.as_ref(), group_id)
        .await?
        .is_some()
    {
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
    let current_epoch = db_mls::lock_group_epoch_for_update(&mut tx, group_id)
        .await
        .map_err(|e| Status::internal(format!("Failed to lock group epoch: {}", e)))?;

    // Validate epoch continuity
    if req.epoch != current_epoch as u64 {
        tx.rollback().await.ok();
        return Err(Status::aborted("EPOCH_MISMATCH"));
    }

    let new_epoch = current_epoch + 1;

    // 6. Store commit in group_commits (30-day TTL)
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
    .map_err(|e| Status::internal(format!("Failed to store commit: {}", e)))?;

    // 7. Update group state (ratchet_tree + epoch)
    db_mls::update_group_epoch_and_ratchet_tree(
        &mut tx,
        group_id,
        &req.new_ratchet_tree,
        new_epoch,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to update group state: {}", e)))?;

    // 8. Process Welcome deliveries (if commit adds members)
    for delivery in &req.welcome_deliveries {
        // Verify the KeyPackage ref is valid and belongs to target device
        let kp_valid = db_mls::is_key_package_valid_for_device(
            &mut tx,
            &delivery.key_package_ref,
            &delivery.device_id,
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to validate key package: {}", e)))?;

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
    if get_group_dissolved_at(svc.db.as_ref(), group_id)
        .await?
        .is_some()
    {
        return Err(Status::not_found("Group dissolved"));
    }

    // 4. Fetch commits since given epoch
    let since_epoch = req.since_epoch as i64;

    let commits = db_mls::get_group_commits_since(svc.db.as_ref(), group_id, since_epoch)
        .await
        .map_err(|e| Status::internal(format!("Failed to fetch commits: {}", e)))?;

    // 5. Convert to proto stream
    let envelopes: Vec<Result<proto::CommitEnvelope, Status>> = commits
        .into_iter()
        .map(|commit| {
            Ok(proto::CommitEnvelope {
                group_id: group_id.to_string(),
                epoch_from: commit.epoch_from as u64,
                epoch_to: commit.epoch_to as u64,
                mls_commit: commit.mls_commit,
                ratchet_tree: commit.ratchet_tree_snapshot,
                mls_welcome: None,
                committed_at: commit.committed_at.timestamp(),
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
