use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::DbPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupAdminAccess {
    pub is_creator: bool,
    pub is_full_admin: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupStateRecord {
    pub epoch: i64,
    pub ratchet_tree: Vec<u8>,
    pub encrypted_group_context: Vec<u8>,
    pub message_retention_days: i16,
    pub threads_enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingCommitRecord {
    pub epoch_from: i64,
    pub epoch_to: i64,
    pub mls_commit: Vec<u8>,
    pub ratchet_tree_snapshot: Vec<u8>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupCommitRecord {
    pub epoch_from: i64,
    pub epoch_to: i64,
    pub mls_commit: Vec<u8>,
    pub ratchet_tree_snapshot: Vec<u8>,
    pub committed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGroupCommit<'a> {
    pub group_id: Uuid,
    pub epoch_from: i64,
    pub epoch_to: i64,
    pub mls_commit: &'a [u8],
    pub ratchet_tree_snapshot: &'a [u8],
    pub committed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteAcceptanceRecord {
    pub target_device_id: String,
    pub mls_welcome: Vec<u8>,
    pub key_package_ref: Vec<u8>,
    pub epoch: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingInviteRecord {
    pub invite_id: Uuid,
    pub group_id: Uuid,
    pub mls_welcome: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub invited_at: DateTime<Utc>,
}

pub async fn get_device_verifying_key(pool: &DbPool, device_id: &str) -> Result<Option<Vec<u8>>> {
    sqlx::query_scalar("SELECT verifying_key FROM devices WHERE device_id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .context("Failed to load device verifying key")
}

pub async fn get_group_admin_access(
    pool: &DbPool,
    group_id: Uuid,
    device_id: &str,
) -> Result<Option<GroupAdminAccess>> {
    let row: Option<(bool, i16)> = sqlx::query_as(
        "SELECT is_creator, role FROM group_admins WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("Failed to load group admin access")?;

    Ok(row.map(|(is_creator, role)| GroupAdminAccess {
        is_creator,
        is_full_admin: role == 1,
    }))
}

pub async fn is_group_member(pool: &DbPool, group_id: Uuid, device_id: &str) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND device_id = $2)",
    )
    .bind(group_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("Failed to check group membership")
}

pub async fn device_belongs_to_user(pool: &DbPool, device_id: &str, user_id: Uuid) -> Result<bool> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1 AND user_id = $2)")
        .bind(device_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to verify device ownership")
}

pub async fn get_group_dissolved_at(
    pool: &DbPool,
    group_id: Uuid,
) -> Result<Option<DateTime<Utc>>> {
    Ok(
        sqlx::query_scalar("SELECT dissolved_at FROM mls_groups WHERE group_id = $1")
            .bind(group_id)
            .fetch_optional(pool)
            .await
            .context("Failed to load group dissolved_at")?
            .flatten(),
    )
}

pub async fn get_group_member_count(pool: &DbPool, group_id: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM group_members WHERE group_id = $1")
        .bind(group_id)
        .fetch_one(pool)
        .await
        .context("Failed to count group members")
}

pub async fn get_group_max_members(pool: &DbPool, group_id: Uuid) -> Result<i16> {
    sqlx::query_scalar("SELECT max_members FROM mls_groups WHERE group_id = $1")
        .bind(group_id)
        .fetch_one(pool)
        .await
        .context("Failed to load group max_members")
}

pub async fn get_group_epoch(pool: &DbPool, group_id: Uuid) -> Result<i64> {
    sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE group_id = $1")
        .bind(group_id)
        .fetch_one(pool)
        .await
        .context("Failed to load group epoch")
}

pub async fn get_active_group_state(
    pool: &DbPool,
    group_id: Uuid,
) -> Result<Option<GroupStateRecord>> {
    sqlx::query_as::<_, GroupStateRecord>(
        r#"
        SELECT epoch, ratchet_tree, encrypted_group_context,
               message_retention_days, threads_enabled, created_at
        FROM mls_groups
        WHERE group_id = $1 AND dissolved_at IS NULL
        "#,
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .context("Failed to load active MLS group state")
}

pub async fn get_pending_commits_since(
    pool: &DbPool,
    group_id: Uuid,
    since_epoch: i64,
) -> Result<Vec<PendingCommitRecord>> {
    sqlx::query_as::<_, PendingCommitRecord>(
        r#"
        SELECT epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot
        FROM group_commits
        WHERE group_id = $1 AND epoch_from >= $2 AND expires_at > NOW()
        ORDER BY epoch_from ASC
        "#,
    )
    .bind(group_id)
    .bind(since_epoch)
    .fetch_all(pool)
    .await
    .context("Failed to load pending MLS commits")
}

pub async fn get_group_commits_since(
    pool: &DbPool,
    group_id: Uuid,
    since_epoch: i64,
) -> Result<Vec<GroupCommitRecord>> {
    sqlx::query_as::<_, GroupCommitRecord>(
        r#"
        SELECT epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot, committed_at
        FROM group_commits
        WHERE group_id = $1 AND epoch_from >= $2 AND expires_at > NOW()
        ORDER BY epoch_from ASC
        "#,
    )
    .bind(group_id)
    .bind(since_epoch)
    .fetch_all(pool)
    .await
    .context("Failed to load MLS commit history")
}

pub async fn set_group_dissolved_at(
    pool: &DbPool,
    group_id: Uuid,
    dissolved_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query("UPDATE mls_groups SET dissolved_at = $1 WHERE group_id = $2")
        .bind(dissolved_at)
        .bind(group_id)
        .execute(pool)
        .await
        .context("Failed to mark group dissolved")?;

    Ok(())
}

pub async fn upsert_group_admin_role(
    pool: &DbPool,
    group_id: Uuid,
    device_id: &str,
    role: i16,
    encrypted_admin_token: Option<&[u8]>,
    granted_by_device_id: &str,
    granted_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO group_admins
            (group_id, device_id, role, is_creator, encrypted_admin_token, granted_by_device_id, granted_at)
        VALUES ($1, $2, $3, FALSE, $4, $5, $6)
        ON CONFLICT (group_id, device_id)
        DO UPDATE SET
            role = EXCLUDED.role,
            encrypted_admin_token = EXCLUDED.encrypted_admin_token,
            granted_by_device_id = EXCLUDED.granted_by_device_id,
            granted_at = EXCLUDED.granted_at
        "#,
    )
    .bind(group_id)
    .bind(device_id)
    .bind(role)
    .bind(encrypted_admin_token)
    .bind(granted_by_device_id)
    .bind(granted_at)
    .execute(pool)
    .await
    .context("Failed to upsert MLS group admin role")?;

    Ok(())
}

pub async fn transfer_group_ownership(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
    old_owner_device_id: &str,
    new_owner_device_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE group_admins SET is_creator = FALSE WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(old_owner_device_id)
    .execute(&mut **tx)
    .await
    .context("Failed to demote previous MLS group owner")?;

    sqlx::query(
        "UPDATE group_admins SET is_creator = TRUE, role = 1 WHERE group_id = $1 AND device_id = $2",
    )
    .bind(group_id)
    .bind(new_owner_device_id)
    .execute(&mut **tx)
    .await
    .context("Failed to promote new MLS group owner")?;

    Ok(())
}

pub async fn get_key_package_device_by_ref(
    pool: &DbPool,
    key_package_ref: &[u8],
) -> Result<Option<String>> {
    sqlx::query_scalar(
        r#"
        SELECT device_id FROM group_key_packages
        WHERE key_package_ref = $1 AND expires_at > NOW()
        "#,
    )
    .bind(key_package_ref)
    .fetch_optional(pool)
    .await
    .context("Failed to resolve device from key package reference")
}

pub async fn has_pending_group_invite(
    pool: &DbPool,
    group_id: Uuid,
    target_device_id: &str,
) -> Result<bool> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM group_invites
            WHERE group_id = $1 AND target_device_id = $2 AND expires_at > NOW()
        )
        "#,
    )
    .bind(group_id)
    .bind(target_device_id)
    .fetch_one(pool)
    .await
    .context("Failed to check pending MLS group invite")
}

pub async fn get_group_invite_for_accept(
    pool: &DbPool,
    invite_id: Uuid,
    group_id: Uuid,
) -> Result<Option<InviteAcceptanceRecord>> {
    sqlx::query_as::<_, InviteAcceptanceRecord>(
        r#"
        SELECT target_device_id, mls_welcome, key_package_ref, epoch
        FROM group_invites
        WHERE invite_id = $1 AND group_id = $2 AND expires_at > NOW()
        "#,
    )
    .bind(invite_id)
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .context("Failed to load MLS invite for acceptance")
}

pub async fn get_next_group_leaf_index(pool: &DbPool, group_id: Uuid) -> Result<i32> {
    let max_leaf_index = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT MAX(leaf_index) FROM group_members WHERE group_id = $1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await
    .context("Failed to load next MLS group leaf index")?;

    Ok(max_leaf_index.map(|value| value + 1).unwrap_or(0))
}

pub async fn delete_group_invite(pool: &DbPool, invite_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM group_invites WHERE invite_id = $1")
        .bind(invite_id)
        .execute(pool)
        .await
        .context("Failed to delete MLS group invite")?;

    Ok(())
}

pub async fn get_group_invite_target_device(
    pool: &DbPool,
    invite_id: Uuid,
    group_id: Uuid,
) -> Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT target_device_id FROM group_invites WHERE invite_id = $1 AND group_id = $2",
    )
    .bind(invite_id)
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .context("Failed to load MLS invite target device")
}

pub async fn list_pending_group_invites(
    pool: &DbPool,
    target_device_id: &str,
    cursor: Option<Uuid>,
    limit: i64,
) -> Result<Vec<PendingInviteRecord>> {
    if let Some(cursor_id) = cursor {
        sqlx::query_as::<_, PendingInviteRecord>(
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
        .bind(target_device_id)
        .bind(cursor_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list pending MLS invites with cursor")
    } else {
        sqlx::query_as::<_, PendingInviteRecord>(
            r#"
            SELECT invite_id, group_id, mls_welcome, expires_at, invited_at
            FROM group_invites
            WHERE target_device_id = $1
              AND expires_at > NOW()
            ORDER BY invite_id ASC
            LIMIT $2
            "#,
        )
        .bind(target_device_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list pending MLS invites")
    }
}

pub async fn remove_group_member(pool: &DbPool, group_id: Uuid, device_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND device_id = $2")
        .bind(group_id)
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to remove MLS group member")?;

    Ok(())
}

pub async fn remove_group_admin_role(pool: &DbPool, group_id: Uuid, device_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM group_admins WHERE group_id = $1 AND device_id = $2")
        .bind(group_id)
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to remove MLS group admin role")?;

    Ok(())
}

pub async fn lock_group_epoch_for_update(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
) -> Result<i64> {
    sqlx::query_scalar("SELECT epoch FROM mls_groups WHERE group_id = $1 FOR UPDATE")
        .bind(group_id)
        .fetch_one(&mut **tx)
        .await
        .context("Failed to lock MLS group epoch for update")
}

pub async fn insert_group_commit(
    tx: &mut Transaction<'_, Postgres>,
    commit: NewGroupCommit<'_>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO group_commits
            (group_id, epoch_from, epoch_to, mls_commit, ratchet_tree_snapshot, committed_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(commit.group_id)
    .bind(commit.epoch_from)
    .bind(commit.epoch_to)
    .bind(commit.mls_commit)
    .bind(commit.ratchet_tree_snapshot)
    .bind(commit.committed_at)
    .bind(commit.expires_at)
    .execute(&mut **tx)
    .await
    .context("Failed to insert MLS group commit")?;

    Ok(())
}

pub async fn update_group_epoch_and_ratchet_tree(
    tx: &mut Transaction<'_, Postgres>,
    group_id: Uuid,
    ratchet_tree: &[u8],
    epoch: i64,
) -> Result<()> {
    sqlx::query("UPDATE mls_groups SET ratchet_tree = $1, epoch = $2 WHERE group_id = $3")
        .bind(ratchet_tree)
        .bind(epoch)
        .bind(group_id)
        .execute(&mut **tx)
        .await
        .context("Failed to update MLS group epoch and ratchet tree")?;

    Ok(())
}

pub async fn is_key_package_valid_for_device(
    tx: &mut Transaction<'_, Postgres>,
    key_package_ref: &[u8],
    device_id: &str,
) -> Result<bool> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM group_key_packages
            WHERE key_package_ref = $1 AND device_id = $2 AND expires_at > NOW()
        )
        "#,
    )
    .bind(key_package_ref)
    .bind(device_id)
    .fetch_one(&mut **tx)
    .await
    .context("Failed to validate key package reference for device")
}
