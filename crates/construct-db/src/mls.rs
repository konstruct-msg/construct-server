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

#[derive(Debug, Clone)]
pub struct NewGroup<'a> {
    pub group_id: Uuid,
    pub creator_device_id: &'a str,
    pub initial_ratchet_tree: &'a [u8],
    pub encrypted_group_context: &'a [u8],
    pub max_members: i16,
    pub message_retention_days: i16,
    pub threads_enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGroupInvite<'a> {
    pub invite_id: Uuid,
    pub group_id: Uuid,
    pub target_device_id: &'a str,
    pub mls_welcome: &'a [u8],
    pub key_package_ref: &'a [u8],
    pub epoch: i64,
    pub invited_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGroupMember<'a> {
    pub group_id: Uuid,
    pub device_id: &'a str,
    pub leaf_index: i32,
    pub acceptance_signature: Option<&'a [u8]>,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewGroupKeyPackage<'a> {
    pub user_id: Uuid,
    pub device_id: &'a str,
    pub key_package: &'a [u8],
    pub key_package_ref: &'a [u8],
    pub published_at: DateTime<Utc>,
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

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsumedKeyPackageRecord {
    pub key_package: Vec<u8>,
    pub device_id: String,
    pub key_package_ref: Vec<u8>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct KeyPackageCountRecord {
    pub count: i64,
    pub last_published_at: Option<DateTime<Utc>>,
}

pub async fn get_device_verifying_key(pool: &DbPool, device_id: &str) -> Result<Option<Vec<u8>>> {
    sqlx::query_scalar("SELECT verifying_key FROM devices WHERE device_id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .context("Failed to load device verifying key")
}

pub async fn create_group_with_creator(pool: &DbPool, group: NewGroup<'_>) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("Failed to start MLS group creation transaction")?;

    sqlx::query(
        r#"
        INSERT INTO mls_groups
            (group_id, epoch, ratchet_tree, encrypted_group_context,
             max_members, message_retention_days, threads_enabled, created_at)
        VALUES ($1, 0, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(group.group_id)
    .bind(group.initial_ratchet_tree)
    .bind(group.encrypted_group_context)
    .bind(group.max_members)
    .bind(group.message_retention_days)
    .bind(group.threads_enabled)
    .bind(group.created_at)
    .execute(&mut *tx)
    .await
    .context("Failed to insert MLS group")?;

    sqlx::query(
        r#"
        INSERT INTO group_members (group_id, device_id, leaf_index, joined_at)
        VALUES ($1, $2, 0, $3)
        "#,
    )
    .bind(group.group_id)
    .bind(group.creator_device_id)
    .bind(group.created_at)
    .execute(&mut *tx)
    .await
    .context("Failed to insert MLS group creator membership")?;

    sqlx::query(
        r#"
        INSERT INTO group_admins
            (group_id, device_id, role, is_creator, granted_by_device_id, granted_at)
        VALUES ($1, $2, 1, TRUE, NULL, $3)
        "#,
    )
    .bind(group.group_id)
    .bind(group.creator_device_id)
    .bind(group.created_at)
    .execute(&mut *tx)
    .await
    .context("Failed to insert MLS group creator admin role")?;

    tx.commit()
        .await
        .context("Failed to commit MLS group creation transaction")?;

    Ok(())
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

pub async fn insert_group_invite(pool: &DbPool, invite: NewGroupInvite<'_>) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO group_invites
            (invite_id, group_id, target_device_id, mls_welcome, key_package_ref,
             epoch, invited_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(invite.invite_id)
    .bind(invite.group_id)
    .bind(invite.target_device_id)
    .bind(invite.mls_welcome)
    .bind(invite.key_package_ref)
    .bind(invite.epoch)
    .bind(invite.invited_at)
    .bind(invite.expires_at)
    .execute(pool)
    .await
    .context("Failed to insert MLS group invite")?;

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

pub async fn insert_group_member(pool: &DbPool, member: NewGroupMember<'_>) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO group_members
            (group_id, device_id, leaf_index, acceptance_signature, joined_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(member.group_id)
    .bind(member.device_id)
    .bind(member.leaf_index)
    .bind(member.acceptance_signature)
    .bind(member.joined_at)
    .execute(pool)
    .await
    .context("Failed to insert MLS group member")?;

    Ok(())
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

pub async fn insert_group_key_package(
    pool: &DbPool,
    key_package: NewGroupKeyPackage<'_>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO group_key_packages
            (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (key_package_ref) DO NOTHING
        "#,
    )
    .bind(key_package.user_id)
    .bind(key_package.device_id)
    .bind(key_package.key_package)
    .bind(key_package.key_package_ref)
    .bind(key_package.published_at)
    .bind(key_package.expires_at)
    .execute(pool)
    .await
    .context("Failed to insert MLS key package")?;

    Ok(())
}

pub async fn count_key_packages_for_device(pool: &DbPool, device_id: &str) -> Result<i64> {
    sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM group_key_packages
        WHERE device_id = $1
          AND expires_at > NOW()
        "#,
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("Failed to count MLS key packages for device")
}

pub async fn consume_key_package_for_user(
    pool: &DbPool,
    user_id: Uuid,
    preferred_device_id: Option<&str>,
) -> Result<Option<ConsumedKeyPackageRecord>> {
    if let Some(device_id) = preferred_device_id {
        sqlx::query_as::<_, ConsumedKeyPackageRecord>(
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
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .context("Failed to consume preferred MLS key package")
    } else {
        sqlx::query_as::<_, ConsumedKeyPackageRecord>(
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
        .fetch_optional(pool)
        .await
        .context("Failed to consume MLS key package")
    }
}

pub async fn get_key_package_count(
    pool: &DbPool,
    user_id: Uuid,
    device_id: Option<&str>,
) -> Result<KeyPackageCountRecord> {
    if let Some(device_id) = device_id {
        sqlx::query_as::<_, KeyPackageCountRecord>(
            r#"
            SELECT COUNT(*) AS count, MAX(published_at) AS last_published_at
            FROM group_key_packages
            WHERE user_id = $1
              AND device_id = $2
              AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(pool)
        .await
        .context("Failed to count MLS key packages for user device")
    } else {
        sqlx::query_as::<_, KeyPackageCountRecord>(
            r#"
            SELECT COUNT(*) AS count, MAX(published_at) AS last_published_at
            FROM group_key_packages
            WHERE user_id = $1
              AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to count MLS key packages for user")
    }
}

// ============================================================================
// Group Messages — Phase 5
// ============================================================================

/// Payload for inserting a new group message.
pub struct NewGroupMessage {
    pub group_id: Uuid,
    pub epoch: i64,
    pub mls_ciphertext: Vec<u8>,
    pub sequence_number: i64,
    pub client_message_id: Option<String>,
    pub thread_id: Option<Uuid>,
    pub topic_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

/// Row returned from group_messages.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupMessageRow {
    pub message_id: Uuid,
    pub group_id: Uuid,
    pub epoch: i64,
    pub mls_ciphertext: Vec<u8>,
    pub sequence_number: i64,
    pub thread_id: Option<Uuid>,
    pub topic_id: Option<Uuid>,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Atomically allocates the next sequence number for a group.
/// Returns the new value (starts at 0 for the first message).
pub async fn next_group_message_sequence(pool: &DbPool, group_id: Uuid) -> Result<i64> {
    let (seq,): (i64,) = sqlx::query_as(
        "UPDATE mls_groups SET last_sequence = last_sequence + 1 \
         WHERE group_id = $1 RETURNING last_sequence",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await
    .context("Failed to allocate group message sequence")?;

    Ok(seq)
}

/// Inserts a group message. Returns the inserted row.
/// If `client_message_id` was already used for this group, returns the
/// existing row (idempotent / safe to retry).
pub async fn insert_group_message(pool: &DbPool, msg: &NewGroupMessage) -> Result<GroupMessageRow> {
    // ON CONFLICT DO UPDATE with a no-op update lets us use RETURNING to
    // retrieve the existing row on duplicate client_message_id without error.
    sqlx::query_as::<_, GroupMessageRow>(
        r#"
        INSERT INTO group_messages
            (group_id, epoch, mls_ciphertext, sequence_number,
             client_message_id, thread_id, topic_id, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (group_id, client_message_id)
            WHERE client_message_id IS NOT NULL
            DO UPDATE SET group_id = EXCLUDED.group_id
        RETURNING message_id, group_id, epoch, mls_ciphertext, sequence_number,
                  thread_id, topic_id, sent_at, expires_at
        "#,
    )
    .bind(msg.group_id)
    .bind(msg.epoch)
    .bind(&msg.mls_ciphertext)
    .bind(msg.sequence_number)
    .bind(&msg.client_message_id)
    .bind(msg.thread_id)
    .bind(msg.topic_id)
    .bind(msg.expires_at)
    .fetch_one(pool)
    .await
    .context("Failed to insert group message")
}

/// Fetches messages after `after_sequence` (exclusive) for a group,
/// ordered by sequence_number ASC, limited to `limit` rows.
/// Optionally filtered to a specific `topic_id`.
pub async fn list_group_messages(
    pool: &DbPool,
    group_id: Uuid,
    after_sequence: Option<i64>,
    limit: i64,
    topic_id: Option<Uuid>,
) -> Result<Vec<GroupMessageRow>> {
    let after = after_sequence.unwrap_or(-1);

    if let Some(tid) = topic_id {
        sqlx::query_as::<_, GroupMessageRow>(
            r#"
            SELECT message_id, group_id, epoch, mls_ciphertext, sequence_number,
                   thread_id, topic_id, sent_at, expires_at
              FROM group_messages
             WHERE group_id        = $1
               AND sequence_number > $2
               AND topic_id        = $3
               AND expires_at      > NOW()
             ORDER BY sequence_number ASC
             LIMIT $4
            "#,
        )
        .bind(group_id)
        .bind(after)
        .bind(tid)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list group messages by topic")
    } else {
        sqlx::query_as::<_, GroupMessageRow>(
            r#"
            SELECT message_id, group_id, epoch, mls_ciphertext, sequence_number,
                   thread_id, topic_id, sent_at, expires_at
              FROM group_messages
             WHERE group_id        = $1
               AND sequence_number > $2
               AND expires_at      > NOW()
             ORDER BY sequence_number ASC
             LIMIT $3
            "#,
        )
        .bind(group_id)
        .bind(after)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list group messages")
    }
}

/// Returns the `message_retention_days` for a group (to compute expires_at).
pub async fn get_group_retention_days(pool: &DbPool, group_id: Uuid) -> Result<i32> {
    let (days,): (i16,) =
        sqlx::query_as("SELECT message_retention_days FROM mls_groups WHERE group_id = $1")
            .bind(group_id)
            .fetch_one(pool)
            .await
            .context("Failed to get group retention days")?;

    Ok(days as i32)
}

// ============================================================================
// Group Topics — Phase 6
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TopicRow {
    pub topic_id: Uuid,
    pub group_id: Uuid,
    pub encrypted_name: Vec<u8>,
    pub sort_order: i16,
    pub created_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
}

/// Returns the count of active (non-archived) topics for a group.
pub async fn count_active_topics(pool: &DbPool, group_id: Uuid) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM group_topics WHERE group_id = $1 AND archived_at IS NULL",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await
    .context("Failed to count active topics")?;
    Ok(count)
}

/// Inserts a new topic. Returns the created row.
pub async fn create_topic_record(
    pool: &DbPool,
    group_id: Uuid,
    encrypted_name: &[u8],
    sort_order: i16,
    device_id: &str,
) -> Result<TopicRow> {
    sqlx::query_as::<_, TopicRow>(
        r#"
        INSERT INTO group_topics (group_id, encrypted_name, sort_order, created_by_device_id)
        VALUES ($1, $2, $3, $4)
        RETURNING topic_id, group_id, encrypted_name, sort_order, created_at, archived_at
        "#,
    )
    .bind(group_id)
    .bind(encrypted_name)
    .bind(sort_order)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("Failed to create topic")
}

/// Fetches topics for a group, optionally including archived ones.
pub async fn list_topic_records(
    pool: &DbPool,
    group_id: Uuid,
    include_archived: bool,
) -> Result<Vec<TopicRow>> {
    if include_archived {
        sqlx::query_as::<_, TopicRow>(
            r#"
            SELECT topic_id, group_id, encrypted_name, sort_order, created_at, archived_at
              FROM group_topics
             WHERE group_id = $1
             ORDER BY sort_order ASC, created_at ASC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await
        .context("Failed to list topics")
    } else {
        sqlx::query_as::<_, TopicRow>(
            r#"
            SELECT topic_id, group_id, encrypted_name, sort_order, created_at, archived_at
              FROM group_topics
             WHERE group_id = $1
               AND archived_at IS NULL
             ORDER BY sort_order ASC, created_at ASC
            "#,
        )
        .bind(group_id)
        .fetch_all(pool)
        .await
        .context("Failed to list active topics")
    }
}

/// Archives a topic. Returns the archived_at timestamp.
/// Returns an error if topic does not belong to the group or is already archived.
pub async fn archive_topic_record(
    pool: &DbPool,
    group_id: Uuid,
    topic_id: Uuid,
) -> Result<DateTime<Utc>> {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        r#"
        UPDATE group_topics
           SET archived_at = NOW()
         WHERE topic_id = $1
           AND group_id  = $2
           AND archived_at IS NULL
         RETURNING archived_at
        "#,
    )
    .bind(topic_id)
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .context("Failed to archive topic")?;

    row.map(|(ts,)| ts)
        .ok_or_else(|| anyhow::anyhow!("Topic not found, wrong group, or already archived"))
}

// ============================================================================
// Group Invite Links — Phase 6
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteLinkRow {
    pub token: String,
    pub group_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InviteLinkResolveRow {
    pub group_id: Uuid,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Creates an invite link with the provided `token`.
/// The caller is responsible for generating a cryptographically random 32-char hex token.
pub async fn create_invite_link_record(
    pool: &DbPool,
    token: &str,
    group_id: Uuid,
    device_id: &str,
    max_uses: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<InviteLinkRow> {
    sqlx::query_as::<_, InviteLinkRow>(
        r#"
        INSERT INTO group_invite_links
            (token, group_id, created_by_device_id, max_uses, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING token, group_id, created_at, max_uses, expires_at
        "#,
    )
    .bind(token)
    .bind(group_id)
    .bind(device_id)
    .bind(max_uses)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .context("Failed to create invite link")
}

/// Marks an invite link as revoked. Returns the revoked_at timestamp.
/// Errors if token is not found or does not belong to the group.
pub async fn revoke_invite_link_record(
    pool: &DbPool,
    group_id: Uuid,
    token: &str,
) -> Result<DateTime<Utc>> {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        r#"
        UPDATE group_invite_links
           SET revoked_at = NOW()
         WHERE token    = $1
           AND group_id  = $2
           AND revoked_at IS NULL
         RETURNING revoked_at
        "#,
    )
    .bind(token)
    .bind(group_id)
    .fetch_optional(pool)
    .await
    .context("Failed to revoke invite link")?;

    row.map(|(ts,)| ts)
        .ok_or_else(|| anyhow::anyhow!("Invite link not found, wrong group, or already revoked"))
}

/// Looks up an invite link by token. Returns None if token does not exist.
pub async fn resolve_invite_link_record(
    pool: &DbPool,
    token: &str,
) -> Result<Option<InviteLinkResolveRow>> {
    sqlx::query_as::<_, InviteLinkResolveRow>(
        r#"
        SELECT group_id, max_uses, use_count, expires_at, revoked_at
          FROM group_invite_links
         WHERE token = $1
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .context("Failed to resolve invite link")
}
