use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

// using sqlx::PgPool directly

// ============================================================================
// Typed Records
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChannelRecord {
    pub channel_id: Uuid,
    pub owner_device_id: String,
    pub visibility: String, // "PUBLIC" or "PRIVATE"
    pub encrypted_metadata: Vec<u8>,
    pub max_subscribers: i32,
    pub retention_days: i32,
    pub subscriber_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChannelSubscriberRecord {
    pub channel_id: Uuid,
    pub device_id: String,
    pub subscribed_at: DateTime<Utc>,
    pub role: String,
    pub is_owner: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChannelPostRecord {
    pub post_id: Uuid,
    pub channel_id: Uuid,
    pub sender_device_id: String,
    pub sequence_number: i64,
    pub ciphertext: Vec<u8>,
    pub thread_id: Option<Uuid>,
    pub client_message_id: Option<String>,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChannelInviteLinkRecord {
    pub token: String,
    pub channel_id: Uuid,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Channel Lifecycle
// ============================================================================

pub async fn create_channel(
    pool: &PgPool,
    owner_device_id: &str,
    visibility: &str,
    encrypted_metadata: &[u8],
    max_subscribers: i32,
    retention_days: i32,
) -> Result<ChannelRecord> {
    let channel = sqlx::query_as::<_, ChannelRecord>(
        r#"
        INSERT INTO channels
            (owner_device_id, visibility, encrypted_metadata, max_subscribers, retention_days, subscriber_count)
        VALUES ($1, $2::channel_visibility, $3, $4, $5, 0)
        RETURNING channel_id, owner_device_id, visibility::TEXT, encrypted_metadata,
                  max_subscribers, retention_days, subscriber_count,
                  created_at, updated_at, deleted_at
        "#,
    )
    .bind(owner_device_id)
    .bind(visibility)
    .bind(encrypted_metadata)
    .bind(max_subscribers)
    .bind(retention_days)
    .fetch_one(pool)
    .await
    .context("Failed to create channel")?;

    Ok(channel)
}

pub async fn get_channel_by_id(pool: &PgPool, channel_id: Uuid) -> Result<Option<ChannelRecord>> {
    sqlx::query_as::<_, ChannelRecord>(
        r#"
        SELECT channel_id, owner_device_id, visibility::TEXT, encrypted_metadata,
               max_subscribers, retention_days, subscriber_count,
               created_at, updated_at, deleted_at
        FROM channels
        WHERE channel_id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(channel_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch channel")
}

pub async fn update_channel_metadata(
    pool: &PgPool,
    channel_id: Uuid,
    encrypted_metadata: &[u8],
    owner_device_id: &str,
) -> Result<DateTime<Utc>> {
    let row: (DateTime<Utc>,) = sqlx::query_as(
        r#"
        UPDATE channels
        SET encrypted_metadata = $2, updated_at = NOW()
        WHERE channel_id = $1
          AND owner_device_id = $3
          AND deleted_at IS NULL
        RETURNING updated_at
        "#,
    )
    .bind(channel_id)
    .bind(encrypted_metadata)
    .bind(owner_device_id)
    .fetch_one(pool)
    .await
    .context("Failed to update channel metadata")?;

    Ok(row.0)
}

pub async fn set_channel_visibility(
    pool: &PgPool,
    channel_id: Uuid,
    visibility: &str,
    owner_device_id: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE channels
        SET visibility = $2::channel_visibility, updated_at = NOW()
        WHERE channel_id = $1
          AND owner_device_id = $3
          AND deleted_at IS NULL
        "#,
    )
    .bind(channel_id)
    .bind(visibility)
    .bind(owner_device_id)
    .execute(pool)
    .await
    .context("Failed to update channel visibility")?;

    Ok(())
}

pub async fn soft_delete_channel(
    pool: &PgPool,
    channel_id: Uuid,
    owner_device_id: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE channels
        SET deleted_at = NOW(), updated_at = NOW()
        WHERE channel_id = $1
          AND owner_device_id = $2
          AND deleted_at IS NULL
        "#,
    )
    .bind(channel_id)
    .bind(owner_device_id)
    .execute(pool)
    .await
    .context("Failed to soft-delete channel")?;

    Ok(())
}

// ============================================================================
// Subscriptions
// ============================================================================

pub async fn subscribe_to_channel(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
    is_owner: bool,
) -> Result<DateTime<Utc>> {
    let role = if is_owner { "ADMIN" } else { "SUBSCRIBER" };
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        r#"
        INSERT INTO channel_subscribers (channel_id, device_id, role, is_owner)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (channel_id, device_id) DO NOTHING
        RETURNING subscribed_at
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .bind(role)
    .bind(is_owner)
    .fetch_optional(pool)
    .await
    .context("Failed to subscribe to channel")?;

    match row {
        Some((ts,)) => Ok(ts),
        None => {
            // Already subscribed, return existing subscribed_at
            let ts: (DateTime<Utc>,) = sqlx::query_as(
                "SELECT subscribed_at FROM channel_subscribers WHERE channel_id = $1 AND device_id = $2",
            )
            .bind(channel_id)
            .bind(device_id)
            .fetch_one(pool)
            .await
            .context("Failed to fetch existing subscription")?;
            Ok(ts.0)
        }
    }
}

pub async fn unsubscribe_from_channel(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<bool> {
    // Owner cannot unsubscribe (must delete channel or transfer ownership first)
    let result = sqlx::query(
        r#"
        DELETE FROM channel_subscribers
        WHERE channel_id = $1
          AND device_id = $2
          AND is_owner = FALSE
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to unsubscribe from channel")?;

    Ok(result.rows_affected() > 0)
}

pub async fn is_channel_subscriber(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM channel_subscribers WHERE channel_id = $1 AND device_id = $2)",
    )
    .bind(channel_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("Failed to check channel subscription")
}

pub async fn is_channel_owner(pool: &PgPool, channel_id: Uuid, device_id: &str) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM channel_subscribers WHERE channel_id = $1 AND device_id = $2 AND is_owner = TRUE)",
    )
    .bind(channel_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("Failed to check channel ownership")
}

pub async fn is_channel_admin(pool: &PgPool, channel_id: Uuid, device_id: &str) -> Result<bool> {
    sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM channel_admins
            WHERE channel_id = $1 AND device_id = $2
            UNION ALL
            SELECT 1 FROM channel_subscribers
            WHERE channel_id = $1 AND device_id = $2 AND (is_owner = TRUE OR role = 'ADMIN')
            LIMIT 1
        )
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .context("Failed to check channel admin status")
}

pub async fn list_channel_subscriptions(
    pool: &PgPool,
    device_id: &str,
    cursor: Option<Uuid>,
    limit: i64,
) -> Result<Vec<ChannelRecord>> {
    if let Some(cursor_id) = cursor {
        sqlx::query_as::<_, ChannelRecord>(
            r#"
            SELECT c.channel_id, c.owner_device_id, c.visibility::TEXT, c.encrypted_metadata,
                   c.max_subscribers, c.retention_days, c.subscriber_count,
                   c.created_at, c.updated_at, c.deleted_at
            FROM channel_subscribers cs
            JOIN channels c ON cs.channel_id = c.channel_id
            WHERE cs.device_id = $1
              AND c.channel_id > $2
              AND c.deleted_at IS NULL
            ORDER BY c.channel_id ASC
            LIMIT $3
            "#,
        )
        .bind(device_id)
        .bind(cursor_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel subscriptions with cursor")
    } else {
        sqlx::query_as::<_, ChannelRecord>(
            r#"
            SELECT c.channel_id, c.owner_device_id, c.visibility::TEXT, c.encrypted_metadata,
                   c.max_subscribers, c.retention_days, c.subscriber_count,
                   c.created_at, c.updated_at, c.deleted_at
            FROM channel_subscribers cs
            JOIN channels c ON cs.channel_id = c.channel_id
            WHERE cs.device_id = $1
              AND c.deleted_at IS NULL
            ORDER BY c.channel_id ASC
            LIMIT $2
            "#,
        )
        .bind(device_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel subscriptions")
    }
}

pub async fn get_channel_subscriber_count(pool: &PgPool, channel_id: Uuid) -> Result<i64> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT subscriber_count FROM channels WHERE channel_id = $1 AND deleted_at IS NULL",
    )
    .bind(channel_id)
    .fetch_optional(pool)
    .await
    .context("Failed to get subscriber count")?;

    Ok(row.map(|(c,)| c as i64).unwrap_or(0))
}

// ============================================================================
// Posts
// ============================================================================

pub async fn next_channel_post_sequence(pool: &PgPool, channel_id: Uuid) -> Result<i64> {
    let (seq,): (i64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(MAX(sequence_number), 0) + 1
        FROM channel_posts
        WHERE channel_id = $1
        "#,
    )
    .bind(channel_id)
    .fetch_one(pool)
    .await
    .context("Failed to allocate post sequence")?;

    Ok(seq)
}

pub async fn insert_channel_post(
    pool: &PgPool,
    channel_id: Uuid,
    sender_device_id: &str,
    ciphertext: &[u8],
    thread_id: Option<Uuid>,
    client_message_id: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<ChannelPostRecord> {
    sqlx::query_as::<_, ChannelPostRecord>(
        r#"
        INSERT INTO channel_posts
            (channel_id, sender_device_id, sequence_number, ciphertext, thread_id, client_message_id, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (channel_id, sequence_number) DO NOTHING
        RETURNING post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                  thread_id, client_message_id, sent_at, expires_at, deleted_at
        "#,
    )
    .bind(channel_id)
    .bind(sender_device_id)
    .bind(next_channel_post_sequence(pool, channel_id).await?)
    .bind(ciphertext)
    .bind(thread_id)
    .bind(client_message_id)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .context("Failed to insert channel post")
}

pub async fn list_channel_posts(
    pool: &PgPool,
    channel_id: Uuid,
    after_sequence: Option<i64>,
    limit: i64,
    thread_id: Option<Uuid>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
) -> Result<Vec<ChannelPostRecord>> {
    let after = after_sequence.unwrap_or(-1);

    // Build query dynamically based on optional filters
    let has_thread = thread_id.is_some();
    let has_since = since.is_some();
    let has_until = until.is_some();

    match (has_thread, has_since, has_until) {
        (true, true, true) => sqlx::query_as::<_, ChannelPostRecord>(
            r#"
                SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                       thread_id, client_message_id, sent_at, expires_at, deleted_at
                FROM channel_posts
                WHERE channel_id = $1
                  AND sequence_number > $2
                  AND thread_id = $3
                  AND sent_at >= $4
                  AND sent_at <= $5
                  AND deleted_at IS NULL
                  AND expires_at > NOW()
                ORDER BY sequence_number ASC
                LIMIT $6
                "#,
        )
        .bind(channel_id)
        .bind(after)
        .bind(thread_id.unwrap())
        .bind(since.unwrap())
        .bind(until.unwrap())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel posts"),
        (true, true, false) => sqlx::query_as::<_, ChannelPostRecord>(
            r#"
                SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                       thread_id, client_message_id, sent_at, expires_at, deleted_at
                FROM channel_posts
                WHERE channel_id = $1
                  AND sequence_number > $2
                  AND thread_id = $3
                  AND sent_at >= $4
                  AND deleted_at IS NULL
                  AND expires_at > NOW()
                ORDER BY sequence_number ASC
                LIMIT $5
                "#,
        )
        .bind(channel_id)
        .bind(after)
        .bind(thread_id.unwrap())
        .bind(since.unwrap())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel posts"),
        (true, false, false) => sqlx::query_as::<_, ChannelPostRecord>(
            r#"
                SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                       thread_id, client_message_id, sent_at, expires_at, deleted_at
                FROM channel_posts
                WHERE channel_id = $1
                  AND sequence_number > $2
                  AND thread_id = $3
                  AND deleted_at IS NULL
                  AND expires_at > NOW()
                ORDER BY sequence_number ASC
                LIMIT $4
                "#,
        )
        .bind(channel_id)
        .bind(after)
        .bind(thread_id.unwrap())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel posts"),
        (false, true, true) => sqlx::query_as::<_, ChannelPostRecord>(
            r#"
                SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                       thread_id, client_message_id, sent_at, expires_at, deleted_at
                FROM channel_posts
                WHERE channel_id = $1
                  AND sequence_number > $2
                  AND sent_at >= $3
                  AND sent_at <= $4
                  AND deleted_at IS NULL
                  AND expires_at > NOW()
                ORDER BY sequence_number ASC
                LIMIT $5
                "#,
        )
        .bind(channel_id)
        .bind(after)
        .bind(since.unwrap())
        .bind(until.unwrap())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel posts"),
        (false, true, false) => sqlx::query_as::<_, ChannelPostRecord>(
            r#"
                SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                       thread_id, client_message_id, sent_at, expires_at, deleted_at
                FROM channel_posts
                WHERE channel_id = $1
                  AND sequence_number > $2
                  AND sent_at >= $3
                  AND deleted_at IS NULL
                  AND expires_at > NOW()
                ORDER BY sequence_number ASC
                LIMIT $4
                "#,
        )
        .bind(channel_id)
        .bind(after)
        .bind(since.unwrap())
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel posts"),
        _ => sqlx::query_as::<_, ChannelPostRecord>(
            r#"
                SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
                       thread_id, client_message_id, sent_at, expires_at, deleted_at
                FROM channel_posts
                WHERE channel_id = $1
                  AND sequence_number > $2
                  AND deleted_at IS NULL
                  AND expires_at > NOW()
                ORDER BY sequence_number ASC
                LIMIT $3
                "#,
        )
        .bind(channel_id)
        .bind(after)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("Failed to list channel posts"),
    }
}

pub async fn get_channel_post_by_id(
    pool: &PgPool,
    post_id: Uuid,
) -> Result<Option<ChannelPostRecord>> {
    sqlx::query_as::<_, ChannelPostRecord>(
        r#"
        SELECT post_id, channel_id, sender_device_id, sequence_number, ciphertext,
               thread_id, client_message_id, sent_at, expires_at, deleted_at
        FROM channel_posts
        WHERE post_id = $1 AND deleted_at IS NULL AND expires_at > NOW()
        "#,
    )
    .bind(post_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch channel post")
}

pub async fn soft_delete_channel_post(
    pool: &PgPool,
    post_id: Uuid,
    admin_device_id: &str,
) -> Result<bool> {
    // Only admin (owner or channel admin) of the post's channel can delete it
    let result = sqlx::query(
        r#"
        UPDATE channel_posts
        SET deleted_at = NOW()
        WHERE post_id = $1
          AND deleted_at IS NULL
          AND channel_id IN (
              SELECT channel_id FROM channel_admins WHERE device_id = $2
              UNION
              SELECT channel_id FROM channel_subscribers
              WHERE device_id = $2 AND (is_owner = TRUE OR role = 'ADMIN')
          )
        "#,
    )
    .bind(post_id)
    .bind(admin_device_id)
    .execute(pool)
    .await
    .context("Failed to soft-delete channel post")?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Admin Management
// ============================================================================

pub async fn add_channel_admin(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
    granted_by_device_id: &str,
) -> Result<DateTime<Utc>> {
    let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
        r#"
        INSERT INTO channel_admins (channel_id, device_id, granted_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (channel_id, device_id) DO NOTHING
        RETURNING granted_at
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .bind(granted_by_device_id)
    .fetch_optional(pool)
    .await
    .context("Failed to add channel admin")?;

    match row {
        Some((ts,)) => Ok(ts),
        None => {
            // Already admin, return existing granted_at
            let ts: (DateTime<Utc>,) = sqlx::query_as(
                "SELECT granted_at FROM channel_admins WHERE channel_id = $1 AND device_id = $2",
            )
            .bind(channel_id)
            .bind(device_id)
            .fetch_one(pool)
            .await
            .context("Failed to fetch existing admin grant")?;
            Ok(ts.0)
        }
    }
}

pub async fn remove_channel_admin(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<bool> {
    // Cannot remove owner's admin status this way
    let result = sqlx::query(
        r#"
        DELETE FROM channel_admins
        WHERE channel_id = $1
          AND device_id = $2
          AND device_id NOT IN (
              SELECT device_id FROM channel_subscribers
              WHERE channel_id = $1 AND is_owner = TRUE
          )
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to remove channel admin")?;

    Ok(result.rows_affected() > 0)
}

pub async fn list_channel_admins(pool: &PgPool, channel_id: Uuid) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT device_id FROM channel_admins WHERE channel_id = $1
        UNION
        SELECT device_id FROM channel_subscribers
        WHERE channel_id = $1 AND (is_owner = TRUE OR role = 'ADMIN')
        ORDER BY device_id
        "#,
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await
    .context("Failed to list channel admins")?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

// ============================================================================
// Invite Links
// ============================================================================

pub async fn create_channel_invite_link(
    pool: &PgPool,
    token: &str,
    channel_id: Uuid,
    created_by_device_id: &str,
    max_uses: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<ChannelInviteLinkRecord> {
    sqlx::query_as::<_, ChannelInviteLinkRecord>(
        r#"
        INSERT INTO channel_invite_links
            (token, channel_id, created_by, max_uses, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING token, channel_id, max_uses, use_count, expires_at, revoked_at, created_at
        "#,
    )
    .bind(token)
    .bind(channel_id)
    .bind(created_by_device_id)
    .bind(max_uses)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .context("Failed to create channel invite link")
}

pub async fn revoke_channel_invite_link(
    pool: &PgPool,
    channel_id: Uuid,
    token: &str,
) -> Result<DateTime<Utc>> {
    let row: (DateTime<Utc>,) = sqlx::query_as(
        r#"
        UPDATE channel_invite_links
        SET revoked_at = NOW()
        WHERE token = $1
          AND channel_id = $2
          AND revoked_at IS NULL
        RETURNING revoked_at
        "#,
    )
    .bind(token)
    .bind(channel_id)
    .fetch_one(pool)
    .await
    .context("Failed to revoke channel invite link")?;

    Ok(row.0)
}

pub async fn resolve_channel_invite_link(
    pool: &PgPool,
    token: &str,
) -> Result<Option<ChannelInviteLinkRecord>> {
    sqlx::query_as::<_, ChannelInviteLinkRecord>(
        r#"
        SELECT token, channel_id, max_uses, use_count, expires_at, revoked_at, created_at
        FROM channel_invite_links
        WHERE token = $1
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .context("Failed to resolve channel invite link")
}

pub async fn increment_channel_invite_link_usage(pool: &PgPool, token: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE channel_invite_links
        SET use_count = use_count + 1
        WHERE token = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
          AND (max_uses IS NULL OR use_count < max_uses)
        "#,
    )
    .bind(token)
    .execute(pool)
    .await
    .context("Failed to increment invite link usage")?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Sender Keys
// ============================================================================

pub async fn store_channel_sender_key(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
    encrypted_sender_key: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO channel_sender_keys (channel_id, device_id, encrypted_sender_key)
        VALUES ($1, $2, $3)
        ON CONFLICT (channel_id, device_id)
        DO UPDATE SET encrypted_sender_key = EXCLUDED.encrypted_sender_key, distributed_at = NOW()
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .bind(encrypted_sender_key)
    .execute(pool)
    .await
    .context("Failed to store channel sender key")?;

    Ok(())
}

pub async fn get_channel_sender_key(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<Option<Vec<u8>>> {
    sqlx::query_scalar(
        r#"
        SELECT encrypted_sender_key
        FROM channel_sender_keys
        WHERE channel_id = $1 AND device_id = $2 AND rotated_at IS NULL
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch channel sender key")
}

pub async fn rotate_channel_sender_key(
    pool: &PgPool,
    channel_id: Uuid,
    device_id: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE channel_sender_keys
        SET rotated_at = NOW()
        WHERE channel_id = $1 AND device_id = $2
        "#,
    )
    .bind(channel_id)
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to rotate channel sender key")?;

    Ok(())
}

// ============================================================================
// Comment Groups (stub — Phase C2)
// ============================================================================

pub async fn get_post_comment_group(pool: &PgPool, post_id: Uuid) -> Result<Option<Uuid>> {
    sqlx::query_scalar(
        r#"
        SELECT group_id FROM channel_post_comment_groups
        WHERE post_id = $1
        "#,
    )
    .bind(post_id)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch comment group")
}

pub async fn create_post_comment_group(
    pool: &PgPool,
    post_id: Uuid,
    group_id: Uuid,
    created_by: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO channel_post_comment_groups (post_id, group_id, created_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (post_id) DO NOTHING
        "#,
    )
    .bind(post_id)
    .bind(group_id)
    .bind(created_by)
    .execute(pool)
    .await
    .context("Failed to create comment group link")?;

    Ok(())
}
