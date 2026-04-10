use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use construct_crypto::{UploadableKeyBundle, envelope_decrypt, envelope_encrypt, hmac_sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

pub type DbPool = Pool<Postgres>;

// New minimal User struct (passwordless, device-based)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    /// HMAC-SHA256(server_secret, normalised_username) — 32 bytes.
    /// NULL for anonymous accounts.
    pub username_hash: Option<Vec<u8>>,
    pub recovery_public_key: Option<Vec<u8>>,
    pub last_recovery_at: Option<DateTime<Utc>>,
    pub primary_device_id: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlockedUser {
    pub user_id: Uuid,
    pub blocked_at: DateTime<Utc>,
    pub reason: Option<String>,
}

use construct_config::DbConfig;

pub async fn create_pool(database_url: &str, db_config: &DbConfig) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(db_config.max_connections)
        .min_connections(db_config.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(
            db_config.acquire_timeout_secs,
        ))
        .idle_timeout(Some(std::time::Duration::from_secs(
            db_config.idle_timeout_secs,
        )))
        // Proactively verify connections before use. On Docker networks this costs ~1 ms but
        // prevents silent failures when Postgres restarted and the pool holds stale sockets.
        .test_before_acquire(true)
        .connect(database_url)
        .await?;

    Ok(pool)
}

// ============================================================================
// Passwordless Device-Based Auth Functions (New)
// ============================================================================

/// Get user by ID (passwordless)
pub async fn get_user_by_id(pool: &DbPool, user_id: &Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username_hash, recovery_public_key, last_recovery_at, primary_device_id
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Look up a user by their HMAC username hash (migration 034+).
pub async fn get_user_by_username_hash(
    pool: &DbPool,
    username_hash: &[u8],
) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username_hash, recovery_public_key, last_recovery_at, primary_device_id
        FROM users
        WHERE username_hash = $1
        "#,
    )
    .bind(username_hash)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

/// Set or clear the username hash for a user account.
///
/// Pass `Some(hash)` to set a new username (computed by the caller via
/// `construct_crypto::hash_username`).  Pass `None` to make the account anonymous.
pub async fn update_user_username(
    pool: &DbPool,
    user_id: &Uuid,
    username_hash: Option<&[u8]>,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET username_hash = $1
        WHERE id = $2
        RETURNING id, username_hash, recovery_public_key, last_recovery_at, primary_device_id
        "#,
    )
    .bind(username_hash)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("Failed to update username hash")?;

    Ok(user)
}

/// Create a new user (passwordless, device-based).
///
/// `username_hash` — pass the output of `construct_crypto::hash_username` for users
/// that want a searchable handle, or `None` for anonymous accounts.
/// The plaintext username is never stored.
pub async fn create_user_passwordless(
    pool: &DbPool,
    username_hash: Option<&[u8]>,
    primary_device_id: &str,
) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username_hash, primary_device_id)
        VALUES (gen_random_uuid(), $1, $2)
        RETURNING id, username_hash, recovery_public_key, last_recovery_at, primary_device_id
        "#,
    )
    .bind(username_hash)
    .bind(primary_device_id)
    .fetch_one(pool)
    .await
    .context("Failed to create passwordless user")?;

    Ok(user)
}

/// Set or clear the `searchable` flag for a user (migration 038+).
///
/// When `searchable = true` the user appears in `FindUser` results.
/// Default is `false` — server never exposes users without explicit opt-in.
pub async fn set_user_searchable(pool: &DbPool, user_id: &Uuid, searchable: bool) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE users
        SET searchable = $1
        WHERE id = $2
        "#,
    )
    .bind(searchable)
    .bind(user_id)
    .execute(pool)
    .await
    .context("Failed to update searchable flag")?;

    Ok(())
}

/// Find a discoverable user by their HMAC username hash.
///
/// Returns `Some(user_id)` only when a matching row exists **and** `searchable = TRUE`.
/// Callers must return the same "not found" response for `None` regardless of whether
/// the user doesn't exist or simply opted out — this prevents username existence oracles.
pub async fn find_discoverable_user_by_username_hash(
    pool: &DbPool,
    username_hash: &[u8],
) -> Result<Option<Uuid>> {
    let user_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id
        FROM users
        WHERE username_hash = $1
          AND searchable = TRUE
        "#,
    )
    .bind(username_hash)
    .fetch_optional(pool)
    .await
    .context("Failed to search user by username hash")?;

    Ok(user_id)
}

/// Delete user account and all associated data
/// This performs a hard delete (cascade will handle related records)
pub async fn delete_user_account(pool: &DbPool, user_id: &Uuid) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Check if `user_id` has enabled discoverable search (`searchable = TRUE`).
pub async fn is_user_searchable(pool: &DbPool, user_id: &Uuid) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND searchable = TRUE)",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("Failed to check user searchable flag")?;
    Ok(exists)
}

/// Add or update a user in caller's blocklist.
pub async fn block_user(
    pool: &DbPool,
    blocker_user_id: &Uuid,
    blocked_user_id: &Uuid,
    reason: Option<&str>,
) -> Result<DateTime<Utc>> {
    let blocked_at = sqlx::query_scalar::<_, DateTime<Utc>>(
        r#"
        INSERT INTO user_blocks (blocker_user_id, blocked_user_id, reason)
        VALUES ($1, $2, $3)
        ON CONFLICT (blocker_user_id, blocked_user_id)
        DO UPDATE SET reason = EXCLUDED.reason, blocked_at = NOW()
        RETURNING blocked_at
        "#,
    )
    .bind(blocker_user_id)
    .bind(blocked_user_id)
    .bind(reason)
    .fetch_one(pool)
    .await
    .context("Failed to block user")?;

    Ok(blocked_at)
}

/// Remove a user from caller's blocklist.
pub async fn unblock_user(
    pool: &DbPool,
    blocker_user_id: &Uuid,
    blocked_user_id: &Uuid,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM user_blocks
        WHERE blocker_user_id = $1 AND blocked_user_id = $2
        "#,
    )
    .bind(blocker_user_id)
    .bind(blocked_user_id)
    .execute(pool)
    .await
    .context("Failed to unblock user")?;

    Ok(result.rows_affected() > 0)
}

/// List blocked users for caller.
pub async fn get_blocked_users(pool: &DbPool, blocker_user_id: &Uuid) -> Result<Vec<BlockedUser>> {
    let rows = sqlx::query_as::<_, BlockedUser>(
        r#"
        SELECT
            ub.blocked_user_id AS user_id,
            ub.blocked_at,
            ub.reason
        FROM user_blocks ub
        WHERE ub.blocker_user_id = $1
        ORDER BY ub.blocked_at DESC
        "#,
    )
    .bind(blocker_user_id)
    .fetch_all(pool)
    .await
    .context("Failed to get blocked users")?;

    Ok(rows)
}

/// Check if `recipient_id` has blocked `sender_id`.
/// Used by SendMessage to return ErrorCode::Blocked without leaking privacy details.
pub async fn is_blocked_by(pool: &DbPool, recipient_id: &Uuid, sender_id: &Uuid) -> Result<bool> {
    let blocked: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_blocks WHERE blocker_user_id = $1 AND blocked_user_id = $2)",
    )
    .bind(recipient_id)
    .bind(sender_id)
    .fetch_one(pool)
    .await
    .context("Failed to check block status")?;

    Ok(blocked)
}

// ============================================================================
// Privacy-preserving contact links
// ============================================================================

/// Insert directional contact link `user_hmac -> peer_hmac`.
pub async fn add_contact_link(pool: &DbPool, user_hmac: &[u8], peer_hmac: &[u8]) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO contact_links (user_hmac, peer_hmac)
        VALUES ($1, $2)
        ON CONFLICT (user_hmac, peer_hmac) DO NOTHING
        "#,
    )
    .bind(user_hmac)
    .bind(peer_hmac)
    .execute(pool)
    .await
    .context("Failed to insert contact link")?;
    Ok(())
}

/// Check if two users are mutual contacts (both directional links exist).
pub async fn are_mutual_contacts(pool: &DbPool, a_hmac: &[u8], b_hmac: &[u8]) -> Result<bool> {
    let ok: bool = sqlx::query_scalar(
        r#"
        SELECT
          EXISTS(SELECT 1 FROM contact_links WHERE user_hmac = $1 AND peer_hmac = $2)
          AND
          EXISTS(SELECT 1 FROM contact_links WHERE user_hmac = $2 AND peer_hmac = $1)
        "#,
    )
    .bind(a_hmac)
    .bind(b_hmac)
    .fetch_one(pool)
    .await
    .context("Failed to check mutual contacts")?;
    Ok(ok)
}

/// Retrieves a key bundle in the crypto-agile format along with username.
/// Returns (bundle, username) tuple.
///
/// Constructs the bundle from the devices table (passwordless auth users).
pub async fn get_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<(UploadableKeyBundle, String)>> {
    get_key_bundle_from_device(pool, user_id).await
}

/// Device key bundle record from database
#[derive(sqlx::FromRow)]
struct DeviceKeyBundle {
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    /// Ed25519 signature of (prologue || signed_prekey_public)
    /// May be None for legacy devices
    pub signed_prekey_signature: Option<Vec<u8>>,
    pub crypto_suites: serde_json::Value,
}

/// Extended key bundle data including separate verifying key
/// Per INVITE_LINKS_QR_API_SPEC.md - verifyingKey must be separate from masterIdentityKey
#[derive(Debug, Clone)]
pub struct ExtendedKeyBundle {
    /// The key bundle (bundleData, masterIdentityKey as X25519)
    pub bundle: UploadableKeyBundle,
    /// Always empty — server no longer stores plaintext username.
    /// Kept for API compatibility; client generates display name locally.
    pub username: String,
    /// Ed25519 verifying key (base64-encoded)
    pub verifying_key: String,
    /// X25519 identity key (base64-encoded) - for masterIdentityKey field
    pub identity_key: String,
}

/// Retrieves a key bundle from the devices table for passwordless auth users
/// Uses the user's primary device (or first active device) to construct the bundle
async fn get_key_bundle_from_device(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<(UploadableKeyBundle, String)>> {
    use construct_crypto::{BundleData, SuiteKeyMaterial};

    let device = sqlx::query_as::<_, DeviceKeyBundle>(
        r#"
        SELECT
            d.verifying_key,
            d.identity_public,
            d.signed_prekey_public,
            d.crypto_suites
        FROM devices d
        JOIN users u ON d.user_id = u.id
        WHERE d.user_id = $1 AND d.is_active = true
        ORDER BY
            CASE WHEN d.device_id = u.primary_device_id THEN 0 ELSE 1 END,
            d.registered_at ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let Some(d) = device else {
        return Ok(None);
    };

    // Parse crypto_suites to determine crypto_suite_id
    let suites: Vec<String> = serde_json::from_value(d.crypto_suites.clone())
        .unwrap_or_else(|_| vec!["Curve25519+Ed25519".to_string()]);

    // Determine crypto_suite_id from first suite
    let crypto_suite_id: u32 = if suites
        .iter()
        .any(|s| s.contains("Kyber") || s.contains("PQ"))
    {
        2 // PQ_HYBRID_KYBER
    } else {
        1 // CLASSIC_X25519
    };

    // Construct SuiteKeyMaterial from device keys
    let suite_key = SuiteKeyMaterial {
        suite_id: crypto_suite_id,
        identity_key: BASE64.encode(&d.identity_public),
        signed_prekey: BASE64.encode(&d.signed_prekey_public),
        signed_prekey_signature: BASE64.encode(vec![0u8; 64]), // Placeholder - device doesn't store this separately
        one_time_prekeys: vec![],                              // Not used for initial key exchange
    };

    // Construct BundleData
    let bundle_data = BundleData {
        user_id: user_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_key],
    };

    // Serialize bundle_data to JSON bytes
    let bundle_data_bytes =
        serde_json::to_vec(&bundle_data).context("Failed to serialize bundle_data")?;

    // For device-based auth, we use verifying_key as master_identity_key
    // TODO: Store real bundle signature from client when system stabilizes
    // For now: placeholder, client doesn't verify
    let bundle = UploadableKeyBundle {
        master_identity_key: BASE64.encode(&d.verifying_key),
        bundle_data: BASE64.encode(&bundle_data_bytes),
        signature: BASE64.encode(vec![0u8; 64]), // TODO: store real signature from client
        nonce: None,
        timestamp: None,
    };

    Ok(Some((bundle, String::new())))
}

/// Retrieves extended key bundle with separate verifying_key and identity_key
/// Per INVITE_LINKS_QR_API_SPEC.md - verifyingKey (Ed25519) must be separate from masterIdentityKey (X25519)
pub async fn get_extended_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<ExtendedKeyBundle>> {
    use construct_crypto::{BundleData, SuiteKeyMaterial};

    // Get the user's primary device or first active device
    let device = sqlx::query_as::<_, DeviceKeyBundle>(
        r#"
        SELECT
            d.verifying_key,
            d.identity_public,
            d.signed_prekey_public,
            d.signed_prekey_signature,
            d.crypto_suites
        FROM devices d
        JOIN users u ON d.user_id = u.id
        WHERE d.user_id = $1 AND d.is_active = true
        ORDER BY
            CASE WHEN d.device_id = u.primary_device_id THEN 0 ELSE 1 END,
            d.registered_at ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    let Some(d) = device else {
        return Ok(None);
    };

    // Parse crypto_suites to determine crypto_suite_id
    let suites: Vec<String> = serde_json::from_value(d.crypto_suites.clone())
        .unwrap_or_else(|_| vec!["Curve25519+Ed25519".to_string()]);

    // Determine crypto_suite_id from first suite
    let crypto_suite_id: u32 = if suites
        .iter()
        .any(|s| s.contains("Kyber") || s.contains("PQ"))
    {
        2 // PQ_HYBRID_KYBER
    } else {
        1 // CLASSIC_X25519
    };

    // Get signed_prekey_signature - required for session initialization
    // If missing, device needs to re-upload their key bundle
    let signed_prekey_sig = match &d.signed_prekey_signature {
        Some(sig) if sig.len() == 64 => BASE64.encode(sig),
        _ => {
            tracing::warn!(
                user_id = %user_id,
                "Device missing signed_prekey_signature - needs key bundle re-upload"
            );
            // Return empty signature - client will fail and prompt user to re-upload
            BASE64.encode(vec![0u8; 64])
        }
    };

    // Construct SuiteKeyMaterial from device keys
    let suite_key = SuiteKeyMaterial {
        suite_id: crypto_suite_id,
        identity_key: BASE64.encode(&d.identity_public),
        signed_prekey: BASE64.encode(&d.signed_prekey_public),
        signed_prekey_signature: signed_prekey_sig,
        one_time_prekeys: vec![],
    };

    // Construct BundleData
    let bundle_data = BundleData {
        user_id: user_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_key],
    };

    // Serialize bundle_data to JSON bytes
    let bundle_data_bytes =
        serde_json::to_vec(&bundle_data).context("Failed to serialize bundle_data")?;

    // Separate keys per spec:
    // - verifying_key: Ed25519 (for invite signatures)
    // - identity_public: X25519 (for key exchange/sessions)
    let verifying_key = BASE64.encode(&d.verifying_key);
    let identity_key = BASE64.encode(&d.identity_public);

    // Bundle signature is for the entire bundleData JSON
    // This is separate from signedPrekeySignature
    //
    // TODO: When system stabilizes, implement full bundle signature verification:
    //   1. Client generates bundleSignature on key upload
    //   2. Server stores bundleSignature in devices table
    //   3. Client verifies on GET /public-key
    // For now: placeholder, client doesn't verify
    let bundle = UploadableKeyBundle {
        master_identity_key: identity_key.clone(), // X25519 for sessions
        bundle_data: BASE64.encode(&bundle_data_bytes),
        signature: BASE64.encode(vec![0u8; 64]), // TODO: store real signature from client
        nonce: None,
        timestamp: None,
    };

    // Return empty string for username (privacy-focused — server has no plaintext)
    // Client will generate friendly display name (e.g., "Blue Penguin")
    Ok(Some(ExtendedKeyBundle {
        bundle,
        username: String::new(),
        verifying_key,
        identity_key,
    }))
}

// ============================================================================
// Device-Based Authentication (Passwordless)
// ============================================================================

/// Device record from database (Privacy-First Design)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Device {
    pub device_id: String,
    pub server_hostname: String,
    pub user_id: Option<Uuid>,
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    /// Ed25519 signature of (prologue || signed_prekey_public), 64 bytes
    /// May be None for legacy devices that haven't re-uploaded their keys
    pub signed_prekey_signature: Option<Vec<u8>>,
    pub crypto_suites: serde_json::Value, // JSONB array
    pub registered_at: DateTime<Utc>,     // Needed for warmup logic
    pub is_active: bool,
}

/// Data for creating a new device
#[derive(Debug, Clone)]
pub struct CreateDeviceData {
    pub device_id: String,
    pub server_hostname: String,
    pub verifying_key: Vec<u8>,
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    /// Ed25519 signature of (prologue || signed_prekey_public), 64 bytes
    /// Required for X3DH session initialization
    pub signed_prekey_signature: Vec<u8>,
    pub crypto_suites: String, // JSONB string like '["Curve25519+Ed25519"]'
}

/// Create a new device (device registration)
///
/// # Arguments
/// * `pool` - Database pool
/// * `data` - Device creation data
/// * `user_id` - Optional user_id to link (None for first device registration)
///
/// # Returns
/// The created device record
pub async fn create_device(
    pool: &DbPool,
    data: CreateDeviceData,
    user_id: Option<Uuid>,
) -> Result<Device> {
    insert_device_impl(pool, data, user_id).await
}

/// Internal implementation for inserting a device (supports transactions)
async fn insert_device_impl<'a, E>(
    executor: E,
    data: CreateDeviceData,
    user_id: Option<Uuid>,
) -> Result<Device>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let device = sqlx::query_as::<_, Device>(
        r#"
        INSERT INTO devices (
            device_id,
            server_hostname,
            user_id,
            verifying_key,
            identity_public,
            signed_prekey_public,
            signed_prekey_signature,
            crypto_suites,
            registered_at,
            is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW(), TRUE)
        RETURNING device_id, server_hostname, user_id, verifying_key,
                  identity_public, signed_prekey_public, signed_prekey_signature,
                  crypto_suites, registered_at, is_active
        "#,
    )
    .bind(&data.device_id)
    .bind(&data.server_hostname)
    .bind(user_id)
    .bind(&data.verifying_key)
    .bind(&data.identity_public)
    .bind(&data.signed_prekey_public)
    .bind(&data.signed_prekey_signature)
    .bind(&data.crypto_suites)
    .fetch_one(executor)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            device_id = %data.device_id,
            user_id = ?user_id,
            crypto_suites = %data.crypto_suites,
            "Failed to create device in database"
        );
        anyhow::anyhow!("Failed to create device: {}", e)
    })?;

    Ok(device)
}

/// Get device by device_id
pub async fn get_device_by_id(pool: &DbPool, device_id: &str) -> Result<Option<Device>> {
    let device = sqlx::query_as::<_, Device>(
        "SELECT device_id, server_hostname, user_id, verifying_key, identity_public, 
                signed_prekey_public, signed_prekey_signature, crypto_suites, registered_at, is_active 
         FROM devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            device_id = %device_id,
            "Database error while fetching device by ID"
        );

        match &e {
            sqlx::Error::ColumnDecode { index, source } => {
                anyhow::anyhow!(
                    "Column decode error at index {}: {}. Check Device struct matches database schema.",
                    index, source
                )
            }
            _ => anyhow::anyhow!("Failed to fetch device '{}': {}", device_id, e)
        }
    })?;

    Ok(device)
}

/// Get all devices for a user
pub async fn get_devices_by_user_id(pool: &DbPool, user_id: &Uuid) -> Result<Vec<Device>> {
    let devices = sqlx::query_as::<_, Device>(
        "SELECT device_id, server_hostname, user_id, verifying_key, identity_public, 
                signed_prekey_public, signed_prekey_signature, crypto_suites, registered_at, is_active 
         FROM devices WHERE user_id = $1 AND is_active = TRUE ORDER BY registered_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            user_id = %user_id,
            "Database error while fetching user devices"
        );
        anyhow::anyhow!("Failed to fetch devices for user {}: {}", user_id, e)
    })?;

    Ok(devices)
}

/// Create user + first device in a single transaction (atomic)
///
/// This ensures that:
/// 1. User is created with generated UUID
/// 2. Device is linked to new user_id
/// 3. users.primary_device_id points to first device
/// 4. All happens atomically (rollback on failure)
///
/// # Arguments
/// * `pool` - Database pool
/// * `username` - Optional username (NULL = maximum privacy)
/// * `device_data` - Device creation data
///
/// # Returns
/// Tuple of (User, Device)
pub async fn create_user_with_first_device(
    pool: &DbPool,
    username_hash: Option<&[u8]>,
    device_data: CreateDeviceData,
) -> Result<(User, Device)> {
    // Start transaction
    let mut tx = pool.begin().await.context("Failed to begin transaction")?;

    // 1. Create user WITHOUT primary_device_id (to avoid FK constraint violation).
    //    Plaintext username is never stored — only the HMAC hash.
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username_hash, primary_device_id)
        VALUES (gen_random_uuid(), $1, NULL)
        RETURNING id, username_hash, recovery_public_key, last_recovery_at, primary_device_id
        "#,
    )
    .bind(username_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            "Failed to create user in database"
        );
        anyhow::anyhow!("Failed to create user: {}", e)
    })?;

    // 2. Create device linked to user using shared implementation
    let device = insert_device_impl(&mut *tx, device_data, Some(user.id)).await?;

    // 3. Update user's primary_device_id (now that device exists)
    sqlx::query(
        r#"
        UPDATE users 
        SET primary_device_id = $1 
        WHERE id = $2
        "#,
    )
    .bind(&device.device_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            user_id = %user.id,
            device_id = %device.device_id,
            "Failed to set primary_device_id"
        );
        anyhow::anyhow!("Failed to set primary_device_id: {}", e)
    })?;

    // Commit transaction
    tx.commit().await.context("Failed to commit transaction")?;

    tracing::info!(
        user_id = %user.id,
        device_id = %device.device_id,
        has_username = username_hash.is_some(),
        "Created user with first device"
    );

    // Return user with updated primary_device_id
    let mut user_with_device_id = user;
    user_with_device_id.primary_device_id = Some(device.device_id.clone());

    Ok((user_with_device_id, device))
}

/// Check if device_id already exists
pub async fn device_exists(pool: &DbPool, device_id: &str) -> Result<bool> {
    let exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1)")
            .bind(device_id)
            .fetch_one(pool)
            .await
            .context("Failed to check device existence")?;

    Ok(exists)
}

/// Update device's last_active_at timestamp
pub async fn update_device_last_active(pool: &DbPool, device_id: &str) -> Result<()> {
    sqlx::query("UPDATE devices SET last_active_at = NOW() WHERE device_id = $1")
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to update device last_active")?;

    Ok(())
}

/// Deactivate a device (soft-delete). Returns true if a row was updated.
pub async fn deactivate_device(pool: &DbPool, device_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE devices SET is_active = FALSE WHERE device_id = $1 AND is_active = TRUE",
    )
    .bind(device_id)
    .execute(pool)
    .await
    .context("Failed to deactivate device")?;
    Ok(result.rows_affected() > 0)
}

/// Get user's primary device (or first active device)
/// Per INVITE_LINKS_QR_API_SPEC.md - used for updating verifying key
pub async fn get_user_primary_device(pool: &DbPool, user_id: &Uuid) -> Result<Option<Device>> {
    let device = sqlx::query_as::<_, Device>(
        r#"
        SELECT
            d.device_id,
            d.server_hostname,
            d.user_id,
            d.verifying_key,
            d.identity_public,
            d.signed_prekey_public,
            d.signed_prekey_signature,
            d.crypto_suites,
            d.registered_at,
            d.is_active
        FROM devices d
        JOIN users u ON d.user_id = u.id
        WHERE d.user_id = $1 AND d.is_active = true
        ORDER BY
            CASE WHEN d.device_id = u.primary_device_id THEN 0 ELSE 1 END,
            d.registered_at ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        // Log detailed error for debugging
        tracing::error!(
            error = %e,
            error_type = ?e,
            user_id = %user_id,
            "Database error while fetching user's primary device"
        );

        // Provide context based on error type
        match &e {
            sqlx::Error::ColumnDecode { index, source } => {
                anyhow::anyhow!(
                    "Failed to decode device column at index {}: {}. \
                    This may indicate a schema mismatch between database and code. \
                    Check migration 016 (signed_prekey_signature).",
                    index,
                    source
                )
            }
            sqlx::Error::RowNotFound => {
                anyhow::anyhow!("Device query returned no rows (unexpected - should return None)")
            }
            sqlx::Error::PoolTimedOut => {
                anyhow::anyhow!(
                    "Database connection pool timeout. \
                    The database may be overloaded or network issues exist."
                )
            }
            sqlx::Error::Database(db_err) => {
                anyhow::anyhow!(
                    "Database error: {} (code: {:?}). \
                    Query: get_user_primary_device for user_id={}",
                    db_err.message(),
                    db_err.code(),
                    user_id
                )
            }
            _ => {
                anyhow::anyhow!("Failed to get user's primary device: {}", e)
            }
        }
    })?;

    Ok(device)
}

/// Update device's verifying key (Ed25519 public key)
/// Per INVITE_LINKS_QR_API_SPEC.md Section 6B
pub async fn update_device_verifying_key(
    pool: &DbPool,
    device_id: &str,
    verifying_key: &[u8],
) -> Result<()> {
    sqlx::query("UPDATE devices SET verifying_key = $1 WHERE device_id = $2")
        .bind(verifying_key)
        .bind(device_id)
        .execute(pool)
        .await
        .context("Failed to update device verifying key")?;

    Ok(())
}

// ============================================================================
// PoW Challenge Management Functions
// ============================================================================

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: i16,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    #[sqlx(try_from = "Option<String>")]
    pub requester_ip: Option<String>,
}

/// Create a new PoW challenge
pub async fn create_pow_challenge(
    pool: &DbPool,
    challenge: &str,
    difficulty: i16,
    requester_ip: Option<&str>,
    ttl_seconds: i64,
) -> Result<PowChallenge> {
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);

    let pow_challenge = sqlx::query_as::<_, PowChallenge>(
        r#"
        INSERT INTO pow_challenges (challenge, difficulty, expires_at, requester_ip)
        VALUES ($1, $2, $3, $4::inet)
        RETURNING challenge, difficulty, created_at, expires_at, used, requester_ip::text as requester_ip
        "#
    )
    .bind(challenge)
    .bind(difficulty)
    .bind(expires_at)
    .bind(requester_ip)
    .fetch_one(pool)
    .await
    .context("Failed to create PoW challenge")?;

    Ok(pow_challenge)
}

/// Get a PoW challenge by challenge string
pub async fn get_pow_challenge(pool: &DbPool, challenge: &str) -> Result<Option<PowChallenge>> {
    let pow_challenge = sqlx::query_as::<_, PowChallenge>(
        "SELECT challenge, difficulty, created_at, expires_at, used, requester_ip::text as requester_ip FROM pow_challenges WHERE challenge = $1"
    )
    .bind(challenge)
    .fetch_optional(pool)
    .await
    .context("Failed to fetch PoW challenge")?;

    Ok(pow_challenge)
}

/// Mark a PoW challenge as used (prevent reuse)
pub async fn mark_challenge_used(pool: &DbPool, challenge: &str) -> Result<()> {
    sqlx::query("UPDATE pow_challenges SET used = TRUE WHERE challenge = $1")
        .bind(challenge)
        .execute(pool)
        .await
        .context("Failed to mark challenge as used")?;

    Ok(())
}

/// Clean up expired PoW challenges (run periodically)
pub async fn cleanup_expired_pow_challenges(pool: &DbPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM pow_challenges WHERE expires_at < NOW()")
        .execute(pool)
        .await
        .context("Failed to cleanup expired challenges")?;

    Ok(result.rows_affected())
}

/// Count PoW challenges created by IP in last N minutes (rate limiting)
pub async fn count_challenges_by_ip(pool: &DbPool, ip: &str, minutes: i32) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM pow_challenges
        WHERE requester_ip = $1::inet
        AND created_at > NOW() - INTERVAL '1 minute' * $2
        "#,
    )
    .bind(ip)
    .bind(minutes)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Count device registrations by IP within time window (anti-spam)
pub async fn count_registrations_by_ip(pool: &DbPool, ip: &str, minutes: i32) -> Result<i64> {
    // Since we don't store IP in devices table, we use pow_challenges that were marked as used
    // This is a proxy: if a challenge was used, it means registration succeeded
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM pow_challenges
        WHERE requester_ip = $1::inet
        AND used = true
        AND created_at > NOW() - INTERVAL '1 minute' * $2
        "#,
    )
    .bind(ip)
    .bind(minutes)
    .fetch_one(pool)
    .await
    .context("Failed to count challenges by IP")?;

    Ok(count)
}

// ============================================================================
// Crypto-Agility Functions (from legacy construct-db)
// ============================================================================

use crypto_agility::{CryptoSuite, InviteTokenRecord, ProtocolVersion, UserCapabilities};

/// Get user capabilities (protocol version and supported crypto suites)
pub async fn get_user_capabilities(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<UserCapabilities>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        protocol_version: i32,
        crypto_suites: Option<serde_json::Value>,
    }

    let row = sqlx::query_as::<_, Row>(
        r#"
        SELECT protocol_version, crypto_suites
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let protocol_version = match r.protocol_version {
                1 => ProtocolVersion::V1Classic,
                2 => ProtocolVersion::V2HybridPQ,
                v => anyhow::bail!("Unknown protocol version: {}", v),
            };

            let crypto_suites: Vec<CryptoSuite> = if let Some(suites_json) = r.crypto_suites {
                serde_json::from_value(suites_json).context("Failed to parse crypto_suites JSON")?
            } else {
                vec![CryptoSuite::ClassicX25519]
            };

            Ok(Some(UserCapabilities {
                user_id: *user_id,
                protocol_version,
                crypto_suites,
            }))
        }
        None => Ok(None),
    }
}

/// Update user's protocol version and crypto suites
pub async fn update_user_protocol(
    pool: &DbPool,
    user_id: &Uuid,
    protocol_version: ProtocolVersion,
) -> Result<()> {
    let version_int = match protocol_version {
        ProtocolVersion::V1Classic => 1,
        ProtocolVersion::V2HybridPQ => 2,
    };

    let crypto_suites = match protocol_version {
        ProtocolVersion::V1Classic => vec![CryptoSuite::ClassicX25519],
        ProtocolVersion::V2HybridPQ => vec![
            CryptoSuite::HybridKyber1024X25519,
            CryptoSuite::ClassicX25519,
        ],
    };

    let suites_json =
        serde_json::to_value(&crypto_suites).context("Failed to serialize crypto_suites")?;

    sqlx::query(
        r#"
        UPDATE users
        SET protocol_version = $1, crypto_suites = $2
        WHERE id = $3
        "#,
    )
    .bind(version_int)
    .bind(suites_json)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Invite Token Functions
// ============================================================================

/// Create a new invite token
pub async fn create_invite_token(
    pool: &DbPool,
    jti: &Uuid,
    user_id: &Uuid,
    ephemeral_key: &[u8],
    signature: &[u8],
) -> Result<InviteTokenRecord> {
    #[derive(sqlx::FromRow)]
    struct Row {
        jti: Uuid,
        user_id: Uuid,
        ephemeral_key: Vec<u8>,
        signature: Vec<u8>,
        created_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
    }

    let row = sqlx::query_as::<_, Row>(
        r#"
        INSERT INTO invite_tokens (jti, user_id, ephemeral_key, signature)
        VALUES ($1, $2, $3, $4)
        RETURNING jti, user_id, ephemeral_key, signature, created_at, used_at
        "#,
    )
    .bind(jti)
    .bind(user_id)
    .bind(ephemeral_key)
    .bind(signature)
    .fetch_one(pool)
    .await?;

    Ok(InviteTokenRecord {
        jti: row.jti,
        user_id: row.user_id,
        device_id: None,
        ephemeral_key: row.ephemeral_key,
        signature: row.signature,
        created_at: row.created_at,
        used_at: row.used_at,
    })
}

/// Get an invite token by jti
pub async fn get_invite_token(pool: &DbPool, jti: &Uuid) -> Result<Option<InviteTokenRecord>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        jti: Uuid,
        user_id: Uuid,
        ephemeral_key: Vec<u8>,
        signature: Vec<u8>,
        created_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
    }

    let row = sqlx::query_as::<_, Row>(
        r#"
        SELECT jti, user_id, ephemeral_key, signature, created_at, used_at
        FROM invite_tokens
        WHERE jti = $1
        "#,
    )
    .bind(jti)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(InviteTokenRecord {
            jti: r.jti,
            user_id: r.user_id,
            device_id: None,
            ephemeral_key: r.ephemeral_key,
            signature: r.signature,
            created_at: r.created_at,
            used_at: r.used_at,
        })),
        None => Ok(None),
    }
}

/// Atomically mark an invite token as used (burn it)
/// Returns true if the token was successfully burned, false if already used or not found
pub async fn burn_invite_token(pool: &DbPool, jti: &Uuid) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE invite_tokens
        SET used_at = NOW()
        WHERE jti = $1 AND used_at IS NULL
        "#,
    )
    .bind(jti)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Check if an invite token is valid (exists and not yet used)
pub async fn is_invite_token_valid(pool: &DbPool, jti: &Uuid) -> Result<bool> {
    let result = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM invite_tokens
            WHERE jti = $1 AND used_at IS NULL
        )
        "#,
    )
    .bind(jti)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Cleanup expired invite tokens
pub async fn cleanup_expired_invites(pool: &DbPool) -> Result<u64> {
    let result = sqlx::query(
        r#"
        DELETE FROM invite_tokens
        WHERE created_at < NOW() - INTERVAL '5 minutes'
          AND used_at IS NULL
        "#,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Trait for types that provide a database pool
pub trait HasDbPool {
    fn db_pool(&self) -> &std::sync::Arc<DbPool>;
}

// ============================================================================
// Privacy-preserving contact requests
// ============================================================================

/// A contact request as returned to the authenticated recipient.
#[derive(Debug, Clone)]
pub struct IncomingContactRequest {
    pub id: Uuid,
    /// Decrypted from `from_enc` — returned only to the authenticated recipient.
    pub from_user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// A sent contact request as returned to the sender (no recipient ID revealed).
#[derive(Debug, Clone)]
pub struct SentContactRequest {
    pub id: Uuid,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Raw DB row — used internally before decryption.
#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct RawContactRequest {
    id: Uuid,
    from_enc: Vec<u8>,
    status: String,
    created_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct SentRow {
    id: Uuid,
    status: String,
    created_at: DateTime<Utc>,
}

/// Insert a new contact request.
///
/// - `from_user_id` and `to_user_id` are HMAC-blinded with `hmac_secret`.
/// - `from_user_id` is envelope-encrypted with `envelope_key` for at-rest protection.
/// - `to_user_id` is **not stored** — caller must deliver the push notification before calling this.
///
/// Returns `Ok(request_id)` on success, or an error if a pending request already exists
/// (UNIQUE constraint on `(from_hmac, to_hmac)`).
pub async fn create_contact_request(
    pool: &DbPool,
    from_user_id: Uuid,
    to_user_id: Uuid,
    hmac_secret: &[u8],
    envelope_key: &[u8],
) -> Result<Uuid> {
    let from_hmac = hmac_sha256(hmac_secret, from_user_id.as_bytes());
    let to_hmac = hmac_sha256(hmac_secret, to_user_id.as_bytes());
    let from_enc = envelope_encrypt(envelope_key, from_user_id.as_bytes())
        .map_err(|e| anyhow::anyhow!("envelope_encrypt failed: {}", e))?;

    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO contact_requests (from_hmac, to_hmac, from_enc)
        VALUES ($1, $2, $3)
        ON CONFLICT (from_hmac, to_hmac) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(&from_hmac[..])
    .bind(&to_hmac[..])
    .bind(&from_enc)
    .fetch_optional(pool)
    .await
    .context("Failed to insert contact request")?
    .ok_or_else(|| anyhow::anyhow!("contact request already exists (duplicate)"))?;

    Ok(id)
}

/// Fetch all pending incoming contact requests for `recipient_user_id`.
/// Decrypts `from_enc` server-side and returns the sender UUID.
pub async fn get_pending_contact_requests(
    pool: &DbPool,
    recipient_user_id: Uuid,
    hmac_secret: &[u8],
    envelope_key: &[u8],
) -> Result<Vec<IncomingContactRequest>> {
    let to_hmac = hmac_sha256(hmac_secret, recipient_user_id.as_bytes());

    let rows: Vec<RawContactRequest> = sqlx::query_as(
        r#"
        SELECT id, from_enc, status, created_at, resolved_at
        FROM contact_requests
        WHERE to_hmac = $1 AND status = 'pending'
        ORDER BY created_at ASC
        "#,
    )
    .bind(&to_hmac[..])
    .fetch_all(pool)
    .await
    .context("Failed to fetch pending contact requests")?;

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let from_bytes = envelope_decrypt(envelope_key, &row.from_enc).map_err(|e| {
            anyhow::anyhow!("envelope_decrypt failed for request {}: {}", row.id, e)
        })?;
        let from_arr: [u8; 16] = from_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("decrypted from_enc is not 16 bytes"))?;
        let from_user_id = Uuid::from_bytes(from_arr);
        result.push(IncomingContactRequest {
            id: row.id,
            from_user_id,
            created_at: row.created_at,
        });
    }
    Ok(result)
}

/// Fetch all sent contact requests for `sender_user_id` (status only, no recipient ID).
pub async fn get_sent_contact_requests(
    pool: &DbPool,
    sender_user_id: Uuid,
    hmac_secret: &[u8],
) -> Result<Vec<SentContactRequest>> {
    let from_hmac = hmac_sha256(hmac_secret, sender_user_id.as_bytes());

    let rows: Vec<SentRow> = sqlx::query_as(
        r#"
        SELECT id, status, created_at
        FROM contact_requests
        WHERE from_hmac = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&from_hmac[..])
    .fetch_all(pool)
    .await
    .context("Failed to fetch sent contact requests")?;

    Ok(rows
        .into_iter()
        .map(|r| SentContactRequest {
            id: r.id,
            status: r.status,
            created_at: r.created_at,
        })
        .collect())
}

/// Check if a pending request from `from_user_id` to `to_user_id` exists.
/// Used by `send_contact_request` handler to detect duplicates without exposing IDs.
pub async fn has_pending_contact_request(
    pool: &DbPool,
    from_user_id: Uuid,
    to_user_id: Uuid,
    hmac_secret: &[u8],
) -> Result<bool> {
    let from_hmac = hmac_sha256(hmac_secret, from_user_id.as_bytes());
    let to_hmac = hmac_sha256(hmac_secret, to_user_id.as_bytes());

    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM contact_requests
            WHERE from_hmac = $1 AND to_hmac = $2 AND status = 'pending'
        )
        "#,
    )
    .bind(&from_hmac[..])
    .bind(&to_hmac[..])
    .fetch_one(pool)
    .await
    .context("Failed to check pending contact request")?;

    Ok(exists)
}

/// Respond to a contact request.
///
/// `actor_user_id` must be the recipient (to_hmac must match) — enforced DB-side.
/// Returns `Ok(())` on success, error if request not found or actor is not the recipient.
pub async fn respond_to_contact_request(
    pool: &DbPool,
    request_id: Uuid,
    actor_user_id: Uuid,
    new_status: &str,
    hmac_secret: &[u8],
) -> Result<()> {
    let actor_to_hmac = hmac_sha256(hmac_secret, actor_user_id.as_bytes());

    let rows_affected = sqlx::query(
        r#"
        UPDATE contact_requests
        SET status = $1, resolved_at = NOW()
        WHERE id = $2
          AND to_hmac = $3
          AND status = 'pending'
        "#,
    )
    .bind(new_status)
    .bind(request_id)
    .bind(&actor_to_hmac[..])
    .execute(pool)
    .await
    .context("Failed to update contact request")?
    .rows_affected();

    if rows_affected == 0 {
        anyhow::bail!(
            "contact request {} not found, already resolved, or actor is not the recipient",
            request_id
        );
    }
    Ok(())
}

/// Fetch the raw (unencrypted) from_enc for a specific request — used internally to get
/// the sender's user_id when establishing contact_links after ACCEPT.
pub async fn get_contact_request_sender(
    pool: &DbPool,
    request_id: Uuid,
    actor_user_id: Uuid,
    hmac_secret: &[u8],
    envelope_key: &[u8],
) -> Result<Uuid> {
    let actor_to_hmac = hmac_sha256(hmac_secret, actor_user_id.as_bytes());

    let from_enc: Vec<u8> = sqlx::query_scalar(
        r#"
        SELECT from_enc FROM contact_requests
        WHERE id = $1 AND to_hmac = $2
        "#,
    )
    .bind(request_id)
    .bind(&actor_to_hmac[..])
    .fetch_optional(pool)
    .await
    .context("Failed to fetch contact request sender")?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "request {} not found or actor is not the recipient",
            request_id
        )
    })?;

    let from_bytes = envelope_decrypt(envelope_key, &from_enc)
        .map_err(|e| anyhow::anyhow!("envelope_decrypt failed: {}", e))?;
    let arr: [u8; 16] = from_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted from_enc is not 16 bytes"))?;
    Ok(Uuid::from_bytes(arr))
}
