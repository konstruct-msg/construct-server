// ============================================================================
// KeyService Core - Database Operations
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub device_id: String,
    pub identity_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_id: u32,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<u32>,
    pub crypto_suite: String,
    pub registered_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OneTimePreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

// ============================================================================
// Pre-Key Bundle Operations
// ============================================================================

/// Get pre-key bundle for a device (consumes one-time pre-key if available)
pub async fn get_prekey_bundle(
    db: &PgPool,
    user_id: &str,
    device_id: Option<&str>,
) -> Result<Option<PreKeyBundle>> {
    // First, get device info
    let device = if let Some(did) = device_id {
        sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at
            FROM devices
            WHERE device_id = $1 AND user_id = $2::uuid AND is_active = true
            "#,
        )
        .bind(did)
        .bind(user_id)
        .fetch_optional(db)
        .await?
    } else {
        // Get primary device (first registered)
        sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at
            FROM devices
            WHERE user_id = $1::uuid AND is_active = true
            ORDER BY registered_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?
    };

    let device = match device {
        Some(d) => d,
        None => return Ok(None),
    };

    // Try to consume a one-time pre-key
    let otp = sqlx::query_as::<_, OneTimePreKeyRow>(
        r#"
        DELETE FROM one_time_prekeys
        WHERE device_id = $1
        AND key_id = (
            SELECT key_id FROM one_time_prekeys
            WHERE device_id = $1
            ORDER BY uploaded_at ASC
            LIMIT 1
        )
        RETURNING key_id, public_key
        "#,
    )
    .bind(&device.device_id)
    .fetch_optional(db)
    .await?;

    Ok(Some(PreKeyBundle {
        device_id: device.device_id,
        identity_key: device.identity_public,
        verifying_key: device.verifying_key,
        signed_prekey: device.signed_prekey_public,
        signed_prekey_id: 1, // TODO: Track signed prekey IDs
        signed_prekey_signature: device.signed_prekey_signature.unwrap_or_default(),
        one_time_prekey: otp.as_ref().map(|k| k.public_key.clone()),
        one_time_prekey_id: otp.as_ref().map(|k| k.key_id as u32),
        crypto_suite: device.crypto_suite,
        registered_at: device.registered_at,
    }))
}

/// Get pre-key bundles for all devices of a user
pub async fn get_prekey_bundles(
    db: &PgPool,
    user_id: &str,
    device_ids: Option<&[String]>,
) -> Result<(Vec<PreKeyBundle>, Vec<String>)> {
    let devices: Vec<DeviceRow> = if let Some(ids) = device_ids {
        sqlx::query_as(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at
            FROM devices
            WHERE user_id = $1::uuid AND device_id = ANY($2) AND is_active = true
            "#,
        )
        .bind(user_id)
        .bind(ids)
        .fetch_all(db)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at
            FROM devices
            WHERE user_id = $1::uuid AND is_active = true
            "#,
        )
        .bind(user_id)
        .fetch_all(db)
        .await?
    };

    let mut bundles = Vec::new();
    let mut unavailable = Vec::new();

    for device in devices {
        // Try to get one-time pre-key
        let otp = sqlx::query_as::<_, OneTimePreKeyRow>(
            r#"
            DELETE FROM one_time_prekeys
            WHERE device_id = $1
            AND key_id = (
                SELECT key_id FROM one_time_prekeys
                WHERE device_id = $1
                ORDER BY uploaded_at ASC
                LIMIT 1
            )
            RETURNING key_id, public_key
            "#,
        )
        .bind(&device.device_id)
        .fetch_optional(db)
        .await?;

        bundles.push(PreKeyBundle {
            device_id: device.device_id,
            identity_key: device.identity_public,
            verifying_key: device.verifying_key,
            signed_prekey: device.signed_prekey_public,
            signed_prekey_id: 1,
            signed_prekey_signature: device.signed_prekey_signature.unwrap_or_default(),
            one_time_prekey: otp.as_ref().map(|k| k.public_key.clone()),
            one_time_prekey_id: otp.as_ref().map(|k| k.key_id as u32),
            crypto_suite: device.crypto_suite,
            registered_at: device.registered_at,
        });
    }

    // Check for requested but unavailable devices
    if let Some(ids) = device_ids {
        let found: std::collections::HashSet<_> = bundles.iter().map(|b| &b.device_id).collect();
        for id in ids {
            if !found.contains(id) {
                unavailable.push(id.clone());
            }
        }
    }

    Ok((bundles, unavailable))
}

// ============================================================================
// One-Time Pre-Key Management
// ============================================================================

/// Upload one-time pre-keys for a device
pub async fn upload_prekeys(
    db: &PgPool,
    device_id: &str,
    prekeys: &[OneTimePreKey],
) -> Result<u32> {
    // Verify device exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1 AND is_active = true)",
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    if !exists {
        anyhow::bail!("Device not found or inactive");
    }

    // Insert pre-keys
    for prekey in prekeys {
        sqlx::query(
            r#"
            INSERT INTO one_time_prekeys (device_id, key_id, public_key)
            VALUES ($1, $2, $3)
            ON CONFLICT (device_id, key_id) DO UPDATE SET public_key = $3
            "#,
        )
        .bind(device_id)
        .bind(prekey.key_id as i32)
        .bind(&prekey.public_key)
        .execute(db)
        .await?;
    }

    // Return total count
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1")
            .bind(device_id)
            .fetch_one(db)
            .await?;

    Ok(count as u32)
}

/// Get count of remaining one-time pre-keys
pub async fn get_prekey_count(db: &PgPool, device_id: &str) -> Result<(u32, DateTime<Utc>)> {
    let row = sqlx::query_as::<_, PreKeyCountRow>(
        r#"
        SELECT COUNT(*) as count, MAX(uploaded_at) as last_upload
        FROM one_time_prekeys
        WHERE device_id = $1
        "#,
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    Ok((
        row.count.unwrap_or(0) as u32,
        row.last_upload.unwrap_or_else(Utc::now),
    ))
}

// ============================================================================
// Signed Pre-Key Operations
// ============================================================================

/// Rotate signed pre-key (archive old one)
pub async fn rotate_signed_prekey(
    db: &PgPool,
    device_id: &str,
    new_key: &SignedPreKey,
    reason: &str,
) -> Result<DateTime<Utc>> {
    // Get current signed prekey before updating
    let current = sqlx::query_as::<_, SignedPreKeyRow>(
        r#"
        SELECT signed_prekey_public, signed_prekey_signature
        FROM devices
        WHERE device_id = $1 AND is_active = true
        "#,
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;

    // Archive old key if it exists
    if let Some(old) = current {
        if let Some(sig) = old.signed_prekey_signature {
            sqlx::query(
                r#"
                INSERT INTO signed_prekey_archive (device_id, key_id, public_key, signature, rotation_reason)
                VALUES ($1, 0, $2, $3, $4)
                ON CONFLICT (device_id, key_id) DO UPDATE SET
                    public_key = $2, signature = $3, rotation_reason = $4,
                    archived_at = NOW(), expires_at = NOW() + INTERVAL '48 hours'
                "#
            )
            .bind(device_id)
            .bind(&old.signed_prekey_public)
            .bind(&sig)
            .bind(reason)
            .execute(db)
            .await?;
        }
    }

    // Update device with new signed prekey
    sqlx::query(
        r#"
        UPDATE devices
        SET signed_prekey_public = $2,
            signed_prekey_signature = $3,
            key_updated_at = NOW(),
            key_update_reason = $4
        WHERE device_id = $1
        "#,
    )
    .bind(device_id)
    .bind(&new_key.public_key)
    .bind(&new_key.signature)
    .bind(reason)
    .execute(db)
    .await?;

    // Old key valid until
    let expires_at = Utc::now() + chrono::Duration::hours(48);
    Ok(expires_at)
}

/// Get signed pre-key age
pub async fn get_signed_prekey_age(
    db: &PgPool,
    device_id: &str,
) -> Result<Option<(DateTime<Utc>, bool)>> {
    let row = sqlx::query_as::<_, SignedPreKeyAgeRow>(
        r#"
        SELECT key_updated_at, registered_at
        FROM devices
        WHERE device_id = $1 AND is_active = true
        "#,
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;

    match row {
        Some(r) => {
            let uploaded_at = r.key_updated_at.unwrap_or(r.registered_at);
            let age = Utc::now() - uploaded_at;
            let should_rotate = age.num_days() >= 30;
            Ok(Some((uploaded_at, should_rotate)))
        }
        None => Ok(None),
    }
}

// ============================================================================
// Identity Key Operations
// ============================================================================

/// Get identity key for a user/device
pub async fn get_identity_key(
    db: &PgPool,
    user_id: &str,
    device_id: Option<&str>,
) -> Result<Option<(Vec<u8>, DateTime<Utc>)>> {
    let row = if let Some(did) = device_id {
        sqlx::query_as::<_, IdentityKeyRow>(
            r#"
            SELECT identity_public, registered_at
            FROM devices
            WHERE device_id = $1 AND user_id = $2::uuid AND is_active = true
            "#,
        )
        .bind(did)
        .bind(user_id)
        .fetch_optional(db)
        .await?
    } else {
        sqlx::query_as::<_, IdentityKeyRow>(
            r#"
            SELECT identity_public, registered_at
            FROM devices
            WHERE user_id = $1::uuid AND is_active = true
            ORDER BY registered_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?
    };

    Ok(row.map(|r| (r.identity_public, r.registered_at)))
}

/// Calculate safety number from two identity keys
pub fn calculate_safety_number(
    our_key: &[u8],
    their_key: &[u8],
    our_id: &str,
    their_id: &str,
) -> String {
    use sha2::{Digest, Sha256};

    // Determine order (lexicographically smaller ID first)
    let (first_key, first_id, second_key, second_id) = if our_id < their_id {
        (our_key, our_id, their_key, their_id)
    } else {
        (their_key, their_id, our_key, our_id)
    };

    // Hash: version || id1 || key1 || id2 || key2
    let mut hasher = Sha256::new();
    hasher.update(b"\x00"); // version byte
    hasher.update(first_id.as_bytes());
    hasher.update(first_key);
    hasher.update(second_id.as_bytes());
    hasher.update(second_key);

    let hash = hasher.finalize();

    // Convert to 60-digit number (5 groups of 12 digits)
    // Use first 30 bytes, convert each 5 bytes to 12-digit group
    let mut result = String::with_capacity(65);
    for i in 0..5 {
        let offset = i * 5;
        let value = u64::from_be_bytes([
            0,
            0,
            0,
            hash[offset],
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
            hash[offset + 4],
        ]) % 1_000_000_000_000;

        if i > 0 {
            result.push(' ');
        }
        result.push_str(&format!("{:012}", value));
    }

    result
}

// ============================================================================
// Row Types
// ============================================================================

#[derive(sqlx::FromRow)]
struct DeviceRow {
    device_id: String,
    identity_public: Vec<u8>,
    verifying_key: Vec<u8>,
    signed_prekey_public: Vec<u8>,
    signed_prekey_signature: Option<Vec<u8>>,
    crypto_suite: String,
    registered_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct OneTimePreKeyRow {
    key_id: i32,
    public_key: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct PreKeyCountRow {
    count: Option<i64>,
    last_upload: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct SignedPreKeyRow {
    signed_prekey_public: Vec<u8>,
    signed_prekey_signature: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct SignedPreKeyAgeRow {
    key_updated_at: Option<DateTime<Utc>>,
    registered_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct IdentityKeyRow {
    identity_public: Vec<u8>,
    registered_at: DateTime<Utc>,
}

// ============================================================================
// Cleanup Jobs
// ============================================================================

/// Delete expired archived signed pre-keys
#[allow(dead_code)]
pub async fn cleanup_expired_archives(db: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM signed_prekey_archive WHERE expires_at < NOW()")
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}
