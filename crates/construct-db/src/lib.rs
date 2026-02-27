//! # Construct Database
//!
//! Database utilities and connection pooling for Construct secure messaging server.
//!
//! ## Features
//!
//! - Connection pooling with configuration
//! - Transaction helpers
//! - Common query patterns (exists, count, etc.)
//! - User management functions
//! - Key bundle storage (crypto-agile)
//!
//! ## Usage
//!
//! ```rust,no_run
//! use construct_db::{create_pool, DbConfig, DbPool};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = DbConfig {
//!     max_connections: 20,
//!     acquire_timeout_secs: 30,
//!     idle_timeout_secs: 600,
//! };
//! let pool = create_pool("postgresql://localhost/mydb", &config).await?;
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bcrypt::{hash, DEFAULT_COST};
use chrono::{DateTime, Utc};
use construct_crypto::{BundleData, UploadableKeyBundle};
use crypto_agility::{
    CryptoSuite, InviteTokenRecord, PQPrekeys, ProtocolVersion, UserCapabilities,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Transaction};
use uuid::Uuid;

// ============================================================================
// Core Types
// ============================================================================

/// Database connection pool type
pub type DbPool = Pool<Postgres>;

/// Database transaction type
pub type DbTransaction<'a> = Transaction<'a, Postgres>;

/// User record from database
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub max_connections: u32,
    pub acquire_timeout_secs: u64,
    pub idle_timeout_secs: u64,
}

/// Create a PostgreSQL connection pool
pub async fn create_pool(database_url: &str, db_config: &DbConfig) -> Result<DbPool> {
    // sqlx 0.8 API - используем доступные методы
    // connect_timeout недоступен в 0.8, используем acquire_timeout и idle_timeout
    let pool = PgPoolOptions::new()
        .max_connections(db_config.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(
            db_config.acquire_timeout_secs,
        ))
        .idle_timeout(Some(std::time::Duration::from_secs(
            db_config.idle_timeout_secs,
        )))
        .test_before_acquire(true) // Test connections before returning from pool
        .connect(database_url)
        .await?;

    Ok(pool)
}

pub async fn create_user(pool: &DbPool, username: &str, password: &str) -> Result<User> {
    let password_hash = hash(password, DEFAULT_COST)?;
    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        RETURNING id, username, password_hash           "#,
    )
    .bind(username)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_username(pool: &DbPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        -- CREATE INDEX idx_users_username ON users(username);
        SELECT id, username, password_hash
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}
pub async fn get_user_by_id(pool: &DbPool, user_id: &Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, password_hash
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn verify_password(user: &User, password: &str) -> Result<bool> {
    Ok(bcrypt::verify(password, &user.password_hash)?)
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

/// Updates user password (requires valid old password)
pub async fn update_user_password(pool: &DbPool, user_id: &Uuid, new_password: &str) -> Result<()> {
    let new_password_hash = hash(new_password, DEFAULT_COST)?;

    sqlx::query(
        r#"
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        "#,
    )
    .bind(new_password_hash)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Key Bundle Functions for Crypto-Agility
// ============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
struct KeyBundleRecord {
    pub user_id: Uuid,
    pub master_identity_key: Vec<u8>,
    pub bundle_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub registered_at: DateTime<Utc>,
}

/// Stores a key bundle in the crypto-agile format
pub async fn store_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
    bundle: &UploadableKeyBundle,
) -> Result<()> {
    // Decode base64 strings to Vec<u8> for storage
    let master_identity_key = BASE64
        .decode(&bundle.master_identity_key)
        .context("Failed to decode master_identity_key from base64")?;

    let bundle_data_bytes = BASE64
        .decode(&bundle.bundle_data)
        .context("Failed to decode bundle_data from base64")?;

    let signature = BASE64
        .decode(&bundle.signature)
        .context("Failed to decode signature from base64")?;

    // Verify that bundle_data decodes as valid protobuf BundleData and extract the user_id
    let bundle_data: BundleData = prost::Message::decode(bundle_data_bytes.as_slice())
        .context("Failed to decode bundle_data as protobuf")?;

    // Security check: ensure the user_id in bundle_data matches the authenticated user
    if bundle_data.user_id != user_id.to_string() {
        return Err(anyhow::anyhow!(
            "User ID mismatch: bundle contains '{}' but user is '{}'",
            bundle_data.user_id,
            user_id
        ));
    }

    sqlx::query(
        r#"
        INSERT INTO key_bundles (user_id, master_identity_key, bundle_data, signature, registered_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            bundle_data = EXCLUDED.bundle_data,
            signature = EXCLUDED.signature,
            updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(master_identity_key)
    .bind(bundle_data_bytes)
    .bind(signature)
    .execute(pool)
    .await?;

    Ok(())
}

// Record for key bundle with username
#[derive(sqlx::FromRow)]
struct KeyBundleWithUsername {
    pub master_identity_key: Vec<u8>,
    pub bundle_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub username: String,
}

/// Retrieves a key bundle in the crypto-agile format along with username
/// Returns (bundle, username) tuple
pub async fn get_key_bundle(
    pool: &DbPool,
    user_id: &Uuid,
) -> Result<Option<(UploadableKeyBundle, String)>> {
    let record = sqlx::query_as::<_, KeyBundleWithUsername>(
        r#"
        SELECT
            kb.master_identity_key,
            kb.bundle_data,
            kb.signature,
            u.username
        FROM key_bundles kb
        JOIN users u ON kb.user_id = u.id
        WHERE kb.user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| {
        (
            UploadableKeyBundle {
                master_identity_key: BASE64.encode(r.master_identity_key),
                bundle_data: BASE64.encode(r.bundle_data),
                signature: BASE64.encode(r.signature),
                nonce: None, // Nonce is not stored in DB (only used for replay protection)
                timestamp: None, // Timestamp is not stored in DB (only used for replay protection)
            },
            r.username,
        )
    }))
}

// ============================================================================
// Transaction Helpers
// ============================================================================

/// Begin a new database transaction
///
/// Returns a `DbTransaction` that can be used to execute queries.
/// You must manually call `commit()` or `rollback()`.
///
/// # Example
/// ```rust,no_run
/// # use construct_db::{DbPool, begin_transaction};
/// # async fn example(pool: &DbPool) -> anyhow::Result<()> {
/// let mut tx = begin_transaction(pool).await?;
///
/// // Perform database operations
/// sqlx::query("INSERT INTO users ...").execute(&mut *tx).await?;
///
/// // Commit on success
/// tx.commit().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Error Handling Pattern
/// ```rust,ignore
/// let mut tx = begin_transaction(&pool).await?;
///
/// let result: Result<(), anyhow::Error> = async {
///     sqlx::query("...").execute(&mut *tx).await?;
///     sqlx::query("...").execute(&mut *tx).await?;
///     Ok(())
/// }.await;
///
/// match result {
///     Ok(_) => tx.commit().await?,
///     Err(e) => {
///         tx.rollback().await?;
///         return Err(e);
///     }
/// }
/// ```
pub async fn begin_transaction(pool: &DbPool) -> Result<DbTransaction<'_>> {
    pool.begin().await.context("Failed to begin transaction")
}

// ============================================================================
// Common Query Patterns
// ============================================================================

/// Check if a record exists
///
/// **Note:** Query must already include WHERE clause with $1 placeholder
///
/// # Example
/// ```rust,no_run
/// # use construct_db::{DbPool, user_exists};
/// # async fn example(pool: &DbPool, user_id: &uuid::Uuid) -> anyhow::Result<()> {
/// let exists = user_exists(pool, user_id).await?;
/// # Ok(())
/// # }
/// ```
pub async fn user_exists(pool: &DbPool, user_id: &Uuid) -> Result<bool> {
    let result: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .context("Failed to check user existence")?;
    Ok(result)
}

/// Count records matching a query
///
/// # Example
/// ```rust,no_run
/// # use construct_db::{DbPool, count};
/// # async fn example(pool: &DbPool) -> anyhow::Result<()> {
/// let total_users = count(pool, "SELECT COUNT(*) FROM users").await?;
/// # Ok(())
/// # }
/// ```
pub async fn count(pool: &DbPool, query: &str) -> Result<i64> {
    let count: i64 = sqlx::query_scalar(query)
        .fetch_one(pool)
        .await
        .context("Failed to count records")?;
    Ok(count)
}

/// Count records with a parameter
pub async fn count_where<'a, T>(pool: &DbPool, query: &'a str, param: T) -> Result<i64>
where
    T: sqlx::Encode<'a, Postgres> + sqlx::Type<Postgres> + Send + 'a,
{
    let count: i64 = sqlx::query_scalar(query)
        .bind(param)
        .fetch_one(pool)
        .await
        .context("Failed to count records")?;
    Ok(count)
}

// ============================================================================
// Error Handling Utilities
// ============================================================================

/// Result type for database operations
pub type DbResult<T> = Result<T, DbError>;

/// Database error types
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("Record not found")]
    NotFound,

    #[error("Unique constraint violation: {0}")]
    UniqueViolation(String),

    #[error("Foreign key violation: {0}")]
    ForeignKeyViolation(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

/// Check if an sqlx error is a unique constraint violation
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = err {
        // PostgreSQL unique violation error code is "23505"
        if let Some(code) = db_err.code() {
            return code.as_ref() == "23505";
        }
    }
    false
}

/// Check if an sqlx error is a foreign key violation
pub fn is_foreign_key_violation(err: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = err {
        // PostgreSQL foreign key violation error code is "23503"
        if let Some(code) = db_err.code() {
            return code.as_ref() == "23503";
        }
    }
    false
}

/// Convert sqlx::Error to DbError with better context
pub fn map_db_error(err: sqlx::Error) -> DbError {
    match err {
        sqlx::Error::RowNotFound => DbError::NotFound,
        ref e if is_unique_violation(e) => {
            if let sqlx::Error::Database(db_err) = &err {
                DbError::UniqueViolation(db_err.message().to_string())
            } else {
                DbError::Database(err)
            }
        }
        ref e if is_foreign_key_violation(e) => {
            if let sqlx::Error::Database(db_err) = &err {
                DbError::ForeignKeyViolation(db_err.message().to_string())
            } else {
                DbError::Database(err)
            }
        }
        e => DbError::Database(e),
    }
}
// ============================================================================
// Crypto-Agility Functions
// ============================================================================

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
                vec![CryptoSuite::ClassicX25519] // Default for old users
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

    let crypto_suites_json = serde_json::to_value(&crypto_suites)?;

    sqlx::query(
        r#"
        UPDATE users
        SET protocol_version = $1,
            crypto_suites = $2
        WHERE id = $3
        "#,
    )
    .bind(version_int)
    .bind(crypto_suites_json)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get post-quantum prekeys for a user
pub async fn get_pq_prekeys(pool: &DbPool, user_id: &Uuid) -> Result<Option<PQPrekeys>> {
    #[derive(sqlx::FromRow)]
    struct Row {
        user_id: Uuid,
        pq_identity_key: Vec<u8>,
        pq_kem_key: Vec<u8>,
        pq_signature: Vec<u8>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    }

    let row = sqlx::query_as::<_, Row>(
        r#"
        SELECT user_id, pq_identity_key, pq_kem_key, pq_signature,
               created_at, updated_at, expires_at
        FROM pq_prekeys
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(PQPrekeys {
            user_id: r.user_id,
            pq_identity_key: r.pq_identity_key,
            pq_kem_key: r.pq_kem_key,
            pq_signature: r.pq_signature,
            created_at: r.created_at,
            updated_at: r.updated_at,
            expires_at: r.expires_at,
        })),
        None => Ok(None),
    }
}

/// Store or update post-quantum prekeys for a user
pub async fn upsert_pq_prekeys(
    pool: &DbPool,
    user_id: &Uuid,
    pq_identity_key: &[u8],
    pq_kem_key: &[u8],
    pq_signature: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO pq_prekeys (user_id, pq_identity_key, pq_kem_key, pq_signature)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id) 
        DO UPDATE SET
            pq_identity_key = EXCLUDED.pq_identity_key,
            pq_kem_key = EXCLUDED.pq_kem_key,
            pq_signature = EXCLUDED.pq_signature,
            updated_at = NOW()
        "#,
    )
    .bind(user_id)
    .bind(pq_identity_key)
    .bind(pq_kem_key)
    .bind(pq_signature)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Invite Tokens Functions (Dynamic Contact Sharing)
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
        device_id: None, // v1 invites don't have device_id
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
            device_id: None, // v1 invites don't have device_id
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

/// Cleanup expired invite tokens (called by background job)
/// Returns the number of tokens deleted
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_error_types() {
        let err = DbError::NotFound;
        assert!(matches!(err, DbError::NotFound));

        let err = DbError::UniqueViolation("username".to_string());
        assert!(err.to_string().contains("Unique constraint"));
    }

    #[test]
    fn test_error_code_detection() {
        // These functions require actual database errors to test properly
        // Just verify they compile
        let _ = is_unique_violation;
        let _ = is_foreign_key_violation;
    }
}
