// ============================================================================
// MediaService Core Business Logic
// ============================================================================
//
// Pure business logic for media operations, independent of transport layer.
// Supports streaming uploads/downloads with chunking.
//
// Security model (gRPC-only production path):
// - Blobs are client-side E2E ciphertext. The server never decrypts, executes,
//   or interprets file contents (no shell, no image codec, no archive unpack).
// - On-disk objects are UUID-named, mode 0600, under MEDIA_STORAGE_DIR only.
// - Upload tokens are HMAC-bound to media_id + expiry + max_size + user_id and
//   are single-use (create_new final object + DB unique media_id).
//
// ============================================================================

use anyhow::{Context, Result, bail};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::config::MediaConfig;
use crate::utils::{compute_hmac, hmac_eq};

// ============================================================================
// Core Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct MediaMetadata {
    pub media_id: String,
    pub size_bytes: i64,
    pub file_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    #[allow(dead_code)]
    pub storage_backend: String,
    pub storage_key: String,
}

/// Claims extracted from a validated upload token.
#[derive(Debug, Clone)]
pub struct UploadTokenClaims {
    pub media_id: String,
    #[allow(dead_code)]
    pub expires_at: i64,
    /// Max bytes this upload may write (bound into the HMAC).
    pub max_size: i64,
    pub user_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct UploadToken {
    pub media_id: String,
    pub expires_at: i64,
    pub max_size: i64,
    pub user_id: Uuid,
    pub signature: String,
}

// ============================================================================
// Token Management
// ============================================================================

/// Wire format v2 (pipe-separated):
///   `{media_id}|{expires_at}|{max_size}|{user_id}|{signature}`
/// Message for HMAC:
///   `{media_id}|{expires_at}|{max_size}|{user_id}`
///
/// v1 (`media_id|expires|sig`) is deliberately rejected — no silent downgrade.
pub fn generate_upload_token(secret: &str, user_id: Uuid, max_size: i64) -> Result<UploadToken> {
    if max_size <= 0 {
        bail!("max_size must be positive");
    }
    let media_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now().timestamp() + 300; // 5 minutes

    let message = format!("{}|{}|{}|{}", media_id, expires_at, max_size, user_id);
    let signature = compute_hmac(&message, secret);

    Ok(UploadToken {
        media_id,
        expires_at,
        max_size,
        user_id,
        signature,
    })
}

/// Format token for the wire.
pub fn format_upload_token(token: &UploadToken) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        token.media_id, token.expires_at, token.max_size, token.user_id, token.signature
    )
}

/// Validate upload token (format, expiry, constant-time HMAC).
pub fn validate_upload_token(token: &str, secret: &str) -> Result<UploadTokenClaims, &'static str> {
    let parts: Vec<&str> = token.split('|').collect();
    if parts.len() != 5 {
        return Err("Invalid token format");
    }

    let media_id = parts[0];
    // media_id must be a UUID — rejects path traversal payloads early
    if Uuid::parse_str(media_id).is_err() {
        return Err("Invalid media_id in token");
    }

    let expires_at = parts[1]
        .parse::<i64>()
        .map_err(|_| "Invalid expiration timestamp")?;
    let max_size = parts[2].parse::<i64>().map_err(|_| "Invalid max_size")?;
    if max_size <= 0 {
        return Err("Invalid max_size");
    }
    let user_id = Uuid::parse_str(parts[3]).map_err(|_| "Invalid user_id in token")?;
    let signature = parts[4];

    let now = Utc::now().timestamp();
    if now > expires_at {
        return Err("Token expired");
    }

    let message = format!("{}|{}|{}|{}", media_id, expires_at, max_size, user_id);
    let expected = compute_hmac(&message, secret);
    if !hmac_eq(signature, &expected) {
        return Err("Invalid signature");
    }

    Ok(UploadTokenClaims {
        media_id: media_id.to_string(),
        expires_at,
        max_size,
        user_id,
    })
}

// ============================================================================
// Path safety
// ============================================================================

/// Resolve a storage object path under `storage_dir`.
///
/// Accepts only a bare UUID string (no separators, no `..`). Prevents path
/// traversal even if a future caller feeds `storage_key` from untrusted input.
pub fn safe_object_path(storage_dir: &Path, key: &str) -> Result<PathBuf> {
    if key.is_empty()
        || key.contains('/')
        || key.contains('\\')
        || key.contains("..")
        || key.contains('\0')
    {
        bail!("invalid storage key");
    }
    let id = Uuid::parse_str(key).context("storage key must be a UUID")?;
    Ok(storage_dir.join(id.to_string()))
}

// ============================================================================
// File Storage Operations
// ============================================================================

/// Upload chunk state (tracks multi-chunk upload).
///
/// Writes go to `{media_id}.partial` with mode 0600, then atomic rename to the
/// final UUID path on finalize. Final path uses `create_new` semantics via rename
/// over non-existing target — if final already exists, finalize fails (one-time).
pub struct UploadState {
    #[allow(dead_code)]
    pub media_id: String,
    pub max_size: i64,
    pub partial_path: PathBuf,
    pub final_path: PathBuf,
    pub file: Option<fs::File>,
    pub hasher: Sha256,
    pub total_received: usize,
}

impl UploadState {
    pub async fn new(storage_dir: &Path, media_id: String, max_size: i64) -> Result<Self> {
        fs::create_dir_all(storage_dir).await?;

        let final_path = safe_object_path(storage_dir, &media_id)?;
        if final_path.exists() {
            bail!("media object already exists (token already used)");
        }

        let partial_path = storage_dir.join(format!("{media_id}.partial"));
        // Drop any leftover partial from a crashed prior attempt.
        if partial_path.exists() {
            let _ = fs::remove_file(&partial_path).await;
        }

        let file = open_exclusive_0600(&partial_path).await?;

        Ok(Self {
            media_id,
            max_size,
            partial_path,
            final_path,
            file: Some(file),
            hasher: Sha256::new(),
            total_received: 0,
        })
    }

    /// Write chunk; enforces token-bound max_size.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let new_total = self
            .total_received
            .checked_add(chunk.len())
            .context("size overflow")?;
        if new_total as i64 > self.max_size {
            bail!("File size limit exceeded");
        }

        if let Some(ref mut file) = self.file {
            file.write_all(chunk).await?;
            self.hasher.update(chunk);
            self.total_received = new_total;
        } else {
            bail!("File already finalized");
        }
        Ok(())
    }

    /// Finalize: fsync, rename partial → final (no-exec 0600 blob).
    pub async fn finalize(mut self) -> Result<(PathBuf, String, usize)> {
        if let Some(file) = self.file.take() {
            file.sync_all().await.ok();
            drop(file);
        }

        if self.final_path.exists() {
            let _ = fs::remove_file(&self.partial_path).await;
            bail!("media object already exists (token already used)");
        }

        fs::rename(&self.partial_path, &self.final_path)
            .await
            .context("atomic rename to final media path")?;

        // Re-assert non-executable permissions after rename (platform-dependent).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.final_path, perms);
        }

        let hash = hex::encode(self.hasher.finalize());
        Ok((self.final_path, hash, self.total_received))
    }

    /// Abort upload and cleanup partial file.
    pub async fn abort(mut self) -> Result<()> {
        if let Some(file) = self.file.take() {
            drop(file);
        }
        if self.partial_path.exists() {
            fs::remove_file(&self.partial_path).await?;
        }
        Ok(())
    }
}

/// Create a new file with mode 0600 (owner read/write only, never executable).
///
/// Media blobs are never interpreted by the server. Mode 0600 is defense-in-depth
/// so a compromised co-tenant process cannot execute a planted binary either.
async fn open_exclusive_0600(path: &Path) -> Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let std_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {}", path.display()))?;
        Ok(fs::File::from_std(std_file))
    }
    #[cfg(not(unix))]
    {
        Ok(fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await
            .with_context(|| format!("create {}", path.display()))?)
    }
}

/// Read file in chunks for streaming download
pub struct DownloadStream {
    file: fs::File,
    total_size: u64,
    bytes_read: u64,
    chunk_size: usize,
}

impl DownloadStream {
    pub async fn new(file_path: &Path, chunk_size: usize) -> Result<Self> {
        let file = fs::File::open(file_path).await?;
        let metadata = file.metadata().await?;
        let total_size = metadata.len();

        Ok(Self {
            file,
            total_size,
            bytes_read: 0,
            chunk_size,
        })
    }

    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.bytes_read >= self.total_size {
            return Ok(None);
        }

        let mut buffer = vec![0u8; self.chunk_size];
        let n = self.file.read(&mut buffer).await?;

        if n == 0 {
            return Ok(None);
        }

        self.bytes_read += n as u64;
        buffer.truncate(n);
        Ok(Some(buffer))
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn is_complete(&self) -> bool {
        self.bytes_read >= self.total_size
    }
}

// ============================================================================
// Database Operations
// ============================================================================

/// Save media metadata to database.
///
/// `ttl_seconds` comes from `MediaConfig::file_ttl_seconds`, and passing it is
/// the point of this signature. Until 2026-08-13 the INSERT listed no
/// `expires_at`, so the retention actually applied was the schema default —
/// `DEFAULT (NOW() + INTERVAL '15 days')` in migration 021 — while the config
/// said 7 days and `MEDIA_FILE_TTL_SECONDS` was read into a field nothing ever
/// used. Two numbers for one meaning, and the one written in the config, quoted
/// in the docs and reasoned about on the client (MediaSendCache keeps a 6-day
/// TTL specifically to stay under the server's) was the one with no effect.
///
/// Runtime query rather than `sqlx::query!` on purpose: the macro checks against
/// the cached schema in `.sqlx/`, and changing the SQL text of a compile-time
/// query would need `cargo sqlx prepare` against a live database before any
/// SQLX_OFFLINE build could succeed. Same reason as `cleanup_expired_media`.
pub async fn save_metadata(
    pool: &sqlx::PgPool,
    media_id: &str,
    size_bytes: i64,
    storage_backend: &str,
    storage_key: &str,
    file_hash: &str,
    ttl_seconds: i64,
) -> Result<MediaMetadata> {
    let media_id_uuid = Uuid::parse_str(media_id)?;

    let record: (Uuid, i64, String, String, String, i64, i64) = sqlx::query_as(
        r#"
        INSERT INTO media_files (media_id, size_bytes, storage_backend, storage_key, file_hash, expires_at)
        VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(secs => $6))
        RETURNING
            media_id,
            size_bytes,
            storage_backend,
            storage_key,
            file_hash,
            EXTRACT(EPOCH FROM created_at)::BIGINT,
            EXTRACT(EPOCH FROM expires_at)::BIGINT
        "#,
    )
    .bind(media_id_uuid)
    .bind(size_bytes)
    .bind(storage_backend)
    .bind(storage_key)
    .bind(file_hash)
    .bind(ttl_seconds as f64)
    .fetch_one(pool)
    .await?;

    Ok(MediaMetadata {
        media_id: record.0.to_string(),
        size_bytes: record.1,
        storage_backend: record.2,
        storage_key: record.3,
        file_hash: record.4,
        created_at: record.5,
        expires_at: record.6,
    })
}

/// Get media metadata from database
pub async fn get_metadata(pool: &sqlx::PgPool, media_id: &str) -> Result<Option<MediaMetadata>> {
    let media_id_uuid = Uuid::parse_str(media_id).context("media_id must be a UUID")?;

    let record = sqlx::query!(
        r#"
        SELECT
            media_id,
            size_bytes,
            storage_backend,
            storage_key,
            file_hash,
            EXTRACT(EPOCH FROM created_at)::BIGINT as "created_at!",
            EXTRACT(EPOCH FROM expires_at)::BIGINT as "expires_at!"
        FROM media_files
        WHERE media_id = $1
        "#,
        media_id_uuid
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| MediaMetadata {
        media_id: r.media_id.to_string(),
        size_bytes: r.size_bytes,
        file_hash: r.file_hash,
        created_at: r.created_at,
        expires_at: r.expires_at,
        storage_backend: r.storage_backend,
        storage_key: r.storage_key,
    }))
}

/// Delete media metadata from database
pub async fn delete_metadata(pool: &sqlx::PgPool, media_id: &str) -> Result<bool> {
    let media_id_uuid = Uuid::parse_str(media_id)?;

    let result = sqlx::query!(
        r#"
        DELETE FROM media_files
        WHERE media_id = $1
        "#,
        media_id_uuid
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete media file from storage and database
pub async fn delete_media(pool: &sqlx::PgPool, storage_dir: &Path, media_id: &str) -> Result<bool> {
    let metadata = get_metadata(pool, media_id).await?;

    if let Some(meta) = metadata {
        if let Ok(file_path) = safe_object_path(storage_dir, &meta.storage_key)
            && file_path.exists()
        {
            fs::remove_file(&file_path).await?;
        }
        // Also drop any leftover partial
        let partial = storage_dir.join(format!("{}.partial", meta.media_id));
        if partial.exists() {
            let _ = fs::remove_file(&partial).await;
        }

        delete_metadata(pool, media_id).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Delete all DB rows + files past expires_at. Returns count deleted.
pub async fn cleanup_expired_media(pool: &sqlx::PgPool, storage_dir: &Path) -> Result<u64> {
    // Runtime query (not query!) so SQLX_OFFLINE builds don't need a cache refresh.
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        r#"
        SELECT media_id, storage_key
        FROM media_files
        WHERE expires_at < NOW()
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut deleted = 0u64;
    for (media_id, storage_key) in rows {
        let id = media_id.to_string();
        if let Ok(path) = safe_object_path(storage_dir, &storage_key)
            && path.exists()
        {
            let _ = fs::remove_file(&path).await;
        }
        let partial = storage_dir.join(format!("{id}.partial"));
        if partial.exists() {
            let _ = fs::remove_file(&partial).await;
        }
        if delete_metadata(pool, &id).await? {
            deleted += 1;
        }
    }

    // Orphan partials older than 1 hour (crashed uploads)
    if let Ok(mut entries) = fs::read_dir(storage_dir).await {
        let now = std::time::SystemTime::now();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".partial") {
                continue;
            }
            if let Ok(meta) = fs::metadata(&path).await
                && let Ok(modified) = meta.modified()
                && now
                    .duration_since(modified)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    > 3600
            {
                let _ = fs::remove_file(&path).await;
            }
        }
    }

    Ok(deleted)
}

/// Validate file size limits
#[allow(dead_code)]
pub fn validate_file_size(size: i64, config: &MediaConfig) -> Result<(), &'static str> {
    if size <= 0 {
        return Err("File size must be positive");
    }
    if size > config.max_file_size as i64 {
        return Err("File exceeds maximum size limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::compute_hmac;

    #[test]
    fn token_roundtrip_binds_user_and_size() {
        let secret = "test-media-hmac-secret-32chars!!";
        let uid = Uuid::new_v4();
        let tok = generate_upload_token(secret, uid, 1024).unwrap();
        let wire = format_upload_token(&tok);
        let claims = validate_upload_token(&wire, secret).unwrap();
        assert_eq!(claims.media_id, tok.media_id);
        assert_eq!(claims.max_size, 1024);
        assert_eq!(claims.user_id, uid);
    }

    #[test]
    fn token_rejects_tampered_max_size() {
        let secret = "test-media-hmac-secret-32chars!!";
        let uid = Uuid::new_v4();
        let tok = generate_upload_token(secret, uid, 1024).unwrap();
        // Bump max_size without re-signing
        let wire = format!(
            "{}|{}|{}|{}|{}",
            tok.media_id, tok.expires_at, 999_999_999, tok.user_id, tok.signature
        );
        assert!(validate_upload_token(&wire, secret).is_err());
    }

    #[test]
    fn token_rejects_v1_format() {
        let secret = "test-media-hmac-secret-32chars!!";
        let mid = Uuid::new_v4();
        let exp = Utc::now().timestamp() + 300;
        let msg = format!("{}|{}", mid, exp);
        let sig = compute_hmac(&msg, secret);
        let v1 = format!("{}|{}|{}", mid, exp, sig);
        assert!(validate_upload_token(&v1, secret).is_err());
    }

    #[test]
    fn safe_object_path_blocks_traversal() {
        let dir = PathBuf::from("/data/media");
        assert!(safe_object_path(&dir, "../etc/passwd").is_err());
        assert!(safe_object_path(&dir, "foo/bar").is_err());
        assert!(safe_object_path(&dir, "").is_err());
        let id = Uuid::new_v4().to_string();
        let p = safe_object_path(&dir, &id).unwrap();
        assert_eq!(p, dir.join(&id));
    }
}
