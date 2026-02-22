// ============================================================================
// MediaService Core Business Logic
// ============================================================================
//
// Pure business logic for media operations, independent of transport layer.
// Supports streaming uploads/downloads with chunking.
//
// ============================================================================

use anyhow::{Context, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::config::MediaConfig;
use crate::utils::compute_hmac;

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
    pub storage_backend: String,
    pub storage_key: String,
}

#[derive(Debug, Clone)]
pub struct UploadToken {
    pub media_id: String,
    pub expires_at: i64,
    pub signature: String,
}

// ============================================================================
// Token Management
// ============================================================================

/// Generate upload token (one-time use, 5 minute TTL)
pub fn generate_upload_token(secret: &str) -> Result<UploadToken> {
    let media_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now().timestamp() + 300; // 5 minutes

    // Message format: {media_id}|{expires_at}
    let message = format!("{}|{}", media_id, expires_at);
    let signature = compute_hmac(&message, secret);

    Ok(UploadToken {
        media_id,
        expires_at,
        signature,
    })
}

/// Validate upload token
/// Format: {media_id}|{expires_at}|{signature}
pub fn validate_upload_token(token: &str, secret: &str) -> Result<(String, i64), &'static str> {
    let parts: Vec<&str> = token.split('|').collect();
    if parts.len() != 3 {
        return Err("Invalid token format");
    }

    let media_id = parts[0];
    let expires_at = parts[1]
        .parse::<i64>()
        .map_err(|_| "Invalid expiration timestamp")?;
    let signature = parts[2];

    // Check expiration
    let now = Utc::now().timestamp();
    if now > expires_at {
        return Err("Token expired");
    }

    // Verify signature
    let message = format!("{}|{}", media_id, expires_at);
    let expected_signature = compute_hmac(&message, secret);

    if signature != expected_signature {
        return Err("Invalid signature");
    }

    Ok((media_id.to_string(), expires_at))
}

// ============================================================================
// File Storage Operations
// ============================================================================

/// Upload chunk state (tracks multi-chunk upload)
pub struct UploadState {
    pub media_id: String,
    pub file_path: PathBuf,
    pub file: Option<fs::File>,
    pub hasher: Sha256,
    pub total_received: usize,
    pub expected_size: Option<i64>,
}

impl UploadState {
    pub async fn new(storage_dir: &PathBuf, media_id: String) -> Result<Self> {
        // Ensure storage directory exists
        fs::create_dir_all(storage_dir).await?;

        let file_path = storage_dir.join(&media_id);
        let file = fs::File::create(&file_path).await?;

        Ok(Self {
            media_id,
            file_path,
            file: Some(file),
            hasher: Sha256::new(),
            total_received: 0,
            expected_size: None,
        })
    }

    /// Write chunk to file and update hash
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        if let Some(ref mut file) = self.file {
            file.write_all(chunk).await?;
            self.hasher.update(chunk);
            self.total_received += chunk.len();
        } else {
            anyhow::bail!("File already finalized");
        }
        Ok(())
    }

    /// Finalize upload and return hash
    pub async fn finalize(mut self) -> Result<(PathBuf, String, usize)> {
        // Close file
        if let Some(file) = self.file.take() {
            drop(file);
        }

        // Calculate final hash
        let hash = hex::encode(self.hasher.finalize());

        Ok((self.file_path, hash, self.total_received))
    }

    /// Abort upload and cleanup
    pub async fn abort(mut self) -> Result<()> {
        // Close file
        if let Some(file) = self.file.take() {
            drop(file);
        }

        // Delete partial file
        if self.file_path.exists() {
            fs::remove_file(&self.file_path).await?;
        }

        Ok(())
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
    pub async fn new(file_path: &PathBuf, chunk_size: usize) -> Result<Self> {
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

    /// Read next chunk
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

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub fn is_complete(&self) -> bool {
        self.bytes_read >= self.total_size
    }
}

// ============================================================================
// Database Operations
// ============================================================================

/// Save media metadata to database
pub async fn save_metadata(
    pool: &sqlx::PgPool,
    media_id: &str,
    size_bytes: i64,
    storage_backend: &str,
    storage_key: &str,
    file_hash: &str,
) -> Result<MediaMetadata> {
    let media_id_uuid = Uuid::parse_str(media_id)?;

    let record = sqlx::query!(
        r#"
        INSERT INTO media_files (media_id, size_bytes, storage_backend, storage_key, file_hash)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING 
            media_id,
            size_bytes,
            storage_backend,
            storage_key,
            file_hash,
            EXTRACT(EPOCH FROM created_at)::BIGINT as "created_at!",
            EXTRACT(EPOCH FROM expires_at)::BIGINT as "expires_at!"
        "#,
        media_id_uuid,
        size_bytes,
        storage_backend,
        storage_key,
        file_hash
    )
    .fetch_one(pool)
    .await?;

    Ok(MediaMetadata {
        media_id: record.media_id.to_string(),
        size_bytes: record.size_bytes,
        file_hash: record.file_hash,
        created_at: record.created_at,
        expires_at: record.expires_at,
        storage_backend: record.storage_backend,
        storage_key: record.storage_key,
    })
}

/// Get media metadata from database
pub async fn get_metadata(pool: &sqlx::PgPool, media_id: &str) -> Result<Option<MediaMetadata>> {
    let media_id_uuid = Uuid::parse_str(media_id)?;

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
pub async fn delete_media(
    pool: &sqlx::PgPool,
    storage_dir: &PathBuf,
    media_id: &str,
) -> Result<bool> {
    // Get metadata first
    let metadata = get_metadata(pool, media_id).await?;

    if let Some(meta) = metadata {
        // Delete file from storage
        let file_path = storage_dir.join(&meta.storage_key);
        if file_path.exists() {
            fs::remove_file(&file_path).await?;
        }

        // Delete metadata from database
        delete_metadata(pool, media_id).await?;

        Ok(true)
    } else {
        Ok(false)
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validate file size limits
pub fn validate_file_size(size: i64, config: &MediaConfig) -> Result<(), &'static str> {
    if size <= 0 {
        return Err("File size must be positive");
    }

    if size > config.max_file_size as i64 {
        return Err("File exceeds maximum size limit");
    }

    Ok(())
}

/// Calculate file expiration timestamp (15 days from now)
pub fn calculate_expiration() -> i64 {
    Utc::now().timestamp() + (15 * 24 * 60 * 60) // 15 days
}
