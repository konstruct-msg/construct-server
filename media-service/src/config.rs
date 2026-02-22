// ============================================================================
// Media Service Configuration
// ============================================================================

use std::path::PathBuf;

/// Media service configuration
#[derive(Clone)]
pub struct MediaConfig {
    /// Directory to store media files
    pub storage_dir: PathBuf,
    /// Maximum file size in bytes
    pub max_file_size: usize,
    /// File TTL in seconds (default: 7 days)
    pub file_ttl_seconds: u64,
    /// HMAC secret for token validation
    pub hmac_secret: String,
    /// Server bind address
    pub bind_address: String,
    /// Enable debug logging
    pub debug: bool,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./media_storage"),
            max_file_size: 100 * 1024 * 1024, // 100MB (unified with messaging-service)
            file_ttl_seconds: 7 * 24 * 60 * 60, // 7 days
            hmac_secret: "change-me-in-production".to_string(),
            bind_address: "0.0.0.0:8082".to_string(),
            debug: false,
        }
    }
}

impl MediaConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            storage_dir: std::env::var("MEDIA_STORAGE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./media_storage")),
            max_file_size: std::env::var("MEDIA_MAX_FILE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100 * 1024 * 1024), // 100MB (unified with messaging-service)
            file_ttl_seconds: std::env::var("MEDIA_FILE_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7 * 24 * 60 * 60), // 7 days
            hmac_secret: std::env::var("MEDIA_UPLOAD_TOKEN_SECRET")
                .or_else(|_| std::env::var("MEDIA_HMAC_SECRET"))
                .unwrap_or_else(|_| "change-me-in-production".to_string()),
            bind_address: std::env::var("MEDIA_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0:8082".to_string()),
            debug: std::env::var("MEDIA_DEBUG")
                .map(|s| s == "true")
                .unwrap_or(false),
        }
    }
}
