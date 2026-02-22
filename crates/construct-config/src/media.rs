// ============================================================================
// Media Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Media server configuration
#[derive(Clone, Debug)]
pub struct MediaConfig {
    /// Whether media uploads are enabled
    pub enabled: bool,
    /// Media server base URL (e.g., "https://media.example.com")
    pub base_url: String,
    /// Shared secret for generating upload tokens (must match MEDIA_UPLOAD_TOKEN_SECRET on media-server)
    pub upload_token_secret: String,
    /// Maximum file size in bytes (default: 100MB)
    pub max_file_size: usize,
    /// Rate limit: uploads per hour per user
    pub rate_limit_per_hour: u32,
}

impl MediaConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            enabled: std::env::var("MEDIA_ENABLED")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
            base_url: std::env::var("MEDIA_BASE_URL").unwrap_or_else(|_| "".to_string()),
            upload_token_secret: std::env::var("MEDIA_UPLOAD_TOKEN_SECRET")
                .unwrap_or_else(|_| "".to_string()),
            max_file_size: std::env::var("MEDIA_MAX_FILE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100 * 1024 * 1024), // 100MB
            rate_limit_per_hour: std::env::var("MEDIA_RATE_LIMIT_PER_HOUR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50),
        }
    }
}
