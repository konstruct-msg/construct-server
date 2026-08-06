// ============================================================================
// Media Service Configuration
// ============================================================================

use anyhow::{Result, bail};
use std::path::PathBuf;

/// Known-insecure default that must never ship (even in "forgot to set env" deploys).
pub const INSECURE_MEDIA_HMAC_DEFAULT: &str = "change-me-in-production";

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
    /// Server bind address (health/metrics only)
    pub bind_address: String,
    /// Enable debug logging
    pub debug: bool,
    /// Max GenerateUploadToken calls per user per hour
    pub rate_limit_per_hour: u32,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./media_storage"),
            max_file_size: 100 * 1024 * 1024,   // 100MB
            file_ttl_seconds: 7 * 24 * 60 * 60, // 7 days
            // Empty — callers must load via from_env() which rejects insecure values.
            hmac_secret: String::new(),
            bind_address: "0.0.0.0:8082".to_string(),
            debug: false,
            rate_limit_per_hour: 50,
        }
    }
}

impl MediaConfig {
    /// Load configuration from environment variables.
    ///
    /// Fails hard if the upload HMAC secret is missing or is the known insecure default.
    /// Media is an open write surface once a token is forged — silent defaults are unacceptable.
    pub fn from_env() -> Result<Self> {
        let hmac_secret = std::env::var("MEDIA_UPLOAD_TOKEN_SECRET")
            .or_else(|_| std::env::var("MEDIA_HMAC_SECRET"))
            .unwrap_or_default();

        validate_hmac_secret(&hmac_secret)?;

        Ok(Self {
            storage_dir: std::env::var("MEDIA_STORAGE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./media_storage")),
            max_file_size: std::env::var("MEDIA_MAX_FILE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100 * 1024 * 1024),
            file_ttl_seconds: std::env::var("MEDIA_FILE_TTL_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(7 * 24 * 60 * 60),
            hmac_secret,
            bind_address: std::env::var("MEDIA_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0:8082".to_string()),
            debug: std::env::var("MEDIA_DEBUG")
                .map(|s| s == "true")
                .unwrap_or(false),
            rate_limit_per_hour: std::env::var("MEDIA_RATE_LIMIT_PER_HOUR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50),
        })
    }
}

/// Reject empty / default / too-short media HMAC secrets.
pub fn validate_hmac_secret(secret: &str) -> Result<()> {
    let t = secret.trim();
    if t.is_empty() {
        bail!(
            "MEDIA_UPLOAD_TOKEN_SECRET (or MEDIA_HMAC_SECRET) is required. \
             Generate with: openssl rand -hex 32"
        );
    }
    if t == INSECURE_MEDIA_HMAC_DEFAULT {
        bail!(
            "MEDIA_UPLOAD_TOKEN_SECRET is set to the insecure default \
             '{INSECURE_MEDIA_HMAC_DEFAULT}'. Generate a real secret: openssl rand -hex 32"
        );
    }
    // 32 chars minimum (hex-32 = 64 is ideal; accept any ≥32 entropy-bearing string)
    if t.len() < 32 {
        bail!(
            "MEDIA_UPLOAD_TOKEN_SECRET must be at least 32 characters (got {}). \
             Generate with: openssl rand -hex 32",
            t.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_default_secret() {
        assert!(validate_hmac_secret("").is_err());
        assert!(validate_hmac_secret(INSECURE_MEDIA_HMAC_DEFAULT).is_err());
        assert!(validate_hmac_secret("short").is_err());
        assert!(validate_hmac_secret(&"a".repeat(32)).is_ok());
    }
}
