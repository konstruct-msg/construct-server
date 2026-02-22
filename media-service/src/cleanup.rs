// ============================================================================
// Media Service Cleanup
// ============================================================================

use super::config::MediaConfig;
use std::sync::Arc;
use tokio::fs;
use tokio::time::{self, Duration};
use tracing::{error, info, warn};

/// Cleanup expired media files
pub async fn cleanup_expired_files(config: Arc<MediaConfig>) {
    let mut interval = time::interval(Duration::from_secs(3600)); // Run every hour

    loop {
        interval.tick().await;

        if let Err(e) = cleanup_once(&config).await {
            error!(error = %e, "Failed to cleanup expired media files");
        }
    }
}

/// Single cleanup run
async fn cleanup_once(
    config: &MediaConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut deleted_count = 0;
    let mut error_count = 0;

    // Get current time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // Read directory
    let mut entries = fs::read_dir(&config.storage_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        // Skip directories
        if !path.is_file() {
            continue;
        }

        // Get file metadata
        let metadata = match fs::metadata(&path).await {
            Ok(m) => m,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to get file metadata");
                error_count += 1;
                continue;
            }
        };

        // Check modification time
        let modified = match metadata.modified()?.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to get file modification time");
                error_count += 1;
                continue;
            }
        };

        // Check if file is expired
        let age_seconds = now.saturating_sub(modified);
        if age_seconds > config.file_ttl_seconds {
            // Delete expired file
            match fs::remove_file(&path).await {
                Ok(_) => {
                    deleted_count += 1;
                    if config.debug {
                        info!(path = %path.display(), age_seconds = age_seconds, "Deleted expired media file");
                    }
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to delete expired media file");
                    error_count += 1;
                }
            }
        }
    }

    if deleted_count > 0 || error_count > 0 {
        info!(
            deleted_count = deleted_count,
            error_count = error_count,
            "Media cleanup completed"
        );
    }

    Ok(())
}
