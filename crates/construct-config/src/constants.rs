// ============================================================================
// Configuration Constants
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

// Default port values
pub(crate) const DEFAULT_PORT: u16 = 8080;
pub(crate) const DEFAULT_HEALTH_PORT: u16 = 8081;

// Default time intervals (in seconds)
// OPTIMIZED: Increased default heartbeat interval from 90s to 180s to reduce Redis commands
pub(crate) const DEFAULT_HEARTBEAT_INTERVAL_SECS: i64 = 180;
pub(crate) const DEFAULT_SERVER_REGISTRY_TTL_SECS: i64 = 270;

// Default TTL values
pub(crate) const DEFAULT_MESSAGE_TTL_DAYS: i64 = 7;
// Access token TTL: 168 hours (1 week) for better UX in messenger apps
pub(crate) const DEFAULT_ACCESS_TOKEN_TTL_HOURS: i64 = 168;
// Session TTL: kept for backward compatibility, but access tokens now use shorter TTL
pub(crate) const DEFAULT_SESSION_TTL_DAYS: i64 = 30;
// Refresh token TTL: 90 days (long-lived for user convenience)
pub(crate) const DEFAULT_REFRESH_TOKEN_TTL_DAYS: i64 = 90;

// Default polling interval (in milliseconds)
// OPTIMIZED: Increased default polling interval from 10s to 30s to reduce Redis commands
// This reduces Redis command usage by ~66% while maintaining acceptable latency for real-time messaging
// OPTIMIZED: Increased from 30s to 60s to reduce Redis commands by 50%
pub(crate) const DEFAULT_DELIVERY_POLL_INTERVAL_MS: u64 = 60000;

// Time conversion constants
pub const SECONDS_PER_MINUTE: i64 = 60;
pub const SECONDS_PER_HOUR: i64 = 3600;
pub const SECONDS_PER_DAY: i64 = 86400;

// Message size limits (in bytes)
// ============================================================================
// ВАЖНО: Разные лимиты для разных типов контента
//
// WebSocket сообщения (текст + метаданные):
// - 64 KB достаточно для ~32K символов UTF-8 + криптографические метаданные
// - Больший размер указывает на атаку или медиафайлы (которые идут через CDN)
//
// HTTP запросы:
// - 2 MB для API endpoints (key bundles, etc.)
// - Медиафайлы загружаются отдельно на CDN (до 100 MB)
// ============================================================================
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64 KB - Message size limit
pub const MAX_REQUEST_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB - HTTP API requests
pub const MAX_MEDIA_FILE_SIZE: usize = 100 * 1024 * 1024; // 100 MB - Media files on CDN
