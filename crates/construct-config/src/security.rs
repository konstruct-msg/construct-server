// ============================================================================
// Security Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Security and rate limiting policies
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    pub prekey_ttl_days: i64,
    #[allow(dead_code)]
    pub prekey_min_ttl_days: i64,
    #[allow(dead_code)]
    pub prekey_max_ttl_days: i64,
    pub max_messages_per_hour: u32,
    /// Maximum messages per IP address per hour (protects against distributed attacks)
    pub max_messages_per_ip_per_hour: u32,
    pub max_key_rotations_per_day: u32,
    pub max_password_changes_per_day: u32,
    pub max_failed_login_attempts: u32,
    #[allow(dead_code)]
    pub max_connections_per_user: u32,
    pub key_bundle_cache_hours: i64,
    pub rate_limit_block_duration_seconds: i64,
    /// Whether IP-based rate limiting is enabled for anonymous operations
    pub ip_rate_limiting_enabled: bool,
    /// Maximum requests per IP per hour (for anonymous operations: login, registration, etc.)
    pub max_requests_per_ip_per_hour: u32,
    /// Whether combined (user_id + IP) rate limiting is enabled for authenticated operations
    pub combined_rate_limiting_enabled: bool,
    /// Maximum requests per user+IP combination per hour (for authenticated operations)
    /// This is typically lower than IP-only limit for stricter control
    pub max_requests_per_user_ip_per_hour: u32,
    /// Maximum long-polling (GET /messages) requests per user per window
    /// Default: 100 requests per minute (allows normal long-polling with reconnects)
    pub max_long_poll_requests_per_window: u32,
    /// Long-polling rate limit window in seconds (default: 60)
    pub long_poll_rate_limit_window_secs: i64,
    /// Whether request signing is required for critical operations (key upload, account deletion)
    pub request_signing_required: bool,
    /// Metrics endpoint protection
    pub metrics_auth_enabled: bool,
    /// IP whitelist for /metrics endpoint (comma-separated)
    /// If empty, only Bearer token auth is used (if enabled)
    pub metrics_ip_whitelist: Vec<String>,
    /// Bearer token for /metrics endpoint (optional, for Prometheus scraping)
    /// If empty, only IP whitelist is used (if enabled)
    pub metrics_bearer_token: Option<String>,
    /// Maximum PoW challenges per IP per hour (anti-spam for registration)
    /// Default: 10 (allows multiple device registration attempts)
    /// Set to 0 to disable rate limiting (for testing)
    pub max_pow_challenges_per_hour: u32,
    /// Maximum device registrations per IP per hour (anti-spam)
    /// Default: 5 (allows registering multiple devices per hour)
    /// Set to 0 to disable rate limiting (for testing)
    pub max_registrations_per_hour: u32,
    /// PoW difficulty (number of leading zero bits required)
    /// Default: 8 (production), set to 1-2 for fast tests
    pub pow_difficulty: u32,
}

impl SecurityConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            prekey_ttl_days: std::env::var("PREKEY_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(30),
            prekey_min_ttl_days: std::env::var("PREKEY_MIN_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(7),
            prekey_max_ttl_days: std::env::var("PREKEY_MAX_TTL_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(90),
            max_messages_per_hour: std::env::var("MAX_MESSAGES_PER_HOUR")
                .ok()
                .and_then(|m| m.parse().ok())
                .unwrap_or(1000),
            max_messages_per_ip_per_hour: std::env::var("MAX_MESSAGES_PER_IP_PER_HOUR")
                .ok()
                .and_then(|m| m.parse().ok())
                .unwrap_or(5000), // Higher limit for IP (shared IPs, NAT, etc.)
            max_key_rotations_per_day: std::env::var("MAX_KEY_ROTATIONS_PER_DAY")
                .ok()
                .and_then(|k| k.parse().ok())
                .unwrap_or(10),
            max_password_changes_per_day: std::env::var("MAX_PASSWORD_CHANGES_PER_DAY")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(5),
            max_failed_login_attempts: std::env::var("MAX_FAILED_LOGIN_ATTEMPTS")
                .ok()
                .and_then(|f| f.parse().ok())
                .unwrap_or(5),
            max_connections_per_user: std::env::var("MAX_CONNECTIONS_PER_USER")
                .ok()
                .and_then(|c| c.parse().ok())
                .unwrap_or(5),
            key_bundle_cache_hours: std::env::var("KEY_BUNDLE_CACHE_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(1),
            rate_limit_block_duration_seconds: std::env::var("RATE_LIMIT_BLOCK_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            // IP-based rate limiting for anonymous operations
            ip_rate_limiting_enabled: std::env::var("IP_RATE_LIMITING_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true), // Enabled by default
            max_requests_per_ip_per_hour: std::env::var("MAX_REQUESTS_PER_IP_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000), // 1000 requests/hour per IP for anonymous operations
            // Combined (user_id + IP) rate limiting for authenticated operations
            combined_rate_limiting_enabled: std::env::var("COMBINED_RATE_LIMITING_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true), // Enabled by default
            max_requests_per_user_ip_per_hour: std::env::var("MAX_REQUESTS_PER_USER_IP_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500), // 500 requests/hour per user+IP (stricter than IP-only)
            // Long-polling rate limiting (GET /messages)
            max_long_poll_requests_per_window: std::env::var("MAX_LONG_POLL_REQUESTS_PER_WINDOW")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100), // 100 requests per window (default: per minute)
            long_poll_rate_limit_window_secs: std::env::var("LONG_POLL_RATE_LIMIT_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60), // 60 seconds window by default
            // Request signing for critical operations (like Signal)
            request_signing_required: std::env::var("REQUEST_SIGNING_REQUIRED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false), // Disabled by default (can be enabled for production)
            // Metrics endpoint protection
            metrics_auth_enabled: std::env::var("METRICS_AUTH_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false), // Disabled by default (metrics are public)
            metrics_ip_whitelist: std::env::var("METRICS_IP_WHITELIST")
                .ok()
                .map(|s| {
                    s.split(',')
                        .map(|ip| ip.trim().to_string())
                        .filter(|ip| !ip.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            metrics_bearer_token: std::env::var("METRICS_BEARER_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            // PoW challenge rate limiting (anti-spam for registration)
            max_pow_challenges_per_hour: std::env::var("MAX_POW_CHALLENGES_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10), // 10 challenges/hour by default (allows multiple device attempts)
            // Device registration rate limiting (anti-spam)
            max_registrations_per_hour: std::env::var("MAX_REGISTRATIONS_PER_HOUR")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5), // 5 registrations/hour by default (multiple devices per user)
            // PoW difficulty (default: 8 for production, set to 1-2 for tests)
            pow_difficulty: std::env::var("POW_DIFFICULTY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8), // 8 leading zeros by default (3-5 seconds to solve)
        }
    }
}

/// CSRF (Cross-Site Request Forgery) protection configuration
#[derive(Clone, Debug)]
pub struct CsrfConfig {
    /// Whether CSRF protection is enabled (default: true)
    pub enabled: bool,
    /// Secret key for CSRF token generation (HMAC-SHA256)
    /// Must be at least 32 characters for security
    pub secret: String,
    /// Token TTL in seconds (default: 3600 = 1 hour)
    pub token_ttl_secs: u64,
    /// Allowed origins for CORS/CSRF validation
    /// Empty = allow same-origin only
    pub allowed_origins: Vec<String>,
    /// Cookie name for CSRF token (default: "csrf_token")
    pub cookie_name: String,
    /// Header name for CSRF token (default: "X-CSRF-Token")
    pub header_name: String,
}

impl CsrfConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        // Check if we're in production
        // Production indicators (any of these means production):
        // 1. ENVIRONMENT is set and not "development"/"dev"/"local"
        // 2. FLY_APP_NAME is set (Fly.io always sets this)
        // 3. FLY_REGION is set (Fly.io always sets this)
        // 4. RAILWAY_ENVIRONMENT is set and not "development"
        // 5. Explicit PRODUCTION=true
        let is_production = std::env::var("PRODUCTION")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or_else(|_| {
                // Check various production indicators
                std::env::var("ENVIRONMENT")
                    .map(|v| {
                        let env_lower = v.to_lowercase();
                        env_lower != "development" && env_lower != "dev" && env_lower != "local"
                    })
                    .or_else(|_| {
                        // Fly.io always sets FLY_APP_NAME and FLY_REGION
                        if std::env::var("FLY_APP_NAME").is_ok()
                            || std::env::var("FLY_REGION").is_ok()
                        {
                            Ok(true)
                        } else {
                            std::env::var("RAILWAY_ENVIRONMENT")
                                .map(|v| v.to_lowercase() != "development")
                        }
                    })
                    .unwrap_or(false)
            });

        let enabled = std::env::var("CSRF_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true); // Enabled by default for security

        let secret = match std::env::var("CSRF_SECRET") {
            Ok(s) if s.len() >= 32 => s,
            Ok(s) => {
                anyhow::bail!(
                    "CSRF_SECRET must be at least 32 characters long (got {}). \
                    Generate with: openssl rand -hex 32",
                    s.len()
                );
            }
            Err(_) if is_production && enabled => {
                anyhow::bail!(
                    "CSRF_SECRET is REQUIRED in production when CSRF is enabled. \
                    Generate with: openssl rand -hex 32. \
                    Set it via: fly secrets set CSRF_SECRET=\"$(openssl rand -hex 32)\" -a <app-name>"
                );
            }
            Err(_) => {
                // Development only: generate random secret with warning
                tracing::warn!(
                    "CSRF_SECRET not set - using random secret. \
                    This means CSRF tokens will be invalidated on restart. \
                    Set CSRF_SECRET in production!"
                );
                use rand::Rng;
                let mut rng = rand::thread_rng();
                (0..32)
                    .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                    .collect()
            }
        };

        Ok(Self {
            enabled,
            secret,
            token_ttl_secs: std::env::var("CSRF_TOKEN_TTL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600), // 1 hour default
            allowed_origins: std::env::var("CSRF_ALLOWED_ORIGINS")
                .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
                .unwrap_or_default(),
            cookie_name: std::env::var("CSRF_COOKIE_NAME")
                .unwrap_or_else(|_| "csrf_token".to_string()),
            header_name: std::env::var("CSRF_HEADER_NAME")
                .unwrap_or_else(|_| "X-CSRF-Token".to_string()),
        })
    }
}
