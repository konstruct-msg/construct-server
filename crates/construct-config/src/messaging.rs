// ============================================================================
// Messaging Service Configuration
// ============================================================================
//
// Centralises every tunable that was previously hard-coded in trust.rs,
// grpc.rs and stream.rs so that deployments can adjust anti-spam policy,
// PoW difficulty, and connection settings via environment variables.
//
// Environment variable prefix: MSG_
// ============================================================================

/// Anti-spam and connection policy for the messaging service.
#[derive(Clone, Debug)]
pub struct MessagingConfig {
    // ── Trust-level age thresholds ─────────────────────────────────────────
    /// Accounts younger than this many hours are classified as `New`.
    /// Default: 168.0 (7 days)
    pub trust_new_max_age_hours: f64,

    /// Accounts younger than this many hours (but older than `trust_new_max_age_hours`)
    /// are classified as `Warming`. Older accounts are `Trusted`.
    /// Default: 720.0 (30 days)
    pub trust_warming_max_age_hours: f64,

    // ── Hourly send limits ─────────────────────────────────────────────────
    /// Maximum messages per hour for New accounts. Default: 20
    pub hourly_limit_new: u32,
    /// Maximum messages per hour for Warming accounts. Default: 100
    pub hourly_limit_warming: u32,
    /// Maximum messages per hour for Trusted accounts. Default: 500
    pub hourly_limit_trusted: u32,

    // ── Daily fanout limits (unique recipients) ────────────────────────────
    /// Maximum unique recipients per day for New accounts. Default: 10
    pub fanout_limit_new: u32,
    /// Maximum unique recipients per day for Warming accounts. Default: 50
    pub fanout_limit_warming: u32,
    // Trusted accounts have no fanout limit.

    // ── Offline queue depth limits ─────────────────────────────────────────
    /// Redis stream MAXLEN applied when a New account writes to a recipient queue.
    /// Caps queue-flooding attacks from freshly-created senders. Default: 100
    pub queue_maxlen_new: i64,
    /// Redis stream MAXLEN for Warming and Trusted senders. Default: 10_000
    pub queue_maxlen_standard: i64,

    // ── PoW challenge difficulty tiers ─────────────────────────────────────
    /// PoW difficulty when counter / limit is in the range [1×, pow_ratio_mid).
    /// Default: 6
    pub pow_level_low: u32,
    /// PoW difficulty when counter / limit is in [pow_ratio_mid, pow_ratio_high).
    /// Default: 8
    pub pow_level_mid: u32,
    /// PoW difficulty when counter / limit is ≥ pow_ratio_high.
    /// Default: 10
    pub pow_level_high: u32,

    // ── PoW ratio thresholds ───────────────────────────────────────────────
    /// Counter/limit ratio at which difficulty escalates from low → mid.
    /// Default: 3.0
    pub pow_ratio_mid: f64,
    /// Counter/limit ratio at which difficulty escalates from mid → high.
    /// Default: 5.0
    pub pow_ratio_high: f64,

    // ── PoW challenge validity ─────────────────────────────────────────────
    /// Seconds a PoW challenge remains valid after issuance. Default: 60
    pub challenge_expiry_secs: u64,

    // ── Stream keepalive ───────────────────────────────────────────────────
    /// Interval in seconds between server-initiated HeartbeatAck frames sent to
    /// idle MessageStream clients. Keeps H2 streams alive through NAT/ICE proxies.
    /// Default: 30
    pub stream_heartbeat_interval_secs: u64,
}

impl MessagingConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            trust_new_max_age_hours: std::env::var("MSG_TRUST_NEW_MAX_AGE_HOURS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(168.0),

            trust_warming_max_age_hours: std::env::var("MSG_TRUST_WARMING_MAX_AGE_HOURS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(720.0),

            hourly_limit_new: std::env::var("MSG_HOURLY_LIMIT_NEW")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20),

            hourly_limit_warming: std::env::var("MSG_HOURLY_LIMIT_WARMING")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),

            hourly_limit_trusted: std::env::var("MSG_HOURLY_LIMIT_TRUSTED")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(500),

            fanout_limit_new: std::env::var("MSG_FANOUT_LIMIT_NEW")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),

            fanout_limit_warming: std::env::var("MSG_FANOUT_LIMIT_WARMING")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50),

            queue_maxlen_new: std::env::var("MSG_QUEUE_MAXLEN_NEW")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),

            queue_maxlen_standard: std::env::var("MSG_QUEUE_MAXLEN_STANDARD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10_000),

            pow_level_low: std::env::var("MSG_POW_LEVEL_LOW")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8),

            pow_level_mid: std::env::var("MSG_POW_LEVEL_MID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),

            pow_level_high: std::env::var("MSG_POW_LEVEL_HIGH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(12),

            pow_ratio_mid: std::env::var("MSG_POW_RATIO_MID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3.0),

            pow_ratio_high: std::env::var("MSG_POW_RATIO_HIGH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5.0),

            challenge_expiry_secs: std::env::var("MSG_CHALLENGE_EXPIRY_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60),

            stream_heartbeat_interval_secs: std::env::var("MSG_STREAM_HEARTBEAT_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }
}

impl Default for MessagingConfig {
    fn default() -> Self {
        Self::from_env()
    }
}
