// ============================================================================
// SentinelService — Core Business Logic
// ============================================================================
//
// All analysis is metadata-only. Server is blind to E2E message content.
//
// Trust levels (device-based, not user-based):
//   NEW      (0–48 h)   — strict limits
//   WARMING  (48 h–7 d) — moderate limits
//   TRUSTED  (7 d+)     — normal limits
//   FLAGGED             — suspicious patterns; minimal limits + review
//   BANNED              — no sends permitted
//
// Redis key schema:
//   sentinel:ban:{device_id}              → "1" (TTL matches ban_expires_at)
//   sentinel:flag:{device_id}             → "1" (TTL 7d)
//   sentinel:reports:{device_id}          → counter (TTL = 7 days)
//   sentinel:rate:msg:{device_id}         → counter (TTL = 3600s, hourly window)
//   sentinel:rate:rcpt:{device_id}        → counter (TTL = 86400s, daily window)
//   sentinel:blocks:{blocker}             → SET of blocked device_ids (TTL 300s)
//   sentinel:rate:report:{device_id}      → counter (TTL = 86400s, daily window)
//   sentinel:violations:24h               → counter (TTL = 86400s)
//   sentinel:dispute:{device_id}:{id}     → dispute metadata cache
// ============================================================================

use anyhow::Result;
use redis::AsyncCommands;
use sqlx::PgPool;
use tracing::{info, warn};

// ─── Constants ───────────────────────────────────────────────────────────────

const REPORTS_KEY_TTL: u64 = 7 * 24 * 3600; // 7 days
const BAN_FLAG_TTL: u64 = 7 * 24 * 3600; // 7 days fallback
const BLOCKS_CACHE_TTL: i64 = 300; // 5 minutes
const REPORT_RATE_LIMIT: i64 = 10; // max reports per reporter per day
const REPORTS_WINDOW_TTL: u64 = 24 * 3600; // 24 hours

/// Thresholds for automatic escalation.
const AUTO_FLAG_REPORTS: i64 = 3;
const AUTO_BAN_REPORTS: i64 = 5;
/// Minimum unique reporters before auto-escalation (botnet protection).
const MIN_UNIQUE_REPORTERS_FOR_FLAG: usize = 2;
const MIN_UNIQUE_REPORTERS_FOR_BAN: usize = 3;

// ─── Rate limits per trust level ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    New,
    Warming,
    Trusted,
    Flagged,
    Banned,
}

impl TrustLevel {
    pub fn msg_limit_hour(&self) -> i32 {
        match self {
            Self::New => 10,
            Self::Warming => 50,
            Self::Trusted => 200,
            Self::Flagged => 5,
            Self::Banned => 0,
        }
    }

    pub fn recipient_limit_day(&self) -> i32 {
        match self {
            Self::New => 3,
            Self::Warming => 10,
            Self::Trusted => 50,
            Self::Flagged => 1,
            Self::Banned => 0,
        }
    }

    pub fn group_msg_limit_day(&self) -> i32 {
        match self {
            Self::New => 0,
            Self::Warming => 20,
            Self::Trusted => 100,
            Self::Flagged => 0,
            Self::Banned => 0,
        }
    }
}

// ─── Core struct ─────────────────────────────────────────────────────────────

pub struct SentinelCore {
    pub db: PgPool,
    pub redis: redis::Client,
}

// ─── Return types ────────────────────────────────────────────────────────────

pub struct SendPermission {
    pub allowed: bool,
    pub denial_reason: String,
    pub retry_after_seconds: i32,
}

pub struct ProtectionStats {
    pub spam_reports_24h: i64,
    pub devices_flagged_24h: i64,
    pub devices_banned_7d: i64,
    pub rate_limit_violations_24h: i64,
    pub blocks_created_24h: i64,
    pub appeals_pending: i64,
}

pub struct DisputeEvidence {
    pub id: String,
    #[allow(dead_code)]
    pub device_id: String,
    pub restriction_type: String,
    pub status: String,
    pub evidence_text: String,
    pub created_at: String,
}

pub struct AppealInfo {
    pub id: String,
    #[allow(dead_code)]
    pub device_id: String,
    pub restriction_type: String,
    pub context: String,
    pub status: String,
    pub created_at: String,
    pub reviewed_at: Option<String>,
}

// ─── Implementation ──────────────────────────────────────────────────────────

impl SentinelCore {
    pub async fn new(database_url: &str, redis_url: &str) -> Result<Self> {
        let db = PgPool::connect(database_url).await?;
        let redis = redis::Client::open(redis_url)?;
        Ok(Self { db, redis })
    }

    async fn redis(&self) -> Result<redis::aio::ConnectionManager> {
        Ok(redis::aio::ConnectionManager::new(self.redis.clone()).await?)
    }

    // ── Trust level ───────────────────────────────────────────────────────────

    pub async fn trust_level(&self, device_id: &str) -> Result<TrustLevel> {
        let mut conn = self.redis().await?;

        // Fast path: ban/flag cached in Redis
        let ban_key = format!("sentinel:ban:{}", device_id);
        let flag_key = format!("sentinel:flag:{}", device_id);

        let is_banned: bool = conn.exists(&ban_key).await?;
        if is_banned {
            return Ok(TrustLevel::Banned);
        }

        let is_flagged: bool = conn.exists(&flag_key).await?;
        if is_flagged {
            return Ok(TrustLevel::Flagged);
        }

        // Check DB for permanent bans/flags (with ban_expires_at support)
        let flag_row = sqlx::query!(
            r#"SELECT is_banned, ban_expires_at AS "ban_expires_at: chrono::DateTime<chrono::Utc>",
                      is_flagged, flagged_at AS "flagged_at: chrono::DateTime<chrono::Utc>"
               FROM device_flags WHERE device_id = $1"#,
            device_id
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = flag_row {
            if row.is_banned {
                // Check if temporary ban has expired
                if let Some(expires_at) = row.ban_expires_at {
                    if chrono::Utc::now() > expires_at {
                        // Ban expired — clear it
                        self.clear_ban(device_id).await?;
                        return self.age_based_level(device_id).await;
                    }
                    // Temp ban still active — set TTL in Redis
                    let remaining = (expires_at - chrono::Utc::now()).num_seconds().max(1);
                    let _: () = conn.set_ex(&ban_key, "1", remaining as u64).await?;
                } else {
                    // Permanent ban — set without TTL (re-check in 7d)
                    let _: () = conn.set_ex(&ban_key, "1", BAN_FLAG_TTL).await?;
                }
                return Ok(TrustLevel::Banned);
            }
            if row.is_flagged {
                let _: () = conn.set_ex(&flag_key, "1", BAN_FLAG_TTL).await?;
                return Ok(TrustLevel::Flagged);
            }
        }

        self.age_based_level(device_id).await
    }

    async fn age_based_level(&self, device_id: &str) -> Result<TrustLevel> {
        let created = sqlx::query_scalar!(
            r#"SELECT registered_at AS "registered_at: chrono::DateTime<chrono::Utc>" FROM devices WHERE device_id = $1"#,
            device_id
        )
        .fetch_optional(&self.db)
        .await?;

        let age_hours: i64 = match created {
            None => return Ok(TrustLevel::New), // unknown device = treat as new
            Some(ts) => (chrono::Utc::now() - ts).num_hours(),
        };

        Ok(match age_hours {
            h if h < 48 => TrustLevel::New,
            h if h < 168 => TrustLevel::Warming,
            _ => TrustLevel::Trusted,
        })
    }

    // ── Rate limits ───────────────────────────────────────────────────────────

    pub async fn msg_quota(&self, device_id: &str, trust: TrustLevel) -> Result<(i32, i32)> {
        let limit = trust.msg_limit_hour();
        if limit <= 0 {
            return Ok((0, limit));
        }

        let mut conn = self.redis().await?;
        let key = format!("sentinel:rate:msg:{}", device_id);
        let used: i32 = conn.get(&key).await.unwrap_or(0);

        Ok(((limit - used).max(0), limit))
    }

    pub async fn recipient_quota(&self, device_id: &str, trust: TrustLevel) -> Result<(i32, i32)> {
        let limit = trust.recipient_limit_day();
        if limit <= 0 {
            return Ok((0, limit));
        }

        let mut conn = self.redis().await?;
        let key = format!("sentinel:rate:rcpt:{}", device_id);
        let used: i32 = conn.get(&key).await.unwrap_or(0);

        Ok(((limit - used).max(0), limit))
    }

    /// Increment rate-limit violation counter for stats.
    async fn record_violation(&self) {
        if let Ok(mut conn) = self.redis().await {
            let _: Result<(), _> = conn.incr("sentinel:violations:24h", 1i64).await;
            let _: Result<(), _> = conn
                .expire("sentinel:violations:24h", REPORTS_WINDOW_TTL as i64)
                .await;
        }
    }

    // ── CheckSendPermission (hot path) ────────────────────────────────────────

    pub async fn check_send_permission(
        &self,
        caller_device_id: &str,
        target_device_id: &str,
    ) -> Result<SendPermission> {
        let trust = self.trust_level(caller_device_id).await?;

        if trust == TrustLevel::Banned {
            self.record_violation().await;
            return Ok(SendPermission {
                allowed: false,
                denial_reason: "Device is banned".into(),
                retry_after_seconds: 0,
            });
        }

        // Check if target has server-blocked the caller (Redis-cached)
        let blocked = self.is_blocked(target_device_id, caller_device_id).await?;
        if blocked {
            self.record_violation().await;
            return Ok(SendPermission {
                allowed: false,
                denial_reason: "Recipient has blocked this device".into(),
                retry_after_seconds: 0,
            });
        }

        // Check hourly message rate
        let (remaining, _) = self.msg_quota(caller_device_id, trust).await?;
        if remaining == 0 {
            self.record_violation().await;
            return Ok(SendPermission {
                allowed: false,
                denial_reason: "Hourly message limit reached".into(),
                retry_after_seconds: 3600,
            });
        }

        Ok(SendPermission {
            allowed: true,
            denial_reason: String::new(),
            retry_after_seconds: 0,
        })
    }

    // ── Block / Unblock (with Redis cache) ────────────────────────────────────

    /// Returns true if `blocker` has blocked `target`. Uses Redis cache.
    pub async fn is_blocked(&self, blocker: &str, target: &str) -> Result<bool> {
        let mut conn = self.redis().await?;
        let cache_key = format!("sentinel:blocks:{}", blocker);

        // Try Redis cache first
        let cached: bool = conn.sismember(&cache_key, target).await.unwrap_or(false);
        if cached {
            return Ok(true);
        }

        // Check if cache exists at all (empty set is valid — means "checked, nothing blocked")
        let cache_exists: bool = conn.exists(&cache_key).await?;
        if cache_exists {
            return Ok(false);
        }

        // Cache miss — load from DB
        let rows = sqlx::query_scalar!(
            "SELECT blocked_device_id FROM device_blocks WHERE blocker_device_id = $1",
            blocker
        )
        .fetch_all(&self.db)
        .await?;

        if !rows.is_empty() {
            let targets: Vec<&str> = rows.iter().map(|s| s.as_str()).collect();
            let _: () = conn.sadd(&cache_key, &targets).await?;
        }
        // Set TTL even for empty set (marks "checked")
        let _: () = conn.expire(&cache_key, BLOCKS_CACHE_TTL).await?;

        Ok(rows.iter().any(|r| r == target))
    }

    /// Invalidate block cache for a blocker after block/unblock operations.
    async fn invalidate_block_cache(&self, blocker: &str) {
        if let Ok(mut conn) = self.redis().await {
            let cache_key = format!("sentinel:blocks:{}", blocker);
            let _: Result<(), _> = conn.del(&cache_key).await;
        }
    }

    pub async fn block_device(&self, blocker: &str, blocked: &str) -> Result<()> {
        sqlx::query!(
            "INSERT INTO device_blocks (blocker_device_id, blocked_device_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            blocker,
            blocked
        )
        .execute(&self.db)
        .await?;
        self.invalidate_block_cache(blocker).await;
        info!(blocker, blocked, "device blocked");
        Ok(())
    }

    pub async fn unblock_device(&self, blocker: &str, blocked: &str) -> Result<()> {
        sqlx::query!(
            "DELETE FROM device_blocks
             WHERE blocker_device_id = $1 AND blocked_device_id = $2",
            blocker,
            blocked
        )
        .execute(&self.db)
        .await?;
        self.invalidate_block_cache(blocker).await;
        Ok(())
    }

    pub async fn get_blocked_devices(
        &self,
        blocker: &str,
        page: i32,
        page_size: i32,
    ) -> Result<(Vec<String>, bool)> {
        let limit = page_size.clamp(1, 100) as i64;
        let offset = (page.max(0) as i64) * limit;

        let rows = sqlx::query_scalar!(
            "SELECT blocked_device_id FROM device_blocks
             WHERE blocker_device_id = $1
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3",
            blocker,
            limit + 1,
            offset
        )
        .fetch_all(&self.db)
        .await?;

        let has_more = rows.len() as i64 > limit;
        let results = rows.into_iter().take(limit as usize).collect();
        Ok((results, has_more))
    }

    // ── Spam reports (with botnet protection) ─────────────────────────────────

    pub async fn report_spam(
        &self,
        reporter: &str,
        reported: &str,
        category: &str,
    ) -> Result<String> {
        // Rate-limit reports from this reporter
        let mut conn = self.redis().await?;
        let rate_key = format!("sentinel:rate:report:{}", reporter);
        let report_count: i64 = conn.incr(&rate_key, 1i64).await?;
        if report_count == 1 {
            let _: () = conn.expire(&rate_key, REPORTS_WINDOW_TTL as i64).await?;
        }
        if report_count > REPORT_RATE_LIMIT {
            return Err(anyhow::anyhow!("Report rate limit exceeded"));
        }

        // Persist report
        let report_id = sqlx::query_scalar!(
            "INSERT INTO spam_reports (reporter_device_id, reported_device_id, category)
             VALUES ($1, $2, $3)
             RETURNING id",
            reporter,
            reported,
            category
        )
        .fetch_one(&self.db)
        .await?;

        // Increment Redis counter with TTL
        let reports_key = format!("sentinel:reports:{}", reported);
        let total: i64 = conn.incr(&reports_key, 1i64).await?;
        if total == 1 {
            let _: () = conn.expire(&reports_key, REPORTS_KEY_TTL as i64).await?;
        }

        // Track unique reporters (for botnet protection)
        let unique_key = format!("sentinel:reporters:{}", reported);
        let _: () = conn.sadd(&unique_key, reporter).await?;
        if total == 1 {
            let _: () = conn.expire(&unique_key, REPORTS_KEY_TTL as i64).await?;
        }
        let unique_count: usize = conn.scard(&unique_key).await?;

        // Auto-escalation with botnet protection
        if total >= AUTO_BAN_REPORTS && unique_count >= MIN_UNIQUE_REPORTERS_FOR_BAN {
            self.set_banned(
                reported,
                "Automatic ban: 5+ spam reports from unique reporters",
            )
            .await?;
            warn!(reported, total, unique_count, "device auto-banned");
        } else if total >= AUTO_FLAG_REPORTS && unique_count >= MIN_UNIQUE_REPORTERS_FOR_FLAG {
            self.set_flagged(reported).await?;
            warn!(reported, total, unique_count, "device auto-flagged");
        }

        Ok(report_id.to_string())
    }

    // ── Flag / Ban / Clear ────────────────────────────────────────────────────

    async fn set_flagged(&self, device_id: &str) -> Result<()> {
        let mut conn = self.redis().await?;
        let flag_key = format!("sentinel:flag:{}", device_id);
        let _: () = conn.set_ex(&flag_key, "1", BAN_FLAG_TTL).await?;

        sqlx::query!(
            "INSERT INTO device_flags (device_id, is_flagged, flagged_at)
             VALUES ($1, TRUE, NOW())
             ON CONFLICT (device_id) DO UPDATE
             SET is_flagged = TRUE, flagged_at = NOW(), updated_at = NOW()",
            device_id
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn set_banned(&self, device_id: &str, reason: &str) -> Result<()> {
        let mut conn = self.redis().await?;
        let ban_key = format!("sentinel:ban:{}", device_id);
        let _: () = conn.set_ex(&ban_key, "1", BAN_FLAG_TTL).await?;

        sqlx::query!(
            "INSERT INTO device_flags (device_id, is_banned, ban_reason, banned_at)
             VALUES ($1, TRUE, $2, NOW())
             ON CONFLICT (device_id) DO UPDATE
             SET is_banned = TRUE, ban_reason = $2, banned_at = NOW(), updated_at = NOW()",
            device_id,
            reason
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn clear_ban(&self, device_id: &str) -> Result<()> {
        let mut conn = self.redis().await?;
        let ban_key = format!("sentinel:ban:{}", device_id);
        let _: () = conn.del(&ban_key).await?;

        sqlx::query!(
            "UPDATE device_flags SET is_banned = FALSE, ban_reason = NULL, ban_expires_at = NULL, updated_at = NOW()
             WHERE device_id = $1",
            device_id
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn clear_flag(&self, device_id: &str) -> Result<()> {
        let mut conn = self.redis().await?;
        let flag_key = format!("sentinel:flag:{}", device_id);
        let _: () = conn.del(&flag_key).await?;

        sqlx::query!(
            "UPDATE device_flags SET is_flagged = FALSE, updated_at = NOW()
             WHERE device_id = $1",
            device_id
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    // ── Appeals ───────────────────────────────────────────────────────────────

    pub async fn submit_appeal(
        &self,
        device_id: &str,
        restriction_type: &str,
        context: &str,
    ) -> Result<String> {
        // Check if device actually has an active restriction
        let has_restriction = match restriction_type {
            "banned" => {
                let row = sqlx::query_scalar!(
                    "SELECT is_banned FROM device_flags WHERE device_id = $1",
                    device_id
                )
                .fetch_optional(&self.db)
                .await?;
                row.unwrap_or(false)
            }
            "flagged" => {
                let row = sqlx::query_scalar!(
                    "SELECT is_flagged FROM device_flags WHERE device_id = $1",
                    device_id
                )
                .fetch_optional(&self.db)
                .await?;
                row.unwrap_or(false)
            }
            _ => true, // rate-limited appeals always allowed
        };

        if !has_restriction {
            return Err(anyhow::anyhow!(
                "No active {} restriction on this device",
                restriction_type
            ));
        }

        // Check for duplicate pending appeals
        let existing = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM restriction_appeals
             WHERE device_id = $1 AND restriction_type = $2 AND status = 'pending_review'",
            device_id,
            restriction_type
        )
        .fetch_one(&self.db)
        .await?;

        if existing.unwrap_or(0) > 0 {
            return Err(anyhow::anyhow!(
                "Appeal already pending for this restriction type"
            ));
        }

        let appeal_id = sqlx::query_scalar!(
            "INSERT INTO restriction_appeals (device_id, restriction_type, context)
             VALUES ($1, $2, $3)
             RETURNING id",
            device_id,
            restriction_type,
            context
        )
        .fetch_one(&self.db)
        .await?;

        Ok(appeal_id.to_string())
    }

    pub async fn get_appeals(&self, device_id: &str) -> Result<Vec<AppealInfo>> {
        let rows = sqlx::query!(
            r#"SELECT id, device_id, restriction_type, context, status,
                      created_at AS "created_at: chrono::DateTime<chrono::Utc>",
                      reviewed_at AS "reviewed_at: chrono::DateTime<chrono::Utc>"
               FROM restriction_appeals
               WHERE device_id = $1
               ORDER BY created_at DESC"#,
            device_id
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| AppealInfo {
                id: r.id.to_string(),
                device_id: r.device_id,
                restriction_type: r.restriction_type,
                context: r.context.unwrap_or_default(),
                status: r.status,
                created_at: r.created_at.to_rfc3339(),
                reviewed_at: r.reviewed_at.map(|t| t.to_rfc3339()),
            })
            .collect())
    }

    // ── Dispute (proof of innocence) ──────────────────────────────────────────

    /// Submit a dispute with evidence against an auto-ban/flag.
    /// Users can provide evidence that reports were from a botnet.
    pub async fn submit_dispute(
        &self,
        device_id: &str,
        restriction_type: &str,
        evidence_text: &str,
    ) -> Result<String> {
        // Check active restriction
        let trust = self.trust_level(device_id).await?;
        match restriction_type {
            "banned" => {
                if trust != TrustLevel::Banned {
                    return Err(anyhow::anyhow!("Device is not banned"));
                }
            }
            "flagged" => {
                if trust != TrustLevel::Flagged {
                    return Err(anyhow::anyhow!("Device is not flagged"));
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid restriction type")),
        }

        // Rate-limit disputes (max 3 pending per device)
        let pending_count: Option<i64> = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM disputes
             WHERE device_id = $1 AND status = 'pending_review'",
            device_id
        )
        .fetch_one(&self.db)
        .await?;

        if pending_count.unwrap_or(0) >= 3 {
            return Err(anyhow::anyhow!("Too many pending disputes"));
        }

        // Collect evidence automatically
        let report_stats = self.collect_report_evidence(device_id).await?;

        let dispute_id: uuid::Uuid = sqlx::query_scalar!(
            "INSERT INTO disputes (device_id, restriction_type, evidence_text, auto_evidence)
             VALUES ($1, $2, $3, $4)
             RETURNING id",
            device_id,
            restriction_type,
            evidence_text,
            report_stats
        )
        .fetch_one(&self.db)
        .await?;

        // Auto-check: if evidence suggests botnet, auto-unban
        if self.evaluate_dispute_evidence(device_id).await? {
            match restriction_type {
                "banned" => self.clear_ban(device_id).await?,
                "flagged" => self.clear_flag(device_id).await?,
                _ => {}
            }
            info!(device_id, "auto-unbanned based on dispute evidence");
        }

        Ok(dispute_id.to_string())
    }

    /// Collect automated evidence about report patterns.
    async fn collect_report_evidence(&self, device_id: &str) -> Result<String> {
        let mut conn = self.redis().await?;
        let unique_key = format!("sentinel:reporters:{}", device_id);
        let unique_reporters: usize = conn.scard(&unique_key).await.unwrap_or(0);
        let total_reports: i64 = conn
            .get(format!("sentinel:reports:{}", device_id))
            .await
            .unwrap_or(0);

        // Check report timing patterns from DB
        let recent_reports = sqlx::query!(
            r#"SELECT reporter_device_id, category,
                      created_at AS "created_at: chrono::DateTime<chrono::Utc>"
               FROM spam_reports
               WHERE reported_device_id = $1
               ORDER BY created_at DESC
               LIMIT 20"#,
            device_id
        )
        .fetch_all(&self.db)
        .await?;

        let time_gaps: Vec<i64> = recent_reports
            .windows(2)
            .map(|w| (w[0].created_at - w[1].created_at).num_seconds())
            .collect();

        let avg_gap = if time_gaps.is_empty() {
            0
        } else {
            time_gaps.iter().sum::<i64>() / time_gaps.len() as i64
        };

        // Suspicious patterns
        let mut flags = Vec::new();
        if unique_reporters > 0 && total_reports > 0 {
            let ratio = total_reports as f64 / unique_reporters as f64;
            if ratio > 3.0 {
                flags.push("same_reporter_multiple_times");
            }
        }
        if avg_gap > 0 && avg_gap < 60 {
            flags.push("reports_too_fast");
        }
        if recent_reports.len() >= 5 {
            let categories: std::collections::HashSet<_> =
                recent_reports.iter().map(|r| &r.category).collect();
            if categories.len() == 1 {
                flags.push("all_same_category");
            }
        }

        let evidence = serde_json::json!({
            "total_reports": total_reports,
            "unique_reporters": unique_reporters,
            "avg_report_gap_seconds": avg_gap,
            "suspicious_flags": flags,
        });

        Ok(evidence.to_string())
    }

    /// Evaluate if dispute evidence suggests botnet attack → auto-unban.
    /// Returns true if device should be unbanned automatically.
    async fn evaluate_dispute_evidence(&self, device_id: &str) -> Result<bool> {
        let mut conn = self.redis().await?;
        let unique_key = format!("sentinel:reporters:{}", device_id);
        let unique_reporters: usize = conn.scard(&unique_key).await.unwrap_or(0);
        let total_reports: i64 = conn
            .get(format!("sentinel:reports:{}", device_id))
            .await
            .unwrap_or(0);

        // Botnet indicators:
        // 1. Few unique reporters but many total reports (same botnet)
        // 2. All reports came in a very short time window
        if total_reports >= AUTO_BAN_REPORTS && unique_reporters < MIN_UNIQUE_REPORTERS_FOR_BAN {
            return Ok(true); // Not enough unique reporters — likely botnet
        }

        Ok(false)
    }

    pub async fn get_disputes(&self, device_id: &str) -> Result<Vec<DisputeEvidence>> {
        let rows = sqlx::query!(
            r#"SELECT id, device_id, restriction_type, status, evidence_text,
                      created_at AS "created_at: chrono::DateTime<chrono::Utc>"
               FROM disputes
               WHERE device_id = $1
               ORDER BY created_at DESC"#,
            device_id
        )
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| DisputeEvidence {
                id: r.id.to_string(),
                device_id: r.device_id,
                restriction_type: r.restriction_type,
                status: r.status,
                evidence_text: r.evidence_text.unwrap_or_default(),
                created_at: r.created_at.to_rfc3339(),
            })
            .collect())
    }

    // ── Protection stats ──────────────────────────────────────────────────────

    pub async fn protection_stats(&self) -> Result<ProtectionStats> {
        let mut conn = self.redis().await?;

        // Get violations from Redis
        let violations: i64 = conn.get("sentinel:violations:24h").await.unwrap_or(0);

        let (spam_24h, flagged_24h, banned_7d, blocks_24h, appeals_pending) = tokio::try_join!(
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM spam_reports WHERE created_at > NOW() - INTERVAL '24 hours'"
            )
            .fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM device_flags WHERE flagged_at > NOW() - INTERVAL '24 hours'"
            )
            .fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM device_flags WHERE is_banned = TRUE AND banned_at > NOW() - INTERVAL '7 days'"
            )
            .fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM device_blocks WHERE created_at > NOW() - INTERVAL '24 hours'"
            )
            .fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM restriction_appeals WHERE status = 'pending_review'"
            )
            .fetch_one(&self.db),
        )?;

        Ok(ProtectionStats {
            spam_reports_24h: spam_24h.unwrap_or(0),
            devices_flagged_24h: flagged_24h.unwrap_or(0),
            devices_banned_7d: banned_7d.unwrap_or(0),
            rate_limit_violations_24h: violations,
            blocks_created_24h: blocks_24h.unwrap_or(0),
            appeals_pending: appeals_pending.unwrap_or(0),
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_msg_limit_order() {
        assert_eq!(TrustLevel::Banned.msg_limit_hour(), 0);
        assert!(TrustLevel::Flagged.msg_limit_hour() > TrustLevel::Banned.msg_limit_hour());
        assert!(TrustLevel::New.msg_limit_hour() > TrustLevel::Flagged.msg_limit_hour());
        assert!(TrustLevel::Warming.msg_limit_hour() > TrustLevel::New.msg_limit_hour());
        assert!(TrustLevel::Trusted.msg_limit_hour() > TrustLevel::Warming.msg_limit_hour());
    }

    #[test]
    fn test_trust_level_recipient_limit_order() {
        assert_eq!(TrustLevel::Banned.recipient_limit_day(), 0);
        assert!(TrustLevel::Flagged.recipient_limit_day() >= 1);
        assert!(TrustLevel::New.recipient_limit_day() > TrustLevel::Flagged.recipient_limit_day());
        assert!(TrustLevel::Warming.recipient_limit_day() > TrustLevel::New.recipient_limit_day());
        assert!(
            TrustLevel::Trusted.recipient_limit_day() > TrustLevel::Warming.recipient_limit_day()
        );
    }

    #[test]
    fn test_new_device_has_no_group_access() {
        assert_eq!(TrustLevel::New.group_msg_limit_day(), 0);
        assert_eq!(TrustLevel::Flagged.group_msg_limit_day(), 0);
        assert_eq!(TrustLevel::Banned.group_msg_limit_day(), 0);
    }

    #[test]
    fn test_warming_device_has_group_access() {
        assert!(TrustLevel::Warming.group_msg_limit_day() > 0);
        assert!(
            TrustLevel::Trusted.group_msg_limit_day() > TrustLevel::Warming.group_msg_limit_day()
        );
    }

    #[test]
    fn test_banned_device_has_zero_limits_everywhere() {
        assert_eq!(TrustLevel::Banned.msg_limit_hour(), 0);
        assert_eq!(TrustLevel::Banned.recipient_limit_day(), 0);
        assert_eq!(TrustLevel::Banned.group_msg_limit_day(), 0);
    }

    #[test]
    fn test_auto_flag_threshold_lower_than_auto_ban() {
        const { assert!(AUTO_FLAG_REPORTS < AUTO_BAN_REPORTS) }
    }

    #[test]
    fn test_auto_flag_threshold_is_reasonable() {
        const { assert!(AUTO_FLAG_REPORTS > 1) }
        const { assert!(AUTO_FLAG_REPORTS <= 5) }
    }

    #[test]
    fn test_auto_ban_threshold_is_reasonable() {
        const { assert!(AUTO_BAN_REPORTS > AUTO_FLAG_REPORTS) }
        const { assert!(AUTO_BAN_REPORTS <= 10) }
    }

    #[test]
    fn test_botnet_protection_thresholds() {
        // Must require more unique reporters for ban than for flag
        const { assert!(MIN_UNIQUE_REPORTERS_FOR_BAN > MIN_UNIQUE_REPORTERS_FOR_FLAG) };
        // At least 2 unique reporters needed for flag
        const { assert!(MIN_UNIQUE_REPORTERS_FOR_FLAG >= 2) };
    }

    #[test]
    fn test_trusted_msg_limit_is_sufficient_for_normal_use() {
        assert!(TrustLevel::Trusted.msg_limit_hour() >= 100);
    }

    #[test]
    fn test_new_device_recipient_limit_allows_minimal_contact() {
        assert!(TrustLevel::New.recipient_limit_day() >= 1);
    }

    #[test]
    fn test_trust_level_eq() {
        assert_eq!(TrustLevel::New, TrustLevel::New);
        assert_ne!(TrustLevel::New, TrustLevel::Trusted);
        assert_ne!(TrustLevel::Banned, TrustLevel::Flagged);
    }

    #[test]
    fn test_trust_level_copy() {
        let level = TrustLevel::Trusted;
        let level2 = level;
        assert_eq!(level, level2);
    }
}
