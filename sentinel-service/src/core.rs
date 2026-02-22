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
//   sentinel:ban:{device_id}          → "1" (with optional TTL for temp bans)
//   sentinel:flag:{device_id}         → "1"
//   sentinel:reports:{device_id}      → counter (INCR, no TTL — persistent)
//   sentinel:rate:msg:{device_id}     → counter (TTL = 3600s, hourly window)
//   sentinel:rate:rcpt:{device_id}    → counter (TTL = 86400s, daily window)
//   sentinel:blocks:{blocker}         → SET of blocked device_ids (cache, TTL 300s)
// ============================================================================

use anyhow::Result;
use chrono;
use redis::AsyncCommands;
use sqlx::PgPool;
use tracing::{info, warn};

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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New     => "TRUST_LEVEL_NEW",
            Self::Warming => "TRUST_LEVEL_WARMING",
            Self::Trusted => "TRUST_LEVEL_TRUSTED",
            Self::Flagged => "TRUST_LEVEL_FLAGGED",
            Self::Banned  => "TRUST_LEVEL_BANNED",
        }
    }

    /// Maximum messages per hour. -1 = unlimited.
    pub fn msg_limit_hour(&self) -> i32 {
        match self {
            Self::New     => 10,
            Self::Warming => 50,
            Self::Trusted => 200,
            Self::Flagged => 5,
            Self::Banned  => 0,
        }
    }

    /// Maximum new unique recipients per day.
    pub fn recipient_limit_day(&self) -> i32 {
        match self {
            Self::New     => 3,
            Self::Warming => 10,
            Self::Trusted => 50,
            Self::Flagged => 1,
            Self::Banned  => 0,
        }
    }

    /// Maximum group messages per day.
    pub fn group_msg_limit_day(&self) -> i32 {
        match self {
            Self::New     => 0,   // no group access in first 48h
            Self::Warming => 20,
            Self::Trusted => 100,
            Self::Flagged => 0,
            Self::Banned  => 0,
        }
    }
}

// ─── Trust level calculation ──────────────────────────────────────────────────

/// Thresholds for automatic escalation.
const AUTO_FLAG_REPORTS: i64 = 3;   // 3+ spam reports → flagged
const AUTO_BAN_REPORTS:  i64 = 5;   // 5+ spam reports → banned

pub struct SentinelCore {
    pub db:    PgPool,
    pub redis: redis::Client,
}

// ─── Return types (must be at module level, not inside impl) ──────────────────

pub struct SendPermission {
    pub allowed:             bool,
    pub denial_reason:       String,
    pub retry_after_seconds: i32,
}

pub struct ProtectionStats {
    pub spam_reports_24h:          i64,
    pub devices_flagged_24h:       i64,
    pub devices_banned_7d:         i64,
    pub rate_limit_violations_24h: i64,
    pub blocks_created_24h:        i64,
    pub appeals_pending:           i64,
}

impl SentinelCore {
    pub async fn new(database_url: &str, redis_url: &str) -> Result<Self> {
        let db    = PgPool::connect(database_url).await?;
        let redis = redis::Client::open(redis_url)?;
        Ok(Self { db, redis })
    }

    async fn redis(&self) -> Result<redis::aio::ConnectionManager> {
        Ok(redis::aio::ConnectionManager::new(self.redis.clone()).await?)
    }

    // ── Trust level ───────────────────────────────────────────────────────────

    /// Calculate trust level for a device. Checks ban/flag in Redis first (fast path),
    /// then falls back to DB account age.
    pub async fn trust_level(&self, device_id: &str) -> Result<TrustLevel> {
        let mut conn = self.redis().await?;

        // Fast path: ban/flag cached in Redis
        let ban_key  = format!("sentinel:ban:{}", device_id);
        let flag_key = format!("sentinel:flag:{}", device_id);

        let is_banned: bool = conn.exists(&ban_key).await?;
        if is_banned {
            return Ok(TrustLevel::Banned);
        }

        let is_flagged: bool = conn.exists(&flag_key).await?;
        if is_flagged {
            return Ok(TrustLevel::Flagged);
        }

        // Also check DB for permanent bans not yet in Redis
        let flag_row = sqlx::query!(
            "SELECT is_banned, is_flagged FROM device_flags WHERE device_id = $1",
            device_id
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = flag_row {
            if row.is_banned {
                // Re-populate Redis cache
                let _: () = conn.set(&ban_key, "1").await?;
                return Ok(TrustLevel::Banned);
            }
            if row.is_flagged {
                let _: () = conn.set(&flag_key, "1").await?;
                return Ok(TrustLevel::Flagged);
            }
        }

        // Account age from devices table
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
            h if h < 48   => TrustLevel::New,
            h if h < 168  => TrustLevel::Warming, // 7 days
            _             => TrustLevel::Trusted,
        })
    }

    // ── Rate limits ───────────────────────────────────────────────────────────

    /// Remaining message quota in the current hourly window.
    /// Returns (remaining, limit) where remaining = -1 means unlimited.
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

    /// Remaining new-recipient quota for today.
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

    // ── CheckSendPermission (hot path) ────────────────────────────────────────

    pub async fn check_send_permission(
        &self,
        caller_device_id: &str,
        target_device_id: &str,
    ) -> Result<SendPermission> {
        let trust = self.trust_level(caller_device_id).await?;

        if trust == TrustLevel::Banned {
            return Ok(SendPermission {
                allowed:             false,
                denial_reason:       "Device is banned".into(),
                retry_after_seconds: 0,
            });
        }

        // Check if target has server-blocked the caller
        let blocked = self.is_blocked(target_device_id, caller_device_id).await?;
        if blocked {
            return Ok(SendPermission {
                allowed:             false,
                denial_reason:       "Recipient has blocked this device".into(),
                retry_after_seconds: 0,
            });
        }

        // Check hourly message rate
        let (remaining, _) = self.msg_quota(caller_device_id, trust).await?;
        if remaining == 0 {
            return Ok(SendPermission {
                allowed:             false,
                denial_reason:       "Hourly message limit reached".into(),
                retry_after_seconds: 3600,
            });
        }

        Ok(SendPermission {
            allowed:             true,
            denial_reason:       String::new(),
            retry_after_seconds: 0,
        })
    }

    // ── Block / Unblock ───────────────────────────────────────────────────────

    /// Returns true if `blocker` has blocked `target`.
    pub async fn is_blocked(&self, blocker: &str, target: &str) -> Result<bool> {
        let row = sqlx::query_scalar!(
            "SELECT 1 FROM device_blocks
             WHERE blocker_device_id = $1 AND blocked_device_id = $2",
            blocker, target
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(row.is_some())
    }

    pub async fn block_device(&self, blocker: &str, blocked: &str) -> Result<()> {
        sqlx::query!(
            "INSERT INTO device_blocks (blocker_device_id, blocked_device_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            blocker, blocked
        )
        .execute(&self.db)
        .await?;
        info!(blocker, blocked, "device blocked");
        Ok(())
    }

    pub async fn unblock_device(&self, blocker: &str, blocked: &str) -> Result<()> {
        sqlx::query!(
            "DELETE FROM device_blocks
             WHERE blocker_device_id = $1 AND blocked_device_id = $2",
            blocker, blocked
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn get_blocked_devices(
        &self,
        blocker: &str,
        page: i32,
        page_size: i32,
    ) -> Result<(Vec<String>, bool)> {
        let limit  = page_size.clamp(1, 100) as i64;
        let offset = (page.max(0) as i64) * limit;

        let rows = sqlx::query_scalar!(
            "SELECT blocked_device_id FROM device_blocks
             WHERE blocker_device_id = $1
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3",
            blocker, limit + 1, offset
        )
        .fetch_all(&self.db)
        .await?;

        let has_more = rows.len() as i64 > limit;
        let results  = rows.into_iter().take(limit as usize).collect();
        Ok((results, has_more))
    }

    // ── Spam reports ──────────────────────────────────────────────────────────

    pub async fn report_spam(
        &self,
        reporter: &str,
        reported: &str,
        category: &str,
    ) -> Result<String> {
        // Persist report
        let report_id = sqlx::query_scalar!(
            "INSERT INTO spam_reports (reporter_device_id, reported_device_id, category)
             VALUES ($1, $2, $3)
             RETURNING id",
            reporter, reported, category
        )
        .fetch_one(&self.db)
        .await?;

        // Increment Redis counter
        let mut conn = self.redis().await?;
        let reports_key = format!("sentinel:reports:{}", reported);
        let total: i64   = conn.incr(&reports_key, 1i64).await?;

        // Auto-escalation
        if total >= AUTO_BAN_REPORTS {
            self.set_banned(reported, "Automatic ban: 5+ spam reports").await?;
            warn!(reported, total, "device auto-banned");
        } else if total >= AUTO_FLAG_REPORTS {
            self.set_flagged(reported).await?;
            warn!(reported, total, "device auto-flagged");
        }

        Ok(report_id.to_string())
    }

    // ── Flag / Ban ────────────────────────────────────────────────────────────

    async fn set_flagged(&self, device_id: &str) -> Result<()> {
        let mut conn = self.redis().await?;
        let _: () = conn.set(format!("sentinel:flag:{}", device_id), "1").await?;

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

    async fn set_banned(&self, device_id: &str, reason: &str) -> Result<()> {
        let mut conn = self.redis().await?;
        let _: () = conn.set(format!("sentinel:ban:{}", device_id), "1").await?;

        sqlx::query!(
            "INSERT INTO device_flags (device_id, is_banned, ban_reason, banned_at)
             VALUES ($1, TRUE, $2, NOW())
             ON CONFLICT (device_id) DO UPDATE
             SET is_banned = TRUE, ban_reason = $2, banned_at = NOW(), updated_at = NOW()",
            device_id, reason
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
        let appeal_id = sqlx::query_scalar!(
            "INSERT INTO restriction_appeals (device_id, restriction_type, context)
             VALUES ($1, $2, $3)
             RETURNING id",
            device_id, restriction_type, context
        )
        .fetch_one(&self.db)
        .await?;

        Ok(appeal_id.to_string())
    }

    // ── Protection stats ──────────────────────────────────────────────────────

    pub async fn protection_stats(&self) -> Result<ProtectionStats> {
        let (spam_24h, flagged_24h, banned_7d, blocks_24h, appeals_pending) = tokio::try_join!(
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM spam_reports WHERE created_at > NOW() - INTERVAL '24 hours'"
            ).fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM device_flags WHERE flagged_at > NOW() - INTERVAL '24 hours'"
            ).fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM device_flags WHERE is_banned = TRUE AND banned_at > NOW() - INTERVAL '7 days'"
            ).fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM device_blocks WHERE created_at > NOW() - INTERVAL '24 hours'"
            ).fetch_one(&self.db),
            sqlx::query_scalar!(
                "SELECT COUNT(*) FROM restriction_appeals WHERE status = 'pending_review'"
            ).fetch_one(&self.db),
        )?;

        Ok(ProtectionStats {
            spam_reports_24h:          spam_24h.unwrap_or(0),
            devices_flagged_24h:       flagged_24h.unwrap_or(0),
            devices_banned_7d:         banned_7d.unwrap_or(0),
            rate_limit_violations_24h: 0, // tracked in Redis; skip for now
            blocks_created_24h:        blocks_24h.unwrap_or(0),
            appeals_pending:           appeals_pending.unwrap_or(0),
        })
    }
}
