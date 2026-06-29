// ============================================================================
// Proof-of-Work challenge storage (Redis-backed).
//
// Replaces the former `pow_challenges` PostgreSQL table. PoW challenges are pure
// short-lived cache (≈10 min TTL), so Redis is the natural home — TTL handles
// expiry automatically (the DB path had no cleanup and grew unbounded).
//
// Keys:
//   pow:ch:{challenge}   String (SETEX)   — challenge record (JSON), auto-expires
//   pow:ipch:{ip}        ZSet             — challenge request timestamps per IP (rate limit)
//   pow:ipreg:{ip}       ZSet             — successful-registration timestamps per IP (anti-spam)
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::MessageQueue;

const CH_PREFIX: &str = "pow:ch:";
const IPCH_PREFIX: &str = "pow:ipch:";
const IPREG_PREFIX: &str = "pow:ipreg:";
// Per-IP counter sorted sets never need to outlive the longest rate-limit window.
const IP_ZSET_TTL_SECS: i64 = 3600;

/// A stored PoW challenge. Mirrors the fields the auth flow reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallengeRecord {
    pub difficulty: i16,
    pub used: bool,
    pub requester_ip: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl MessageQueue {
    /// Create and store a PoW challenge with the given TTL. Also records the
    /// request against the requester IP's sliding window (when IP is known).
    pub async fn create_pow_challenge(
        &mut self,
        challenge: &str,
        difficulty: i16,
        requester_ip: Option<&str>,
        ttl_seconds: i64,
    ) -> Result<PowChallengeRecord> {
        use redis::AsyncCommands;

        let now = Utc::now();
        let record = PowChallengeRecord {
            difficulty,
            used: false,
            requester_ip: requester_ip.map(|s| s.to_string()),
            expires_at: now + Duration::seconds(ttl_seconds),
        };
        let json = serde_json::to_string(&record)?;
        let key = format!("{CH_PREFIX}{challenge}");
        let _: () = self
            .client
            .connection_mut()
            .set_ex(&key, json, ttl_seconds.max(1) as u64)
            .await?;

        if let Some(ip) = requester_ip {
            let zkey = format!("{IPCH_PREFIX}{ip}");
            let _: i64 = self
                .client
                .connection_mut()
                .zadd(&zkey, challenge, now.timestamp_millis())
                .await?;
            let _: bool = self
                .client
                .connection_mut()
                .expire(&zkey, IP_ZSET_TTL_SECS)
                .await?;
        }

        Ok(record)
    }

    /// Fetch a stored PoW challenge (None if expired/never existed).
    pub async fn get_pow_challenge(
        &mut self,
        challenge: &str,
    ) -> Result<Option<PowChallengeRecord>> {
        use redis::AsyncCommands;

        let key = format!("{CH_PREFIX}{challenge}");
        let json: Option<String> = self.client.connection_mut().get(&key).await?;
        match json {
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
            None => Ok(None),
        }
    }

    /// Mark a challenge as used (single-use) and record a successful
    /// registration against the requester IP's sliding window.
    pub async fn mark_pow_challenge_used(&mut self, challenge: &str) -> Result<()> {
        use redis::AsyncCommands;

        let key = format!("{CH_PREFIX}{challenge}");
        let json: Option<String> = self.client.connection_mut().get(&key).await?;
        let Some(s) = json else {
            return Ok(()); // already expired/consumed — nothing to do
        };
        let mut record: PowChallengeRecord = serde_json::from_str(&s)?;
        record.used = true;
        let ip = record.requester_ip.clone();

        // Preserve remaining TTL so a used challenge still expires on schedule.
        let ttl: i64 = self.client.connection_mut().ttl(&key).await?;
        let new_json = serde_json::to_string(&record)?;
        if ttl > 0 {
            let _: () = self
                .client
                .connection_mut()
                .set_ex(&key, new_json, ttl as u64)
                .await?;
        } else {
            let _: () = self.client.connection_mut().set(&key, new_json).await?;
        }

        if let Some(ip) = ip {
            let zkey = format!("{IPREG_PREFIX}{ip}");
            let _: i64 = self
                .client
                .connection_mut()
                .zadd(&zkey, challenge, Utc::now().timestamp_millis())
                .await?;
            let _: bool = self
                .client
                .connection_mut()
                .expire(&zkey, IP_ZSET_TTL_SECS)
                .await?;
        }

        Ok(())
    }

    /// Count PoW challenges requested by an IP within the last `minutes`.
    pub async fn count_pow_challenges_by_ip(&mut self, ip: &str, minutes: i64) -> Result<i64> {
        self.count_pow_window(&format!("{IPCH_PREFIX}{ip}"), minutes)
            .await
    }

    /// Count successful registrations from an IP within the last `minutes`.
    pub async fn count_pow_registrations_by_ip(&mut self, ip: &str, minutes: i64) -> Result<i64> {
        self.count_pow_window(&format!("{IPREG_PREFIX}{ip}"), minutes)
            .await
    }

    /// Sliding-window count over a per-IP sorted set: trims entries older than
    /// the window, then counts what remains.
    async fn count_pow_window(&mut self, zkey: &str, minutes: i64) -> Result<i64> {
        use redis::AsyncCommands;

        let cutoff = Utc::now().timestamp_millis() - minutes * 60 * 1000;
        let _: i64 = self
            .client
            .connection_mut()
            .zrembyscore(zkey, f64::NEG_INFINITY, cutoff as f64)
            .await?;
        let count: i64 = self
            .client
            .connection_mut()
            .zcount(zkey, cutoff as f64, f64::INFINITY)
            .await?;
        Ok(count)
    }
}
