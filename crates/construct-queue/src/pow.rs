// ============================================================================
// Proof-of-Work challenge storage (Redis-backed).
//
// Replaces the former `pow_challenges` PostgreSQL table. PoW challenges are pure
// short-lived cache (≈10 min TTL), so Redis is the natural home — TTL handles
// expiry automatically (the DB path had no cleanup and grew unbounded).
//
// Keys:
//   pow:ch:{challenge}   String (SETEX)   — challenge record (JSON), auto-expires
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::MessageQueue;

const CH_PREFIX: &str = "pow:ch:";

/// A stored PoW challenge. Mirrors the fields the auth flow reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallengeRecord {
    pub difficulty: i16,
    /// Set by a server older than 2026-11-23 sharing this Redis, which marks a spent challenge
    /// instead of taking it. Never written `true` here; a challenge lives ten minutes.
    pub used: bool,
    pub expires_at: DateTime<Utc>,
}

impl MessageQueue {
    /// Create and store a PoW challenge with the given TTL.
    pub async fn create_pow_challenge(
        &mut self,
        challenge: &str,
        difficulty: i16,
        ttl_seconds: i64,
    ) -> Result<PowChallengeRecord> {
        use redis::AsyncCommands;

        let record = PowChallengeRecord {
            difficulty,
            used: false,
            expires_at: Utc::now() + Duration::seconds(ttl_seconds),
        };
        let json = serde_json::to_string(&record)?;
        let key = format!("{CH_PREFIX}{challenge}");
        let _: () = self
            .client
            .connection_mut()
            .set_ex(&key, json, ttl_seconds.max(1) as u64)
            .await?;

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

    /// Take the challenge out of the store. Whoever receives the record spent it; everyone else,
    /// on any instance, receives `None`. `GETDEL`, not a read and a write: between those two,
    /// another registration passes with the same solution.
    pub async fn consume_pow_challenge(
        &mut self,
        challenge: &str,
    ) -> Result<Option<PowChallengeRecord>> {
        use redis::AsyncCommands;

        let key = format!("{CH_PREFIX}{challenge}");
        let json: Option<String> = self.client.connection_mut().get_del(&key).await?;
        let Some(json) = json else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(&json)?))
    }
}
