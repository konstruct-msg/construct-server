// ============================================================================
// Account Recovery Core
// ============================================================================
//
// Implements account recovery via BIP39 seed phrase.
//
// Architecture:
// - Client derives Ed25519 keypair from seed phrase (never sent to server)
// - Server stores recovery_public_key (Ed25519 pubkey, 32 bytes)
// - Recovery: client signs challenge with recovery privkey, server verifies
// - On success: all devices revoked, new device registered
//
// Security:
// - Recovery key is immutable once set (DB trigger prevents changes)
// - 7-day cooldown after each recovery
// - Signature includes timestamp to prevent replay attacks
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug)]
pub struct RecoveryStatus {
    pub is_setup: bool,
    pub fingerprint: Option<String>,
    pub setup_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub has_backup: bool,
}

#[derive(Debug)]
pub struct RecoveryResult {
    pub user_id: Uuid,
    pub devices_revoked: u32,
}

// ============================================================================
// SetRecoveryKey
// ============================================================================

/// Set recovery public key for a user (one-time, immutable)
pub async fn set_recovery_key(
    db: &PgPool,
    user_id: Uuid,
    recovery_public_key: &[u8],
    setup_signature: &[u8],
    timestamp: i64,
    encrypted_backup: Option<&[u8]>,
) -> Result<String> {
    // 1. Validate key size (Ed25519 pubkey = 32 bytes)
    if recovery_public_key.len() != 32 {
        anyhow::bail!("recovery_public_key must be 32 bytes (Ed25519)");
    }

    // 2. Validate signature freshness (reject timestamps older than 5 minutes)
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > 300 {
        anyhow::bail!("Setup signature has expired");
    }

    // 3. Parse the Ed25519 public key
    let verifying_key = VerifyingKey::from_bytes(
        recovery_public_key.try_into().map_err(|_| anyhow::anyhow!("Invalid key bytes"))?
    ).map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;

    // 4. Verify setup signature
    // Message: "CONSTRUCT_RECOVERY_SETUP:{user_id}:{timestamp}"
    let message = format!("CONSTRUCT_RECOVERY_SETUP:{}:{}", user_id, timestamp);
    let sig_bytes: [u8; 64] = setup_signature.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(message.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("Invalid setup signature"))?;

    // 5. Check if recovery key already set
    let existing: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT recovery_public_key FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .flatten();

    if existing.is_some() {
        anyhow::bail!("Recovery key already set and cannot be changed");
    }

    // 6. Store recovery key (DB trigger enforces immutability)
    sqlx::query(
        "UPDATE users SET recovery_public_key = $1 WHERE id = $2"
    )
    .bind(recovery_public_key)
    .bind(user_id)
    .execute(db)
    .await?;

    // 7. Store encrypted backup if provided
    if let Some(backup) = encrypted_backup {
        // Store in a separate column or table
        // For now: store in recovery_backup column if exists
        // TODO: add recovery_backup column in migration if needed
        let _ = backup; // placeholder
    }

    // 8. Return fingerprint
    let fingerprint = key_fingerprint(recovery_public_key);
    Ok(fingerprint)
}

// ============================================================================
// GetRecoveryStatus
// ============================================================================

/// Check recovery setup status for authenticated user
pub async fn get_recovery_status(
    db: &PgPool,
    user_id: Uuid,
) -> Result<RecoveryStatus> {
    let row = sqlx::query_as::<_, RecoveryStatusRow>(
        r#"
        SELECT recovery_public_key, created_at, last_recovery_at
        FROM users
        WHERE id = $1
        "#
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;

    match row {
        Some(r) => {
            let fingerprint = r.recovery_public_key.as_ref().map(|k| key_fingerprint(k));
            Ok(RecoveryStatus {
                is_setup: r.recovery_public_key.is_some(),
                fingerprint,
                setup_at: Some(r.created_at),
                last_used_at: r.last_recovery_at,
                has_backup: false, // TODO: check backup column
            })
        }
        None => anyhow::bail!("User not found"),
    }
}

// ============================================================================
// RecoverAccount
// ============================================================================

/// Recover account: verify signature, revoke all devices
pub async fn verify_recovery_signature(
    db: &PgPool,
    identifier: &str,
    challenge: &str,
    recovery_signature: &[u8],
) -> Result<Uuid> {
    // 1. Find user by username or UUID
    let row = sqlx::query_as::<_, RecoveryKeyRow>(
        r#"
        SELECT id, recovery_public_key, last_recovery_at
        FROM users
        WHERE id::text = $1 OR username = $1
        "#
    )
    .bind(identifier)
    .fetch_optional(db)
    .await?;

    let row = row.ok_or_else(|| anyhow::anyhow!("Account not found"))?;

    // 2. Check recovery is set up
    let recovery_public_key = row.recovery_public_key
        .ok_or_else(|| anyhow::anyhow!("Recovery not set up for this account"))?;

    // 3. Check cooldown (7 days)
    if let Some(last_recovery) = row.last_recovery_at {
        let elapsed = Utc::now() - last_recovery;
        if elapsed.num_days() < 7 {
            let remaining = 7 * 24 * 3600 - elapsed.num_seconds();
            anyhow::bail!("Recovery cooldown active. Try again in {} seconds", remaining);
        }
    }

    // 4. Verify signature
    let key_bytes: [u8; 32] = recovery_public_key.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("Stored recovery key has invalid length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid stored recovery key: {}", e))?;

    let sig_bytes: [u8; 64] = recovery_signature.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(challenge.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("Invalid recovery signature"))?;

    Ok(row.id)
}

/// Revoke all devices for a user (during recovery)
pub async fn revoke_all_devices(db: &PgPool, user_id: Uuid) -> Result<u32> {
    let result = sqlx::query(
        "UPDATE devices SET is_active = false WHERE user_id = $1 AND is_active = true"
    )
    .bind(user_id)
    .execute(db)
    .await?;

    Ok(result.rows_affected() as u32)
}

/// Update last_recovery_at timestamp after successful recovery
pub async fn mark_recovery_used(db: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET last_recovery_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute display fingerprint from key bytes
/// Format: "AB12 CD34 EF56 GH78" (8 groups of 4 hex chars)
pub fn key_fingerprint(key: &[u8]) -> String {
    hex::encode(key)
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase()
        .chars()
        .take(39) // 8 groups × 4 chars + 7 spaces
        .collect()
}

// ============================================================================
// Row types
// ============================================================================

#[derive(sqlx::FromRow)]
struct RecoveryStatusRow {
    recovery_public_key: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    last_recovery_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct RecoveryKeyRow {
    id: Uuid,
    recovery_public_key: Option<Vec<u8>>,
    last_recovery_at: Option<DateTime<Utc>>,
}
