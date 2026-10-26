// ============================================================================
// Account Recovery Core
// ============================================================================
//
// Implements account recovery via BIP39 seed phrase.
//
// Architecture:
// - Client derives the recovery key from the seed phrase (the phrase never leaves it): Ed25519,
//   and since construct-core 0.59.0 a hybrid Ed25519 + ML-DSA-65 key whose Ed25519 half is the
//   same key
// - Server stores recovery_public_key (the Ed25519 key, 32 bytes — also the account's address)
//   and recovery_mldsa_public_key (the ML-DSA-65 half, 1952 bytes, once the account is hybrid)
// - Recovery: client signs a claim with the recovery key, server verifies
// - On success: all devices revoked, new device registered
//
// Security:
// - Recovery key is immutable once set (DB triggers prevent changes); an Ed25519 key is completed
//   to a hybrid one once, by a signature of both halves
// - 7-day cooldown after each recovery
// - A hybrid claim names the new device and is fresh within ten minutes
//   (`construct_server_trust::recovery`). The legacy claim signs a client timestamp nobody
//   checks and names no device, so it is replayable; it is accepted only from an account that
//   is not hybrid, and a hybrid account never takes it (no downgrade).
// construct-docs todo/222-recovery-key-hybrid-pq.md
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use construct_crypto::hash_username;
use construct_crypto::pqc::hybrid::verify_hybrid_signature;
use construct_crypto::server_trust::recovery as claim_bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sqlx::PgPool;
use uuid::Uuid;

/// Max encrypted recovery backup size accepted from clients (256 KiB).
/// Prevents unbounded storage abuse via SetRecoveryKey.
pub const MAX_RECOVERY_BACKUP_BYTES: usize = 256 * 1024;

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
    /// The recovery key has its ML-DSA-65 half.
    pub is_hybrid: bool,
}

/// Length of a hybrid recovery key: Ed25519 (32) ‖ ML-DSA-65 (1952).
pub const HYBRID_RECOVERY_KEY_LEN: usize = 32 + 1952;

/// 2026-11-01T00:00:00Z. From this instant the legacy formats are refused — the 32-byte Ed25519
/// setup and the claim over `challenge` — and every recovery key is set, and every account
/// recovered, with the hybrid key (owner, 2026-10-26). An account still on its Ed25519 key loses
/// nothing: the hybrid claim of its phrase recovers it and completes its key.
pub const LEGACY_RECOVERY_CUTOFF: i64 = 1_793_491_200;

/// Whether the legacy formats are still accepted at `now`.
pub fn legacy_recovery_accepted(now: i64) -> bool {
    now < LEGACY_RECOVERY_CUTOFF
}

/// How a RecoverAccount request proves the phrase.
pub enum RecoveryClaim<'a> {
    /// Ed25519 over a client-chosen string. Binds nothing; refused by a hybrid account.
    Legacy {
        challenge: &'a str,
        signature: &'a [u8],
    },
    /// Hybrid over `claim_signable`: the key, the time and the device it hands the account to.
    Hybrid {
        public_key: &'a [u8],
        timestamp: i64,
        signature: &'a [u8],
        device_id: &'a str,
        verifying_key: &'a [u8],
        identity_public: &'a [u8],
    },
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RecoveryResult {
    pub user_id: Uuid,
    pub devices_revoked: u32,
}

// ============================================================================
// SetRecoveryKey
// ============================================================================

/// Set recovery public key for a user (one-time, immutable) — or complete the Ed25519 key set
/// there to the hybrid key whose Ed25519 half it is. The key's length names its kind.
pub async fn set_recovery_key(
    db: &PgPool,
    user_id: Uuid,
    recovery_public_key: &[u8],
    setup_signature: &[u8],
    timestamp: i64,
    encrypted_backup: Option<&[u8]>,
) -> Result<String> {
    set_recovery_key_at(
        db,
        user_id,
        recovery_public_key,
        setup_signature,
        timestamp,
        encrypted_backup,
        Utc::now().timestamp(),
    )
    .await
}

/// `set_recovery_key` with the server's clock at `now`.
pub async fn set_recovery_key_at(
    db: &PgPool,
    user_id: Uuid,
    recovery_public_key: &[u8],
    setup_signature: &[u8],
    timestamp: i64,
    encrypted_backup: Option<&[u8]>,
    now: i64,
) -> Result<String> {
    match recovery_public_key.len() {
        32 if !legacy_recovery_accepted(now) => anyhow::bail!(
            "Invalid recovery key: Ed25519-only keys are no longer accepted, send the hybrid key"
        ),
        32 => {
            set_ed25519_recovery_key(
                db,
                user_id,
                recovery_public_key,
                setup_signature,
                timestamp,
                encrypted_backup,
                now,
            )
            .await
        }
        HYBRID_RECOVERY_KEY_LEN => {
            set_hybrid_recovery_key(
                db,
                user_id,
                recovery_public_key,
                setup_signature,
                timestamp,
                encrypted_backup,
                now,
            )
            .await
        }
        _ => anyhow::bail!(
            "recovery_public_key must be 32 bytes (Ed25519) or {HYBRID_RECOVERY_KEY_LEN} (hybrid)"
        ),
    }
}

/// A hybrid setup: both halves sign `setup_signable`. On an account with no key it sets both; on
/// an account whose Ed25519 key is this key's Ed25519 half it adds the ML-DSA-65 half — the
/// Ed25519 half of the signature is the stored key's, so only the phrase's holder upgrades.
async fn set_hybrid_recovery_key(
    db: &PgPool,
    user_id: Uuid,
    recovery_public_key: &[u8],
    setup_signature: &[u8],
    timestamp: i64,
    encrypted_backup: Option<&[u8]>,
    now: i64,
) -> Result<String> {
    if !claim_bytes::fresh(timestamp, now) {
        anyhow::bail!("Setup signature has expired");
    }
    let message = claim_bytes::setup_signable(&user_id.to_string(), timestamp, recovery_public_key)
        .map_err(|_| anyhow::anyhow!("Invalid setup message"))?;
    verify_hybrid_signature(recovery_public_key, &message, setup_signature)
        .map_err(|_| anyhow::anyhow!("Invalid setup signature"))?;
    if let Some(backup) = encrypted_backup
        && backup.len() > MAX_RECOVERY_BACKUP_BYTES
    {
        anyhow::bail!(
            "encrypted_backup too large (max {} bytes)",
            MAX_RECOVERY_BACKUP_BYTES
        );
    }

    let (ed25519, mldsa) = recovery_public_key.split_at(32);
    let existing: Option<StoredRecoveryKey> = sqlx::query_as(
        "SELECT recovery_public_key, recovery_mldsa_public_key FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let Some((stored, stored_mldsa)) = existing else {
        anyhow::bail!("User not found");
    };

    match (stored.as_deref(), stored_mldsa.as_deref()) {
        (Some(s), Some(m)) if s == ed25519 && m == mldsa => {}
        (Some(s), None) if s == ed25519 => {
            sqlx::query(
                "UPDATE users SET recovery_mldsa_public_key = $1, \
                     recovery_encrypted_backup = COALESCE($2, recovery_encrypted_backup) \
                 WHERE id = $3 AND recovery_mldsa_public_key IS NULL",
            )
            .bind(mldsa)
            .bind(encrypted_backup)
            .bind(user_id)
            .execute(db)
            .await?;
        }
        (Some(_), _) => anyhow::bail!("Recovery key already set and cannot be changed"),
        (None, _) => {
            let (key_type, route_id) = construct_db::account_address_columns(ed25519);
            sqlx::query(
                "UPDATE users SET recovery_public_key = $1, recovery_mldsa_public_key = $2, \
                     recovery_encrypted_backup = COALESCE($3, recovery_encrypted_backup), \
                     identity_public_key = $1, identity_key_type = $4, route_id = $5 \
                 WHERE id = $6",
            )
            .bind(ed25519)
            .bind(mldsa)
            .bind(encrypted_backup)
            .bind(key_type)
            .bind(&route_id)
            .bind(user_id)
            .execute(db)
            .await?;
        }
    }
    Ok(key_fingerprint(ed25519))
}

/// The account's recovery key as stored: the Ed25519 key and the ML-DSA-65 half.
type StoredRecoveryKey = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The Ed25519 setup, as before 0.59.0.
async fn set_ed25519_recovery_key(
    db: &PgPool,
    user_id: Uuid,
    recovery_public_key: &[u8],
    setup_signature: &[u8],
    timestamp: i64,
    encrypted_backup: Option<&[u8]>,
    now: i64,
) -> Result<String> {
    // 2. Validate signature freshness (reject timestamps older than 5 minutes)
    if (now - timestamp).abs() > 300 {
        anyhow::bail!("Setup signature has expired");
    }

    // 3. Parse the Ed25519 public key
    let verifying_key = VerifyingKey::from_bytes(
        recovery_public_key
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key bytes"))?,
    )
    .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;

    // 4. Verify setup signature
    // Message: "CONSTRUCT_RECOVERY_SETUP:{user_id}:{timestamp}"
    let message = format!("CONSTRUCT_RECOVERY_SETUP:{}:{}", user_id, timestamp);
    let sig_bytes: [u8; 64] = setup_signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("Invalid setup signature"))?;

    // 5. Check if recovery key already set
    let existing: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT recovery_public_key FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?
            .flatten();

    // The same key again is the same setup again: a client that registered its key silently
    // and lost the answer retries with it (construct-docs
    // `decisions/recovery-key-backup-is-deferred-not-skipped.md`, review point 1). The signature
    // above already proved the caller holds it. Any other key is still refused.
    match existing {
        Some(stored) if stored == recovery_public_key => {
            return Ok(key_fingerprint(recovery_public_key));
        }
        Some(_) => anyhow::bail!("Recovery key already set and cannot be changed"),
        None => {}
    }

    // 6. Validate optional encrypted backup size before write
    if let Some(backup) = encrypted_backup
        && backup.len() > MAX_RECOVERY_BACKUP_BYTES
    {
        anyhow::bail!(
            "encrypted_backup too large (max {} bytes)",
            MAX_RECOVERY_BACKUP_BYTES
        );
    }

    // 7. Store recovery key (DB trigger enforces immutability), optional backup, and the address
    // the key names — in one statement, so an account never has one without the other
    // (construct-docs `decisions/pubkey-as-identity.md`, "Which key is the address").
    let (key_type, route_id) = construct_db::account_address_columns(recovery_public_key);
    sqlx::query(
        "UPDATE users SET recovery_public_key = $1, \
             recovery_encrypted_backup = COALESCE($2, recovery_encrypted_backup), \
             identity_public_key = $1, identity_key_type = $3, route_id = $4 \
         WHERE id = $5",
    )
    .bind(recovery_public_key)
    .bind(encrypted_backup)
    .bind(key_type)
    .bind(&route_id)
    .bind(user_id)
    .execute(db)
    .await?;

    // 8. Return fingerprint
    let fingerprint = key_fingerprint(recovery_public_key);
    Ok(fingerprint)
}

// ============================================================================
// GetRecoveryStatus
// ============================================================================

/// Check recovery setup status for authenticated user
pub async fn get_recovery_status(db: &PgPool, user_id: Uuid) -> Result<RecoveryStatus> {
    let row = sqlx::query_as::<_, RecoveryStatusRow>(
        r#"
        SELECT recovery_public_key, recovery_setup_at, last_recovery_at,
               (recovery_encrypted_backup IS NOT NULL) AS has_backup,
               (recovery_mldsa_public_key IS NOT NULL) AS is_hybrid
        FROM users
        WHERE id = $1
        "#,
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
                setup_at: r.recovery_setup_at,
                last_used_at: r.last_recovery_at,
                has_backup: r.has_backup,
                is_hybrid: r.is_hybrid,
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
    claim: RecoveryClaim<'_>,
    hmac_secret: &[u8],
) -> Result<Uuid> {
    verify_recovery_signature_at(db, identifier, claim, hmac_secret, Utc::now().timestamp()).await
}

/// `verify_recovery_signature` with the server's clock at `now`.
pub async fn verify_recovery_signature_at(
    db: &PgPool,
    identifier: &str,
    claim: RecoveryClaim<'_>,
    hmac_secret: &[u8],
    now: i64,
) -> Result<Uuid> {
    // 1. Find user by UUID or username_hash (privacy-first)
    // Trim first so surrounding whitespace doesn't break either branch.
    let identifier = identifier.trim();
    let row = if let Ok(user_uuid) = identifier.parse::<Uuid>() {
        // identifier is a UUID → direct lookup
        sqlx::query_as::<_, RecoveryKeyRow>(
            r#"
            SELECT id, recovery_public_key, recovery_mldsa_public_key, last_recovery_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_uuid)
        .fetch_optional(db)
        .await?
    } else {
        // identifier is a username → normalize EXACTLY like registration
        // (main.rs: `username.trim().to_lowercase()` before `hash_username`) and look up by
        // hash. Without this, a user who registered "Alice" but types "alice"/"ALICE"/" alice "
        // during recovery hashes to a different value → "Account not found" (NOT_FOUND).
        let normalized = identifier.to_lowercase();
        let hash = hash_username(hmac_secret, &normalized);
        sqlx::query_as::<_, RecoveryKeyRow>(
            r#"
            SELECT id, recovery_public_key, recovery_mldsa_public_key, last_recovery_at
            FROM users
            WHERE username_hash = $1
            "#,
        )
        .bind(&hash)
        .fetch_optional(db)
        .await?
    };

    let row = row.ok_or_else(|| anyhow::anyhow!("Account not found"))?;

    // 2. Check recovery is set up
    let recovery_public_key = row
        .recovery_public_key
        .ok_or_else(|| anyhow::anyhow!("Recovery not set up for this account"))?;

    // 3. Check cooldown (7 days)
    if let Some(last_recovery) = row.last_recovery_at {
        let elapsed = Utc::now() - last_recovery;
        if elapsed.num_days() < 7 {
            let remaining = 7 * 24 * 3600 - elapsed.num_seconds();
            anyhow::bail!(
                "Recovery cooldown active. Try again in {} seconds",
                remaining
            );
        }
    }

    // 4. Verify the claim
    match claim {
        RecoveryClaim::Legacy {
            challenge,
            signature,
        } => {
            // A hybrid account takes no Ed25519-only claim: that is the downgrade the ML-DSA
            // half exists to refuse.
            if row.recovery_mldsa_public_key.is_some() {
                anyhow::bail!("Invalid recovery signature: this account takes hybrid claims only");
            }
            if !legacy_recovery_accepted(now) {
                anyhow::bail!("Invalid recovery signature: legacy claims are no longer accepted");
            }
            verify_ed25519_claim(&recovery_public_key, challenge, signature)?;
        }
        RecoveryClaim::Hybrid {
            public_key,
            timestamp,
            signature,
            device_id,
            verifying_key,
            identity_public,
        } => {
            if public_key.len() != HYBRID_RECOVERY_KEY_LEN {
                anyhow::bail!("Invalid recovery key length");
            }
            let (ed25519, mldsa) = public_key.split_at(32);
            if ed25519 != recovery_public_key.as_slice() {
                anyhow::bail!("Invalid recovery signature");
            }
            if let Some(stored) = &row.recovery_mldsa_public_key
                && stored.as_slice() != mldsa
            {
                anyhow::bail!("Invalid recovery signature");
            }
            let after_last = row
                .last_recovery_at
                .is_none_or(|last| timestamp > last.timestamp());
            if !claim_bytes::fresh(timestamp, now) || !after_last {
                anyhow::bail!("Invalid recovery signature: the claim is not fresh");
            }
            let message = claim_bytes::claim_signable(
                public_key,
                timestamp,
                device_id,
                verifying_key,
                identity_public,
            )
            .map_err(|_| anyhow::anyhow!("Invalid recovery claim"))?;
            verify_hybrid_signature(public_key, &message, signature)
                .map_err(|_| anyhow::anyhow!("Invalid recovery signature"))?;

            // An account recovered with the hybrid key keeps its ML-DSA half: from now on it
            // takes hybrid claims only.
            if row.recovery_mldsa_public_key.is_none() {
                sqlx::query(
                    "UPDATE users SET recovery_mldsa_public_key = $1 \
                     WHERE id = $2 AND recovery_mldsa_public_key IS NULL",
                )
                .bind(mldsa)
                .bind(row.id)
                .execute(db)
                .await?;
            }
        }
    }

    Ok(row.id)
}

fn verify_ed25519_claim(
    recovery_public_key: &[u8],
    challenge: &str,
    recovery_signature: &[u8],
) -> Result<()> {
    let key_bytes: [u8; 32] = recovery_public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("Stored recovery key has invalid length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid stored recovery key: {}", e))?;

    let sig_bytes: [u8; 64] = recovery_signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(challenge.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("Invalid recovery signature"))
}

/// Revoke all devices for a user (during recovery)
pub async fn revoke_all_devices(db: &PgPool, user_id: Uuid) -> Result<u32> {
    let result =
        sqlx::query("UPDATE devices SET is_active = false WHERE user_id = $1 AND is_active = true")
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
    recovery_setup_at: Option<DateTime<Utc>>,
    last_recovery_at: Option<DateTime<Utc>>,
    has_backup: bool,
    is_hybrid: bool,
}

#[derive(sqlx::FromRow)]
struct RecoveryKeyRow {
    id: Uuid,
    recovery_public_key: Option<Vec<u8>>,
    recovery_mldsa_public_key: Option<Vec<u8>>,
    last_recovery_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod address_tests {
    use super::*;

    /// The tests' clock: a day before the legacy cutoff, so the suite does not change its verdicts
    /// when the date passes. The tests of the cutoff itself use `AFTER_CUTOFF`.
    const NOW: i64 = LEGACY_RECOVERY_CUTOFF - 86_400;
    const AFTER_CUTOFF: i64 = LEGACY_RECOVERY_CUTOFF + 86_400;
    use ed25519_dalek::{Signer, SigningKey};

    /// Local Postgres from `ops/docker-compose.dev.yml`; the test skips without it.
    async fn try_db() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:password@127.0.0.1:5432/construct_test".to_string()
        });
        let pool = PgPool::connect(&url).await.ok()?;
        sqlx::migrate!("../shared/migrations")
            .run(&pool)
            .await
            .ok()?;
        Some(pool)
    }

    /// Setting the recovery key writes the address it names in the same statement
    /// (construct-docs `decisions/pubkey-as-identity.md`, "Which key is the address").
    #[tokio::test]
    async fn setting_the_recovery_key_writes_the_account_address() {
        let Some(db) = try_db().await else {
            eprintln!("recovery address test: postgres unavailable — skipping");
            return;
        };
        let user_id: Uuid =
            sqlx::query_scalar("INSERT INTO users (id) VALUES (gen_random_uuid()) RETURNING id")
                .fetch_one(&db)
                .await
                .unwrap();
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let public = signing.verifying_key().to_bytes();
        let timestamp = NOW;
        let signature =
            signing.sign(format!("CONSTRUCT_RECOVERY_SETUP:{user_id}:{timestamp}").as_bytes());

        set_recovery_key_at(
            &db,
            user_id,
            &public,
            &signature.to_bytes(),
            timestamp,
            None,
            NOW,
        )
        .await
        .unwrap();

        let (identity, key_type, route_id): (Option<Vec<u8>>, i16, Option<String>) =
            sqlx::query_as(
                "SELECT identity_public_key, identity_key_type, route_id FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(identity.as_deref(), Some(public.as_slice()));
        assert_eq!(key_type, 1, "Ed25519");
        let found = construct_db::get_user_by_route_id(&db, route_id.as_deref().unwrap())
            .await
            .unwrap()
            .expect("the address resolves to the account");
        assert_eq!(found.id, user_id);

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&db)
            .await;
    }

    fn signed_setup(signing: &SigningKey, user_id: Uuid) -> ([u8; 32], [u8; 64], i64) {
        let timestamp = NOW;
        let signature =
            signing.sign(format!("CONSTRUCT_RECOVERY_SETUP:{user_id}:{timestamp}").as_bytes());
        (
            signing.verifying_key().to_bytes(),
            signature.to_bytes(),
            timestamp,
        )
    }

    /// A retry with the key already set answers like the first call; another key is refused.
    ///
    /// Mutation: bail on any existing key — the retry fails and this reddens.
    #[tokio::test]
    async fn the_same_key_again_is_accepted_and_another_is_refused() {
        let Some(db) = try_db().await else {
            eprintln!("recovery retry test: postgres unavailable — skipping");
            return;
        };
        let user_id: Uuid =
            sqlx::query_scalar("INSERT INTO users (id) VALUES (gen_random_uuid()) RETURNING id")
                .fetch_one(&db)
                .await
                .unwrap();
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());

        let (public, signature, timestamp) = signed_setup(&signing, user_id);
        let first = set_recovery_key_at(&db, user_id, &public, &signature, timestamp, None, NOW)
            .await
            .unwrap();
        let (public, signature, timestamp) = signed_setup(&signing, user_id);
        let again = set_recovery_key_at(&db, user_id, &public, &signature, timestamp, None, NOW)
            .await
            .expect("the same key again is accepted");
        assert_eq!(first, again);

        let other = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let (public, signature, timestamp) = signed_setup(&other, user_id);
        assert!(
            set_recovery_key_at(&db, user_id, &public, &signature, timestamp, None, NOW)
                .await
                .is_err(),
            "another key is still refused"
        );

        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&db)
            .await;
    }

    // ── Hybrid recovery key (construct-docs todo/222-recovery-key-hybrid-pq.md) ──────────────

    use construct_crypto::pqc::hybrid::{hybrid_sign, hybrid_signature_keypair_from_seeds};

    /// A phrase's recovery key as its two seeds: the Ed25519 one is the legacy key.
    struct Phrase {
        ed25519: [u8; 32],
        mldsa: [u8; 32],
    }

    impl Phrase {
        fn new() -> Self {
            Self {
                ed25519: rand::random(),
                mldsa: rand::random(),
            }
        }
        fn legacy(&self) -> SigningKey {
            SigningKey::from_bytes(&self.ed25519)
        }
        fn hybrid(&self) -> (Vec<u8>, Vec<u8>) {
            hybrid_signature_keypair_from_seeds(&self.ed25519, &self.mldsa)
        }
        fn hybrid_setup(&self, user_id: Uuid) -> (Vec<u8>, Vec<u8>, i64) {
            let (private, public) = self.hybrid();
            let timestamp = NOW;
            let message =
                claim_bytes::setup_signable(&user_id.to_string(), timestamp, &public).unwrap();
            (public, hybrid_sign(&private, &message).unwrap(), timestamp)
        }
        fn hybrid_claim(&self, timestamp: i64, device: &Device) -> (Vec<u8>, Vec<u8>) {
            let (private, public) = self.hybrid();
            let message = claim_bytes::claim_signable(
                &public,
                timestamp,
                &device.id,
                &device.verifying_key,
                &device.identity_public,
            )
            .unwrap();
            let signature = hybrid_sign(&private, &message).unwrap();
            (public, signature)
        }
    }

    struct Device {
        id: String,
        verifying_key: Vec<u8>,
        identity_public: Vec<u8>,
    }

    impl Device {
        fn new() -> Self {
            Self {
                id: hex::encode(rand::random::<[u8; 16]>()),
                verifying_key: rand::random::<[u8; 32]>().to_vec(),
                identity_public: rand::random::<[u8; 32]>().to_vec(),
            }
        }
    }

    async fn new_user(db: &PgPool) -> Uuid {
        sqlx::query_scalar("INSERT INTO users (id) VALUES (gen_random_uuid()) RETURNING id")
            .fetch_one(db)
            .await
            .unwrap()
    }

    async fn drop_user(db: &PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(db)
            .await;
    }

    async fn set_legacy(db: &PgPool, user_id: Uuid, phrase: &Phrase) {
        let (public, signature, timestamp) = signed_setup(&phrase.legacy(), user_id);
        set_recovery_key_at(db, user_id, &public, &signature, timestamp, None, NOW)
            .await
            .unwrap();
    }

    async fn set_hybrid(db: &PgPool, user_id: Uuid, phrase: &Phrase) -> Result<String> {
        let (public, signature, timestamp) = phrase.hybrid_setup(user_id);
        set_recovery_key_at(db, user_id, &public, &signature, timestamp, None, NOW).await
    }

    async fn claim(
        db: &PgPool,
        user_id: Uuid,
        public_key: &[u8],
        timestamp: i64,
        signature: &[u8],
        device: &Device,
    ) -> Result<Uuid> {
        verify_recovery_signature_at(
            db,
            &user_id.to_string(),
            RecoveryClaim::Hybrid {
                public_key,
                timestamp,
                signature,
                device_id: &device.id,
                verifying_key: &device.verifying_key,
                identity_public: &device.identity_public,
            },
            b"test",
            NOW,
        )
        .await
    }

    async fn legacy_claim(db: &PgPool, user_id: Uuid, phrase: &Phrase) -> Result<Uuid> {
        let challenge = NOW.to_string();
        let signature = phrase.legacy().sign(challenge.as_bytes()).to_bytes();
        verify_recovery_signature_at(
            db,
            &user_id.to_string(),
            RecoveryClaim::Legacy {
                challenge: &challenge,
                signature: &signature,
            },
            b"test",
            NOW,
        )
        .await
    }

    async fn is_hybrid(db: &PgPool, user_id: Uuid) -> bool {
        get_recovery_status(db, user_id).await.unwrap().is_hybrid
    }

    /// An Ed25519 account is completed by the hybrid key whose Ed25519 half it holds, keeps its
    /// address and fingerprint, and is not completed a second time with another ML-DSA half.
    ///
    /// Mutation: refuse a hybrid key on an account that has a key — the upgrade fails; reddens.
    /// Mutation: accept a second ML-DSA half — the last assertion reddens.
    #[tokio::test]
    async fn an_ed25519_account_is_upgraded_by_its_phrases_hybrid_key_once() {
        let Some(db) = try_db().await else {
            eprintln!("recovery upgrade test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_legacy(&db, user_id, &phrase).await;
        let before = get_recovery_status(&db, user_id).await.unwrap();
        assert!(!before.is_hybrid);

        let fingerprint = set_hybrid(&db, user_id, &phrase).await.expect("upgraded");
        assert!(is_hybrid(&db, user_id).await);
        assert_eq!(
            Some(fingerprint),
            before.fingerprint,
            "the same key, the same fingerprint"
        );
        set_hybrid(&db, user_id, &phrase)
            .await
            .expect("the same hybrid key again is accepted");

        let other_mldsa = Phrase {
            ed25519: phrase.ed25519,
            mldsa: rand::random(),
        };
        assert!(set_hybrid(&db, user_id, &other_mldsa).await.is_err());
        drop_user(&db, user_id).await;
    }

    /// A hybrid key whose Ed25519 half is another key upgrades nothing.
    ///
    /// Mutation: compare only the ML-DSA half on upgrade — this reddens.
    #[tokio::test]
    async fn a_hybrid_key_of_another_phrase_does_not_upgrade() {
        let Some(db) = try_db().await else {
            eprintln!("recovery upgrade test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        set_legacy(&db, user_id, &Phrase::new()).await;
        assert!(set_hybrid(&db, user_id, &Phrase::new()).await.is_err());
        assert!(!is_hybrid(&db, user_id).await);
        drop_user(&db, user_id).await;
    }

    /// A hybrid account takes the hybrid claim of its phrase and refuses the Ed25519-only one.
    ///
    /// Mutation: drop the downgrade check in the legacy branch — the legacy claim is accepted;
    /// this reddens.
    #[tokio::test]
    async fn a_hybrid_account_refuses_the_ed25519_only_claim() {
        let Some(db) = try_db().await else {
            eprintln!("recovery claim test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_hybrid(&db, user_id, &phrase).await.unwrap();

        let err = legacy_claim(&db, user_id, &phrase).await.unwrap_err();
        assert!(err.to_string().contains("hybrid claims only"), "{err}");

        let device = Device::new();
        let now = NOW;
        let (public, signature) = phrase.hybrid_claim(now, &device);
        assert_eq!(
            claim(&db, user_id, &public, now, &signature, &device)
                .await
                .unwrap(),
            user_id
        );
        drop_user(&db, user_id).await;
    }

    /// A claim hands the account to the device it names and to no other, and only while fresh.
    ///
    /// Mutation: sign the claim without the device keys — the substituted device is accepted;
    /// this reddens.
    /// Mutation: drop the freshness check — the stale claim is accepted; this reddens.
    #[tokio::test]
    async fn a_claim_is_for_its_device_and_its_moment() {
        let Some(db) = try_db().await else {
            eprintln!("recovery claim test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_hybrid(&db, user_id, &phrase).await.unwrap();
        let device = Device::new();
        let now = NOW;

        let (public, signature) = phrase.hybrid_claim(now, &device);
        let attacker = Device {
            id: device.id.clone(),
            ..Device::new()
        };
        assert!(
            claim(&db, user_id, &public, now, &signature, &attacker)
                .await
                .is_err(),
            "the claim was moved to other device keys"
        );

        let stale = now - claim_bytes::MAX_SKEW_SECS - 1;
        let (public, signature) = phrase.hybrid_claim(stale, &device);
        let err = claim(&db, user_id, &public, stale, &signature, &device)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not fresh"), "{err}");
        drop_user(&db, user_id).await;
    }

    /// An Ed25519 account recovered with its phrase's hybrid key keeps the ML-DSA half, and from
    /// then on refuses the Ed25519-only claim.
    ///
    /// Mutation: skip storing the ML-DSA half on a hybrid claim — the account stays Ed25519 and
    /// this reddens.
    #[tokio::test]
    async fn a_hybrid_recovery_upgrades_an_ed25519_account() {
        let Some(db) = try_db().await else {
            eprintln!("recovery claim test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_legacy(&db, user_id, &phrase).await;
        legacy_claim(&db, user_id, &phrase)
            .await
            .expect("an Ed25519 account still takes the legacy claim");

        let device = Device::new();
        let now = NOW;
        let (public, signature) = phrase.hybrid_claim(now, &device);
        claim(&db, user_id, &public, now, &signature, &device)
            .await
            .unwrap();
        assert!(is_hybrid(&db, user_id).await);
        assert!(legacy_claim(&db, user_id, &phrase).await.is_err());
        drop_user(&db, user_id).await;
    }

    // ── The legacy cutoff, 2026-11-01 ─────────────────────────────────────────────────────────

    #[test]
    fn the_legacy_formats_close_at_the_cutoff() {
        assert!(legacy_recovery_accepted(LEGACY_RECOVERY_CUTOFF - 1));
        assert!(!legacy_recovery_accepted(LEGACY_RECOVERY_CUTOFF));
    }

    /// After the cutoff no account gets an Ed25519-only recovery key.
    ///
    /// Mutation: drop the cutoff from the 32-byte setup — the key is set; this reddens.
    #[tokio::test]
    async fn after_the_cutoff_an_ed25519_key_is_not_set() {
        let Some(db) = try_db().await else {
            eprintln!("recovery cutoff test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let signature =
            signing.sign(format!("CONSTRUCT_RECOVERY_SETUP:{user_id}:{AFTER_CUTOFF}").as_bytes());
        let err = set_recovery_key_at(
            &db,
            user_id,
            &signing.verifying_key().to_bytes(),
            &signature.to_bytes(),
            AFTER_CUTOFF,
            None,
            AFTER_CUTOFF,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no longer accepted"), "{err}");
        assert!(!get_recovery_status(&db, user_id).await.unwrap().is_setup);
        drop_user(&db, user_id).await;
    }

    /// After the cutoff an account still on its Ed25519 key refuses the legacy claim, and its
    /// phrase's hybrid claim recovers it and completes the key — nobody is locked out.
    ///
    /// Mutation: drop the cutoff from the legacy claim — it is accepted; this reddens.
    #[tokio::test]
    async fn after_the_cutoff_an_ed25519_account_is_recovered_by_its_hybrid_claim_only() {
        let Some(db) = try_db().await else {
            eprintln!("recovery cutoff test: postgres unavailable — skipping");
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_legacy(&db, user_id, &phrase).await;

        let challenge = AFTER_CUTOFF.to_string();
        let signature = phrase.legacy().sign(challenge.as_bytes()).to_bytes();
        let err = verify_recovery_signature_at(
            &db,
            &user_id.to_string(),
            RecoveryClaim::Legacy {
                challenge: &challenge,
                signature: &signature,
            },
            b"test",
            AFTER_CUTOFF,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no longer accepted"), "{err}");

        let device = Device::new();
        let (public, signature) = phrase.hybrid_claim(AFTER_CUTOFF, &device);
        let recovered = verify_recovery_signature_at(
            &db,
            &user_id.to_string(),
            RecoveryClaim::Hybrid {
                public_key: &public,
                timestamp: AFTER_CUTOFF,
                signature: &signature,
                device_id: &device.id,
                verifying_key: &device.verifying_key,
                identity_public: &device.identity_public,
            },
            b"test",
            AFTER_CUTOFF,
        )
        .await
        .unwrap();
        assert_eq!(recovered, user_id);
        assert!(is_hybrid(&db, user_id).await);
        drop_user(&db, user_id).await;
    }
}
