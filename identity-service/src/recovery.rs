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
// - Every setup/claim requires a hybrid key and both signatures. A claim names the new device
//   and is fresh within ten minutes (`construct_server_trust::recovery`). The retired
//   Ed25519-only writer and challenge verifier are gone. Stored Ed25519-only accounts remain
//   recoverable with their phrase's hybrid proof, which completes the existing key.
// construct-docs todo/222-recovery-key-hybrid-pq.md
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use construct_crypto::hash_username;
use construct_crypto::pqc::hybrid::verify_hybrid_signature;
use construct_crypto::server_trust::recovery as claim_bytes;
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

/// A hybrid proof bound to the new device. The retired challenge-only format has no
/// representation here; existing Ed25519 account rows are upgraded by a valid hybrid proof.
pub struct RecoveryClaim<'a> {
    pub public_key: &'a [u8],
    pub timestamp: i64,
    pub signature: &'a [u8],
    pub device_id: &'a str,
    pub verifying_key: &'a [u8],
    pub identity_public: &'a [u8],
}

fn require_hybrid_recovery_key(public_key: &[u8]) -> Result<()> {
    if public_key.len() != HYBRID_RECOVERY_KEY_LEN {
        anyhow::bail!(
            "Invalid recovery key: expected {HYBRID_RECOVERY_KEY_LEN}-byte hybrid public key"
        );
    }
    Ok(())
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
/// there to the hybrid key whose Ed25519 half it is. Only the hybrid wire format is accepted.
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
    require_hybrid_recovery_key(recovery_public_key)?;
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
    let RecoveryClaim {
        public_key,
        timestamp,
        signature,
        device_id,
        verifying_key,
        identity_public,
    } = claim;
    require_hybrid_recovery_key(public_key)?;

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

    // 4. Verify both halves of the device-bound hybrid claim.
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

    Ok(row.id)
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

    /// Frozen after retirement (2026-11-02); freshness tests never depend on the wall clock.
    const NOW: i64 = 1_793_577_600;
    use ed25519_dalek::{Signer, SigningKey};

    /// Local Postgres from `ops/docker-compose.dev.yml`; the test skips without it, except
    /// under CI.
    async fn try_db() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:password@127.0.0.1:5432/construct_test".to_string()
        });
        let pool = match PgPool::connect(&url).await {
            Ok(pool) => pool,
            Err(e) => {
                service_absent("Postgres", e);
                return None;
            }
        };
        // A migration that fails is a failed test, not a missing service.
        sqlx::migrate!("../shared/migrations")
            .run(&pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    /// A missing service skips the test on a laptop and fails it under CI (`CI` is set by
    /// GitHub Actions): a run that has the services and still skips proves nothing.
    fn service_absent(what: &str, error: impl std::fmt::Display) {
        assert!(
            std::env::var_os("CI").is_none(),
            "{what} is required under CI: {error}"
        );
        eprintln!("{what} unavailable ({error}) — skipping");
    }

    /// Setting the recovery key writes the address it names in the same statement
    /// (construct-docs `decisions/pubkey-as-identity.md`, "Which key is the address").
    #[tokio::test]
    async fn setting_the_recovery_key_writes_the_account_address() {
        let Some(db) = try_db().await else {
            return;
        };
        let user_id: Uuid =
            sqlx::query_scalar("INSERT INTO users (id) VALUES (gen_random_uuid()) RETURNING id")
                .fetch_one(&db)
                .await
                .unwrap();
        let phrase = Phrase::new();
        let (public, signature, timestamp) = phrase.hybrid_setup(user_id);

        set_recovery_key_at(&db, user_id, &public, &signature, timestamp, None, NOW)
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
        assert_eq!(identity.as_deref(), Some(&public[..32]));
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

    /// A retry with the key already set answers like the first call; another key is refused.
    ///
    /// Mutation: bail on any existing key — the retry fails and this reddens.
    #[tokio::test]
    async fn the_same_key_again_is_accepted_and_another_is_refused() {
        let Some(db) = try_db().await else {
            return;
        };
        let user_id: Uuid =
            sqlx::query_scalar("INSERT INTO users (id) VALUES (gen_random_uuid()) RETURNING id")
                .fetch_one(&db)
                .await
                .unwrap();
        let phrase = Phrase::new();

        let (public, signature, timestamp) = phrase.hybrid_setup(user_id);
        let first = set_recovery_key_at(&db, user_id, &public, &signature, timestamp, None, NOW)
            .await
            .unwrap();
        let (public, signature, timestamp) = phrase.hybrid_setup(user_id);
        let again = set_recovery_key_at(&db, user_id, &public, &signature, timestamp, None, NOW)
            .await
            .expect("the same key again is accepted");
        assert_eq!(first, again);

        let other = Phrase::new();
        let (public, signature, timestamp) = other.hybrid_setup(user_id);
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

    /// A historical database row, not a call to the retired production writer. Keep its
    /// account address exactly as it was so setup/recovery upgrades prove compatibility.
    async fn set_legacy(db: &PgPool, user_id: Uuid, phrase: &Phrase) {
        let public = phrase.legacy().verifying_key().to_bytes();
        let (key_type, route_id) = construct_db::account_address_columns(&public);
        sqlx::query("UPDATE users SET recovery_public_key = $1, identity_public_key = $1, identity_key_type = $2, route_id = $3 WHERE id = $4")
            .bind(public.as_slice()).bind(key_type).bind(route_id).bind(user_id)
            .execute(db).await.unwrap();
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
            RecoveryClaim {
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

    /// A retired 64-byte proof cannot be smuggled into a hybrid-shaped request either.
    async fn legacy_claim(db: &PgPool, user_id: Uuid, phrase: &Phrase) -> Result<Uuid> {
        let challenge = NOW.to_string();
        let signature = phrase.legacy().sign(challenge.as_bytes()).to_bytes();
        let (_, public) = phrase.hybrid();
        let device = Device::new();
        claim(db, user_id, &public, NOW, &signature, &device).await
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
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_hybrid(&db, user_id, &phrase).await.unwrap();

        let err = legacy_claim(&db, user_id, &phrase).await.unwrap_err();
        assert!(
            err.to_string().contains("Invalid recovery signature"),
            "{err}"
        );

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
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_legacy(&db, user_id, &phrase).await;
        assert!(
            legacy_claim(&db, user_id, &phrase).await.is_err(),
            "a legacy account must also prove both halves"
        );

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

    /// A valid signature under a different phrase never recovers this account. Once the
    /// ML-DSA half is stored, even another hybrid key with the same Ed25519 half is refused.
    #[tokio::test]
    async fn a_hybrid_claim_cannot_substitute_either_stored_key_half() {
        let Some(db) = try_db().await else {
            return;
        };
        for hybrid in [false, true] {
            let user_id = new_user(&db).await;
            let phrase = Phrase::new();
            if hybrid {
                set_hybrid(&db, user_id, &phrase).await.unwrap();
            } else {
                set_legacy(&db, user_id, &phrase).await;
            }
            let device = Device::new();
            let attacker = Phrase::new();
            let (public, signature) = attacker.hybrid_claim(NOW, &device);
            assert!(
                claim(&db, user_id, &public, NOW, &signature, &device)
                    .await
                    .is_err()
            );
            assert_eq!(
                is_hybrid(&db, user_id).await,
                hybrid,
                "a failed claim changed the key"
            );
            if hybrid {
                let attacker = Phrase {
                    ed25519: phrase.ed25519,
                    mldsa: rand::random(),
                };
                let (public, signature) = attacker.hybrid_claim(NOW, &device);
                assert!(
                    claim(&db, user_id, &public, NOW, &signature, &device)
                        .await
                        .is_err(),
                    "stored ML-DSA half was substituted"
                );
            }
            // Neither failed proof may poison a valid proof from the original phrase.
            let (public, signature) = phrase.hybrid_claim(NOW, &device);
            assert_eq!(
                claim(&db, user_id, &public, NOW, &signature, &device)
                    .await
                    .unwrap(),
                user_id
            );
            drop_user(&db, user_id).await;
        }
    }

    #[tokio::test]
    async fn hybrid_setup_checks_both_signatures_and_freshness_before_writing() {
        let Some(db) = try_db().await else {
            return;
        };
        for legacy in [false, true] {
            let user_id = new_user(&db).await;
            let phrase = Phrase::new();
            if legacy {
                set_legacy(&db, user_id, &phrase).await;
            }
            let (public, signature, timestamp) = phrase.hybrid_setup(user_id);
            for byte in [0, 64] {
                // Ed25519 and ML-DSA parts, respectively.
                let mut altered = signature.clone();
                altered[byte] ^= 1;
                assert!(
                    set_recovery_key_at(&db, user_id, &public, &altered, timestamp, None, NOW)
                        .await
                        .is_err()
                );
                assert!(!is_hybrid(&db, user_id).await);
                assert_eq!(
                    get_recovery_status(&db, user_id).await.unwrap().is_setup,
                    legacy
                );
            }
            let stale = NOW - claim_bytes::MAX_SKEW_SECS - 1;
            let (private, _) = phrase.hybrid();
            let message =
                claim_bytes::setup_signable(&user_id.to_string(), stale, &public).unwrap();
            let stale_signature = hybrid_sign(&private, &message).unwrap();
            assert!(
                set_recovery_key_at(&db, user_id, &public, &stale_signature, stale, None, NOW)
                    .await
                    .is_err()
            );
            assert!(!is_hybrid(&db, user_id).await);
            set_hybrid(&db, user_id, &phrase).await.unwrap();
            assert!(is_hybrid(&db, user_id).await);
            drop_user(&db, user_id).await;
        }
    }

    /// Retirement is permanent: rolling the server clock back cannot enable old setup.
    #[tokio::test]
    async fn retired_setup_is_rejected_even_if_the_server_clock_goes_back() {
        let Some(db) = try_db().await else {
            return;
        };
        let user_id = new_user(&db).await;
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        for now in [1_793_404_800, NOW] {
            let signature =
                signing.sign(format!("CONSTRUCT_RECOVERY_SETUP:{user_id}:{now}").as_bytes());
            let result = set_recovery_key_at(
                &db,
                user_id,
                &signing.verifying_key().to_bytes(),
                &signature.to_bytes(),
                now,
                None,
                now,
            )
            .await;
            assert!(
                result.is_err(),
                "retired Ed25519 setup was re-enabled by a pre-cutoff clock"
            );
            assert!(!get_recovery_status(&db, user_id).await.unwrap().is_setup);
        }
        drop_user(&db, user_id).await;
    }

    #[tokio::test]
    async fn malformed_or_legacy_keys_are_rejected_before_database_access() {
        // No connection is established. A DB lookup before the shape check fails this test.
        let db = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://postgres@127.0.0.1:9/unreachable")
            .unwrap();
        let device = Device::new();
        for len in [
            0,
            31,
            32,
            HYBRID_RECOVERY_KEY_LEN - 1,
            HYBRID_RECOVERY_KEY_LEN + 1,
        ] {
            let public = vec![0; len];
            let setup = set_recovery_key_at(&db, Uuid::new_v4(), &public, &[0; 64], NOW, None, NOW)
                .await
                .unwrap_err();
            assert!(
                setup.to_string().contains("1984-byte hybrid public key"),
                "{setup}"
            );
            let recovery = claim(&db, Uuid::new_v4(), &public, NOW, &[0; 64], &device)
                .await
                .unwrap_err();
            assert!(
                recovery.to_string().contains("1984-byte hybrid public key"),
                "{recovery}"
            );
        }
    }

    /// A historical account is recovered by its phrase's hybrid proof and keeps its address.
    #[tokio::test]
    async fn a_legacy_account_recovers_with_the_same_address_after_retirement() {
        let Some(db) = try_db().await else {
            return;
        };
        let user_id = new_user(&db).await;
        let phrase = Phrase::new();
        set_legacy(&db, user_id, &phrase).await;
        let before = get_recovery_status(&db, user_id).await.unwrap();
        let address_before: (Option<Vec<u8>>, Option<String>) =
            sqlx::query_as("SELECT identity_public_key, route_id FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&db)
                .await
                .unwrap();
        let device = Device::new();
        let (public, signature) = phrase.hybrid_claim(NOW, &device);
        let recovered = claim(&db, user_id, &public, NOW, &signature, &device)
            .await
            .unwrap();
        assert_eq!(recovered, user_id);
        let after = get_recovery_status(&db, user_id).await.unwrap();
        assert!(after.is_hybrid);
        assert_eq!(after.fingerprint, before.fingerprint);
        let stored: (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<String>) = sqlx::query_as("SELECT recovery_public_key, recovery_mldsa_public_key, identity_public_key, route_id FROM users WHERE id = $1").bind(user_id).fetch_one(&db).await.unwrap();
        assert_eq!(stored.0, public[..32]);
        assert_eq!(stored.1, public[32..]);
        assert_eq!((stored.2, stored.3), address_before);
        drop_user(&db, user_id).await;
    }
}
