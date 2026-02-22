// ============================================================================
// Key Rotation Scheduler
// ============================================================================
//
// Automatic key rotation with:
// - Configurable policies per key type
// - Graceful transitions (no service disruption)
// - Audit logging
// - Alert integration
//
// ============================================================================

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::audit;
use super::keys::{KeyManager, KeyType};
use super::vault::VaultClient;
use crate::db::DbPool;

/// Rotation policy for a key type
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Key type this policy applies to
    pub key_type: KeyType,
    /// How often to rotate (e.g., 90 days for JWT)
    pub rotation_interval: Duration,
    /// Minimum time before forced rotation
    pub min_age: Duration,
    /// Grace period after rotation (old key still valid for verification)
    pub grace_period: Duration,
    /// Whether automatic rotation is enabled
    pub enabled: bool,
    /// Cron expression for rotation schedule (optional, for specific timing)
    pub cron_schedule: Option<String>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            key_type: KeyType::Jwt,
            rotation_interval: Duration::days(90),
            min_age: Duration::days(7),
            grace_period: Duration::days(7),
            enabled: true,
            cron_schedule: None,
        }
    }
}

impl RotationPolicy {
    /// Create JWT signing key policy (90 days, 7 day grace)
    pub fn jwt() -> Self {
        Self {
            key_type: KeyType::Jwt,
            rotation_interval: Duration::days(90),
            min_age: Duration::days(7),
            grace_period: Duration::days(7),
            enabled: true,
            cron_schedule: None,
        }
    }

    /// Create APNS encryption key policy (180 days)
    pub fn apns() -> Self {
        Self {
            key_type: KeyType::ApnsEncryption,
            rotation_interval: Duration::days(180),
            min_age: Duration::days(14),
            grace_period: Duration::days(14),
            enabled: true,
            cron_schedule: None,
        }
    }

    /// Create federation key policy (365 days, longer grace for federation peers)
    pub fn federation() -> Self {
        Self {
            key_type: KeyType::Federation,
            rotation_interval: Duration::days(365),
            min_age: Duration::days(30),
            grace_period: Duration::days(30),
            enabled: true,
            cron_schedule: None,
        }
    }

    /// Create database encryption key policy (yearly)
    pub fn database() -> Self {
        Self {
            key_type: KeyType::DatabaseEncryption,
            rotation_interval: Duration::days(365),
            min_age: Duration::days(30),
            grace_period: Duration::days(7),
            enabled: true,
            cron_schedule: None,
        }
    }
}

/// Key rotation scheduler
pub struct RotationScheduler {
    db: Arc<DbPool>,
    vault: Arc<VaultClient>,
    key_manager: Arc<RwLock<KeyManager>>,
    policies: HashMap<KeyType, RotationPolicy>,
    /// Track ongoing rotations to prevent duplicates
    active_rotations: Arc<RwLock<HashMap<KeyType, DateTime<Utc>>>>,
}

impl RotationScheduler {
    /// Create a new rotation scheduler
    pub fn new(
        db: Arc<DbPool>,
        vault: Arc<VaultClient>,
        key_manager: Arc<RwLock<KeyManager>>,
    ) -> Self {
        let mut policies = HashMap::new();
        policies.insert(KeyType::Jwt, RotationPolicy::jwt());
        policies.insert(KeyType::ApnsEncryption, RotationPolicy::apns());
        policies.insert(KeyType::Federation, RotationPolicy::federation());
        policies.insert(KeyType::DatabaseEncryption, RotationPolicy::database());

        Self {
            db,
            vault,
            key_manager,
            policies,
            active_rotations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the rotation scheduler background task
    pub async fn start(&self) -> Result<()> {
        let db = self.db.clone();
        let vault = self.vault.clone();
        let key_manager = self.key_manager.clone();
        let policies = self.policies.clone();
        let active_rotations = self.active_rotations.clone();

        tokio::spawn(async move {
            Self::rotation_loop(db, vault, key_manager, policies, active_rotations).await;
        });

        tracing::info!("Key rotation scheduler started");
        Ok(())
    }

    /// Background loop checking for keys that need rotation
    async fn rotation_loop(
        db: Arc<DbPool>,
        vault: Arc<VaultClient>,
        key_manager: Arc<RwLock<KeyManager>>,
        policies: HashMap<KeyType, RotationPolicy>,
        active_rotations: Arc<RwLock<HashMap<KeyType, DateTime<Utc>>>>,
    ) {
        // Check every hour
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));

        loop {
            interval.tick().await;

            for (key_type, policy) in &policies {
                if !policy.enabled {
                    continue;
                }

                // Check if rotation is already in progress
                {
                    let rotations = active_rotations.read().await;
                    if rotations.contains_key(key_type) {
                        continue;
                    }
                }

                // Check if key needs rotation
                let needs_rotation = {
                    let manager = key_manager.read().await;
                    Self::check_needs_rotation(&manager, *key_type, policy)
                };

                if needs_rotation {
                    tracing::info!(key_type = %key_type, "Starting scheduled key rotation");

                    // Mark rotation as active
                    {
                        let mut rotations = active_rotations.write().await;
                        rotations.insert(*key_type, Utc::now());
                    }

                    // Perform rotation
                    match Self::perform_rotation(
                        &db,
                        &vault,
                        &key_manager,
                        *key_type,
                        "scheduled",
                        "system:scheduler",
                    )
                    .await
                    {
                        Ok(new_key_id) => {
                            tracing::info!(
                                key_type = %key_type,
                                new_key_id = %new_key_id,
                                "Key rotation completed successfully"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                key_type = %key_type,
                                error = %e,
                                "Key rotation failed"
                            );
                        }
                    }

                    // Remove from active rotations
                    {
                        let mut rotations = active_rotations.write().await;
                        rotations.remove(key_type);
                    }
                }
            }
        }
    }

    /// Check if a key needs rotation based on policy
    fn check_needs_rotation(
        manager: &KeyManager,
        key_type: KeyType,
        policy: &RotationPolicy,
    ) -> bool {
        let active_key = match manager.get_active_key(key_type) {
            Some(key) => key,
            None => {
                // No active key - definitely needs one
                tracing::warn!(key_type = %key_type, "No active key found");
                return true;
            }
        };

        // Check if key has been active long enough
        if let Some(activated_at) = active_key.activated_at {
            let age = Utc::now() - activated_at;

            // Don't rotate if key is too new
            if age < policy.min_age {
                return false;
            }

            // Rotate if key is older than rotation interval
            if age >= policy.rotation_interval {
                tracing::info!(
                    key_type = %key_type,
                    key_id = %active_key.key_id,
                    age_days = age.num_days(),
                    "Key exceeds rotation interval"
                );
                return true;
            }
        }

        false
    }

    /// Perform the actual key rotation
    async fn perform_rotation(
        db: &DbPool,
        vault: &VaultClient,
        key_manager: &Arc<RwLock<KeyManager>>,
        key_type: KeyType,
        reason: &str,
        initiated_by: &str,
    ) -> Result<String> {
        let start_time = std::time::Instant::now();

        // Generate new key ID
        let new_key_id = format!("{}_{}", key_type, Uuid::new_v4());

        // Get vault path for key type
        let vault_path = Self::get_vault_path(key_type);
        let algorithm = Self::get_algorithm(key_type);

        // Rotate key in Vault first
        let new_version = vault
            .rotate_key(&vault_path)
            .await
            .context("Failed to rotate key in Vault")?;

        tracing::debug!(
            key_type = %key_type,
            vault_path = %vault_path,
            new_version = new_version,
            "Key rotated in Vault"
        );

        // Start rotation in database (atomic transaction)
        sqlx::query("SELECT start_key_rotation($1, $2, $3, $4, $5, $6, $7)")
            .bind(key_type.to_string())
            .bind(&new_key_id)
            .bind(&vault_path)
            .bind(new_version)
            .bind(&algorithm)
            .bind(initiated_by)
            .bind(reason)
            .execute(db)
            .await
            .context("Failed to start key rotation in database")?;

        // Complete rotation (mark old key as deprecated)
        sqlx::query("SELECT complete_key_rotation($1, $2)")
            .bind(key_type.to_string())
            .bind(initiated_by)
            .execute(db)
            .await
            .context("Failed to complete key rotation")?;

        // Refresh key manager
        let new_manager = KeyManager::load_from_db_and_vault(db, vault).await?;
        {
            let mut manager = key_manager.write().await;
            *manager = new_manager;
        }

        // Log successful rotation
        let duration = start_time.elapsed();
        audit::log_rotation_completed(
            db,
            key_type,
            &new_key_id,
            initiated_by,
            duration.as_millis() as i32,
        )
        .await?;

        Ok(new_key_id)
    }

    /// Trigger immediate rotation (manual or emergency)
    pub async fn rotate_now(
        &self,
        key_type: KeyType,
        reason: &str,
        initiated_by: &str,
    ) -> Result<String> {
        // Check if rotation is already in progress
        {
            let rotations = self.active_rotations.read().await;
            if let Some(started_at) = rotations.get(&key_type) {
                return Err(anyhow::anyhow!(
                    "Rotation already in progress for {} (started at {})",
                    key_type,
                    started_at
                ));
            }
        }

        // Mark rotation as active
        {
            let mut rotations = self.active_rotations.write().await;
            rotations.insert(key_type, Utc::now());
        }

        let result = Self::perform_rotation(
            &self.db,
            &self.vault,
            &self.key_manager,
            key_type,
            reason,
            initiated_by,
        )
        .await;

        // Remove from active rotations
        {
            let mut rotations = self.active_rotations.write().await;
            rotations.remove(&key_type);
        }

        result
    }

    /// Get Vault transit key path for key type
    fn get_vault_path(key_type: KeyType) -> String {
        match key_type {
            KeyType::Jwt => "jwt-signing".to_string(),
            KeyType::ApnsEncryption => "apns-encryption".to_string(),
            KeyType::Federation => "federation-signing".to_string(),
            KeyType::DatabaseEncryption => "database-encryption".to_string(),
        }
    }

    /// Get algorithm for key type
    fn get_algorithm(key_type: KeyType) -> String {
        match key_type {
            KeyType::Jwt => "RS256".to_string(),
            KeyType::ApnsEncryption => "ChaCha20-Poly1305".to_string(),
            KeyType::Federation => "Ed25519".to_string(),
            KeyType::DatabaseEncryption => "AES-256-GCM".to_string(),
        }
    }

    /// Update rotation policy
    pub fn set_policy(&mut self, policy: RotationPolicy) {
        self.policies.insert(policy.key_type, policy);
    }

    /// Get current policies
    pub fn get_policies(&self) -> &HashMap<KeyType, RotationPolicy> {
        &self.policies
    }

    /// Check rotation status for a key type
    pub async fn get_rotation_status(&self, key_type: KeyType) -> RotationStatus {
        let rotations = self.active_rotations.read().await;
        if let Some(started_at) = rotations.get(&key_type) {
            return RotationStatus::InProgress {
                started_at: *started_at,
            };
        }

        let manager = self.key_manager.read().await;
        if let Some(key) = manager.get_active_key(key_type)
            && let Some(policy) = self.policies.get(&key_type)
            && let Some(activated_at) = key.activated_at
        {
            let age = Utc::now() - activated_at;
            let next_rotation = activated_at + policy.rotation_interval;

            return RotationStatus::Scheduled {
                current_key_id: key.key_id.clone(),
                activated_at,
                age_days: age.num_days(),
                next_rotation,
            };
        }

        RotationStatus::NoActiveKey
    }
}

/// Status of key rotation
#[derive(Debug, Clone)]
pub enum RotationStatus {
    /// Rotation is currently in progress
    InProgress { started_at: DateTime<Utc> },
    /// Key is scheduled for rotation
    Scheduled {
        current_key_id: String,
        activated_at: DateTime<Utc>,
        age_days: i64,
        next_rotation: DateTime<Utc>,
    },
    /// No active key exists
    NoActiveKey,
}
