// ============================================================================
// Production Key Management Module
// ============================================================================
//
// Features:
// - HashiCorp Vault integration
// - Hot reload without service restart
// - Automatic rotation with grace periods
// - Audit logging
// - Emergency revocation
//
// ============================================================================

pub mod audit;
pub mod keys;
pub mod rotation;
pub mod vault;

use crate::db::DbPool;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

pub use keys::{KeyManager, KeyType, ManagedKey};
pub use rotation::{RotationPolicy, RotationScheduler};
pub use vault::VaultClient;

/// Central key management system
pub struct KeyManagementSystem {
    vault: Arc<VaultClient>,
    db: Arc<DbPool>,
    key_manager: Arc<RwLock<KeyManager>>,
    rotation_scheduler: Arc<RotationScheduler>,
    config: Arc<KeyManagementConfig>,
}

#[derive(Debug, Clone)]
pub struct KeyManagementConfig {
    /// Vault address
    pub vault_addr: String,
    /// Vault token (or use Kubernetes auth)
    pub vault_token: Option<String>,
    /// Vault Kubernetes auth role
    pub vault_k8s_role: Option<String>,
    /// Key refresh interval (how often to check for new keys)
    pub refresh_interval_secs: u64,
    /// Grace period for old keys (must be >= max token TTL)
    pub grace_period_secs: u64,
    /// Enable automatic rotation
    pub auto_rotation_enabled: bool,
}

impl Default for KeyManagementConfig {
    fn default() -> Self {
        Self {
            vault_addr: "http://127.0.0.1:8200".to_string(),
            vault_token: None,
            vault_k8s_role: None,
            refresh_interval_secs: 60,
            grace_period_secs: 7 * 24 * 3600, // 7 days
            auto_rotation_enabled: true,
        }
    }
}

impl KeyManagementConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            vault_addr: std::env::var("VAULT_ADDR")
                .unwrap_or_else(|_| "http://127.0.0.1:8200".to_string()),
            vault_token: std::env::var("VAULT_TOKEN").ok(),
            vault_k8s_role: std::env::var("VAULT_K8S_ROLE").ok(),
            refresh_interval_secs: std::env::var("KEY_REFRESH_INTERVAL_SECS")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            grace_period_secs: std::env::var("KEY_GRACE_PERIOD_SECS")
                .unwrap_or_else(|_| "604800".to_string()) // 7 days
                .parse()
                .unwrap_or(604800),
            auto_rotation_enabled: std::env::var("KEY_AUTO_ROTATION_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        })
    }
}

impl KeyManagementSystem {
    /// Initialize the key management system
    pub async fn new(db: Arc<DbPool>, config: KeyManagementConfig) -> Result<Self> {
        let config = Arc::new(config);

        // Initialize Vault client
        let vault = Arc::new(VaultClient::new(&config).await?);

        // Initialize key manager with current keys from DB + Vault
        let key_manager = Arc::new(RwLock::new(
            KeyManager::load_from_db_and_vault(&db, &vault).await?,
        ));

        // Initialize rotation scheduler
        let rotation_scheduler = Arc::new(RotationScheduler::new(
            db.clone(),
            vault.clone(),
            key_manager.clone(),
        ));

        Ok(Self {
            vault,
            db,
            key_manager,
            rotation_scheduler,
            config,
        })
    }

    /// Start background tasks (key refresh, rotation)
    pub async fn start(&self) -> Result<()> {
        // Start key refresh loop
        let key_manager = self.key_manager.clone();
        let db = self.db.clone();
        let vault = self.vault.clone();
        let refresh_interval = self.config.refresh_interval_secs;

        tokio::spawn(async move {
            Self::key_refresh_loop(key_manager, db, vault, refresh_interval).await;
        });

        // Start rotation scheduler if enabled
        if self.config.auto_rotation_enabled {
            self.rotation_scheduler.start().await?;
        }

        Ok(())
    }

    /// Background loop to refresh keys from DB/Vault
    async fn key_refresh_loop(
        key_manager: Arc<RwLock<KeyManager>>,
        db: Arc<DbPool>,
        vault: Arc<VaultClient>,
        interval_secs: u64,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            match KeyManager::load_from_db_and_vault(&db, &vault).await {
                Ok(new_manager) => {
                    let mut manager = key_manager.write().await;
                    *manager = new_manager;
                    tracing::debug!("Keys refreshed successfully");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to refresh keys");
                    // Don't panic - keep using old keys
                }
            }
        }
    }

    /// Get the key manager for signing/verification
    pub fn key_manager(&self) -> Arc<RwLock<KeyManager>> {
        self.key_manager.clone()
    }

    /// Trigger manual key rotation
    pub async fn rotate_key(
        &self,
        key_type: KeyType,
        reason: &str,
        initiated_by: &str,
    ) -> Result<String> {
        self.rotation_scheduler
            .rotate_now(key_type, reason, initiated_by)
            .await
    }

    /// Emergency key revocation
    pub async fn emergency_revoke(
        &self,
        key_id: &str,
        reason: &str,
        initiated_by: &str,
    ) -> Result<()> {
        tracing::warn!(
            key_id = %key_id,
            reason = %reason,
            initiated_by = %initiated_by,
            "EMERGENCY KEY REVOCATION"
        );

        // Revoke in database
        sqlx::query("SELECT emergency_revoke_key($1, $2, $3)")
            .bind(key_id)
            .bind(initiated_by)
            .bind(reason)
            .execute(&*self.db)
            .await?;

        // Refresh keys immediately
        let new_manager = KeyManager::load_from_db_and_vault(&self.db, &self.vault).await?;
        let mut manager = self.key_manager.write().await;
        *manager = new_manager;

        // Alert (in production, this would go to PagerDuty, etc.)
        audit::log_emergency_revocation(&self.db, key_id, reason, initiated_by).await?;

        Ok(())
    }
}
