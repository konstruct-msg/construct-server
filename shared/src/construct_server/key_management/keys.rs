// ============================================================================
// Key Manager - Production Key Storage and Operations
// ============================================================================

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::vault::VaultClient;
use crate::db::DbPool;

/// Types of managed keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// JWT signing (RS256)
    Jwt,
    /// APNS device token encryption (ChaCha20-Poly1305)
    ApnsEncryption,
    /// Federation server signing (Ed25519)
    Federation,
    /// Database encryption (AES-256-GCM)
    DatabaseEncryption,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Jwt => write!(f, "jwt"),
            KeyType::ApnsEncryption => write!(f, "apns"),
            KeyType::Federation => write!(f, "federation"),
            KeyType::DatabaseEncryption => write!(f, "database"),
        }
    }
}

/// A managed key with metadata
#[derive(Debug, Clone)]
pub struct ManagedKey {
    pub key_id: String,
    pub key_type: KeyType,
    pub vault_path: String,
    pub vault_version: i32,
    pub algorithm: String,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub deprecated_at: Option<DateTime<Utc>>,
    /// Cached public key for JWT verification (avoids Vault calls)
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Rotating,
    Deprecated,
    Revoked,
}

impl From<&str> for KeyStatus {
    fn from(s: &str) -> Self {
        match s {
            "active" => KeyStatus::Active,
            "rotating" => KeyStatus::Rotating,
            "deprecated" => KeyStatus::Deprecated,
            "revoked" => KeyStatus::Revoked,
            _ => KeyStatus::Revoked, // Default to most restrictive
        }
    }
}

/// Database row for master_keys
#[derive(Debug, sqlx::FromRow)]
struct MasterKeyRow {
    key_id: String,
    key_type: String,
    vault_path: String,
    vault_version: i32,
    algorithm: String,
    status: String,
    created_at: DateTime<Utc>,
    activated_at: Option<DateTime<Utc>>,
    deprecated_at: Option<DateTime<Utc>>,
}

/// Central key manager
pub struct KeyManager {
    /// All loaded keys by type
    keys_by_type: HashMap<KeyType, Vec<ManagedKey>>,
    /// Quick lookup by key_id
    keys_by_id: HashMap<String, ManagedKey>,
    /// Grace period for deprecated keys
    grace_period: Duration,
    /// When keys were last loaded
    loaded_at: DateTime<Utc>,
}

impl KeyManager {
    /// Load all keys from database and Vault
    pub async fn load_from_db_and_vault(db: &DbPool, vault: &VaultClient) -> Result<Self> {
        let grace_period_secs: i64 = std::env::var("KEY_GRACE_PERIOD_SECS")
            .unwrap_or_else(|_| "604800".to_string())
            .parse()
            .unwrap_or(604800);
        let grace_period = Duration::seconds(grace_period_secs);

        // Load key metadata from database
        let rows: Vec<MasterKeyRow> = sqlx::query_as(
            r#"
            SELECT key_id, key_type, vault_path, vault_version, algorithm,
                   status, created_at, activated_at, deprecated_at
            FROM master_keys
            WHERE status IN ('active', 'rotating', 'deprecated')
              AND (revoked_at IS NULL)
              AND (deprecated_at IS NULL OR deprecated_at > NOW() - $1::interval)
            ORDER BY key_type, status = 'active' DESC, activated_at DESC
            "#,
        )
        .bind(format!("{} seconds", grace_period_secs))
        .fetch_all(db)
        .await
        .context("Failed to load keys from database")?;

        let mut keys_by_type: HashMap<KeyType, Vec<ManagedKey>> = HashMap::new();
        let mut keys_by_id: HashMap<String, ManagedKey> = HashMap::new();

        for row in rows {
            let key_type = match row.key_type.as_str() {
                "jwt" => KeyType::Jwt,
                "apns" => KeyType::ApnsEncryption,
                "federation" => KeyType::Federation,
                "database" => KeyType::DatabaseEncryption,
                _ => continue, // Unknown key type, skip
            };

            // For JWT keys, fetch the public key from Vault for local verification
            let public_key = if key_type == KeyType::Jwt {
                match vault
                    .get_public_key(&row.vault_path, row.vault_version)
                    .await
                {
                    Ok(Some(pk)) => Some(pk.into_bytes()),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(
                            key_id = %row.key_id,
                            error = %e,
                            "Failed to fetch public key from Vault"
                        );
                        None
                    }
                }
            } else {
                None
            };

            let key = ManagedKey {
                key_id: row.key_id.clone(),
                key_type,
                vault_path: row.vault_path,
                vault_version: row.vault_version,
                algorithm: row.algorithm,
                status: KeyStatus::from(row.status.as_str()),
                created_at: row.created_at,
                activated_at: row.activated_at,
                deprecated_at: row.deprecated_at,
                public_key,
            };

            keys_by_type.entry(key_type).or_default().push(key.clone());
            keys_by_id.insert(row.key_id, key);
        }

        Ok(Self {
            keys_by_type,
            keys_by_id,
            grace_period,
            loaded_at: Utc::now(),
        })
    }

    /// Get the active (primary) key for signing/encryption
    pub fn get_active_key(&self, key_type: KeyType) -> Option<&ManagedKey> {
        self.keys_by_type
            .get(&key_type)
            .and_then(|keys| keys.iter().find(|k| k.status == KeyStatus::Active))
    }

    /// Get all valid keys for verification/decryption (active + deprecated within grace)
    pub fn get_valid_keys(&self, key_type: KeyType) -> Vec<&ManagedKey> {
        self.keys_by_type
            .get(&key_type)
            .map(|keys| {
                keys.iter()
                    .filter(|k| {
                        k.status == KeyStatus::Active
                            || (k.status == KeyStatus::Deprecated
                                && k.deprecated_at
                                    .map(|d| Utc::now() - d < self.grace_period)
                                    .unwrap_or(false))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a key by its ID
    pub fn get_key_by_id(&self, key_id: &str) -> Option<&ManagedKey> {
        self.keys_by_id.get(key_id)
    }

    /// Sign JWT claims using the active JWT key
    pub async fn sign_jwt<T: Serialize>(&self, vault: &VaultClient, claims: &T) -> Result<String> {
        let key = self
            .get_active_key(KeyType::Jwt)
            .ok_or_else(|| anyhow::anyhow!("No active JWT key"))?;

        // Create header with key ID
        let header = Header {
            alg: Algorithm::RS256,
            kid: Some(key.key_id.clone()),
            ..Default::default()
        };

        // Encode claims to JSON
        let claims_json = serde_json::to_string(claims)?;

        // Sign using Vault
        let message = format!(
            "{}.{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                serde_json::to_string(&header)?
            ),
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &claims_json
            )
        );

        let (signature, _version) = vault
            .sign(&key.vault_path, message.as_bytes(), Some(key.vault_version))
            .await?;

        // Extract just the signature part from Vault's format (vault:v1:...)
        let sig_part = signature.strip_prefix("vault:v1:").unwrap_or(&signature);

        Ok(format!("{}.{}", message, sig_part))
    }

    /// Verify JWT and return claims
    pub fn verify_jwt<T: for<'de> Deserialize<'de>>(&self, token: &str) -> Result<T> {
        // Extract key ID from token header
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header
            .kid
            .ok_or_else(|| anyhow::anyhow!("Token missing key ID (kid)"))?;

        // Find the key
        let key = self
            .get_key_by_id(&kid)
            .ok_or_else(|| anyhow::anyhow!("Unknown key ID: {}", kid))?;

        // Check key is valid
        if key.status == KeyStatus::Revoked {
            return Err(anyhow::anyhow!("Key has been revoked"));
        }

        if key.status == KeyStatus::Deprecated
            && let Some(deprecated_at) = key.deprecated_at
            && Utc::now() - deprecated_at >= self.grace_period
        {
            return Err(anyhow::anyhow!("Key has expired grace period"));
        }

        // Get public key for verification
        let public_key = key
            .public_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No public key available for verification"))?;

        let decoding_key = DecodingKey::from_rsa_pem(public_key)?;
        let validation = Validation::new(Algorithm::RS256);

        let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Encrypt data using the active encryption key
    pub async fn encrypt(
        &self,
        vault: &VaultClient,
        key_type: KeyType,
        plaintext: &[u8],
    ) -> Result<EncryptedData> {
        let key = self
            .get_active_key(key_type)
            .ok_or_else(|| anyhow::anyhow!("No active {} key", key_type))?;

        let (ciphertext, version) = vault
            .encrypt(&key.vault_path, plaintext, Some(key.vault_version))
            .await?;

        Ok(EncryptedData {
            key_id: key.key_id.clone(),
            key_version: version,
            ciphertext,
        })
    }

    /// Decrypt data
    pub async fn decrypt(&self, vault: &VaultClient, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        let key = self
            .get_key_by_id(&encrypted.key_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown key ID: {}", encrypted.key_id))?;

        if key.status == KeyStatus::Revoked {
            return Err(anyhow::anyhow!("Key has been revoked, cannot decrypt"));
        }

        vault.decrypt(&key.vault_path, &encrypted.ciphertext).await
    }

    /// Check if keys need refresh
    pub fn needs_refresh(&self, max_age: Duration) -> bool {
        Utc::now() - self.loaded_at > max_age
    }
}

/// Encrypted data with key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub key_id: String,
    pub key_version: i32,
    pub ciphertext: String,
}

impl EncryptedData {
    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("Failed to deserialize encrypted data")
    }
}
