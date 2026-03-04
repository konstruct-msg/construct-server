// ============================================================================
// HashiCorp Vault Client
// ============================================================================
//
// Supports:
// - Transit secrets engine for key operations
// - KV secrets engine for static secrets
// - Kubernetes authentication (for production)
// - Token authentication (for development)
//
// ============================================================================

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use super::KeyManagementConfig;

/// Vault client for key management operations
pub struct VaultClient {
    client: Client,
    addr: String,
    token: Arc<RwLock<String>>,
    k8s_role: Option<String>,
}

#[derive(Debug, Serialize)]
struct TransitSignRequest<'a> {
    input: &'a str, // base64 encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct TransitSignResponse {
    data: TransitSignData,
}

#[derive(Debug, Deserialize)]
struct TransitSignData {
    signature: String,
    key_version: i32,
}

#[derive(Debug, Serialize)]
struct TransitVerifyRequest<'a> {
    input: &'a str, // base64 encoded
    signature: &'a str,
}

#[derive(Debug, Deserialize)]
struct TransitVerifyResponse {
    data: TransitVerifyData,
}

#[derive(Debug, Deserialize)]
struct TransitVerifyData {
    valid: bool,
}

#[derive(Debug, Serialize)]
struct TransitEncryptRequest<'a> {
    plaintext: &'a str, // base64 encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct TransitEncryptResponse {
    data: TransitEncryptData,
}

#[derive(Debug, Deserialize)]
struct TransitEncryptData {
    ciphertext: String,
    key_version: i32,
}

#[derive(Debug, Serialize)]
struct TransitDecryptRequest<'a> {
    ciphertext: &'a str,
}

#[derive(Debug, Deserialize)]
struct TransitDecryptResponse {
    data: TransitDecryptData,
}

#[derive(Debug, Deserialize)]
struct TransitDecryptData {
    plaintext: String, // base64 encoded
}

#[derive(Debug, Deserialize)]
struct TransitKeyResponse {
    data: TransitKeyData,
}

#[derive(Debug, Deserialize)]
pub struct TransitKeyData {
    latest_version: i32,
    keys: std::collections::HashMap<String, TransitKeyVersion>,
}

#[derive(Debug, Deserialize)]
struct TransitKeyVersion {
    public_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct K8sLoginRequest<'a> {
    jwt: &'a str,
    role: &'a str,
}

#[derive(Debug, Deserialize)]
struct VaultAuthResponse {
    auth: VaultAuth,
}

#[derive(Debug, Deserialize)]
struct VaultAuth {
    client_token: String,
}

impl VaultClient {
    /// Create a new Vault client
    pub async fn new(config: &KeyManagementConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        let token = if let Some(ref token) = config.vault_token {
            // Direct token auth (development)
            token.clone()
        } else if let Some(ref role) = config.vault_k8s_role {
            // Kubernetes auth (production)
            Self::k8s_login(&client, &config.vault_addr, role).await?
        } else {
            return Err(anyhow::anyhow!(
                "Either VAULT_TOKEN or VAULT_K8S_ROLE must be set"
            ));
        };

        let client = Self {
            client,
            addr: config.vault_addr.clone(),
            token: Arc::new(RwLock::new(token)),
            k8s_role: config.vault_k8s_role.clone(),
        };

        // Start token renewal loop if using K8s auth
        if config.vault_k8s_role.is_some() {
            let client_clone = client.clone_for_renewal();
            tokio::spawn(async move {
                client_clone.token_renewal_loop().await;
            });
        }

        Ok(client)
    }

    /// Kubernetes authentication
    async fn k8s_login(client: &Client, vault_addr: &str, role: &str) -> Result<String> {
        // Read service account token
        let jwt = tokio::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .await
            .context("Failed to read K8s service account token")?;

        let url = format!("{}/v1/auth/kubernetes/login", vault_addr);
        let request = K8sLoginRequest { jwt: &jwt, role };

        let response: VaultAuthResponse = client
            .post(&url)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.auth.client_token)
    }

    fn clone_for_renewal(&self) -> VaultClientRenewal {
        VaultClientRenewal {
            client: self.client.clone(),
            addr: self.addr.clone(),
            token: self.token.clone(),
            k8s_role: self.k8s_role.clone(),
        }
    }

    /// Get token for requests
    async fn get_token(&self) -> String {
        self.token.read().await.clone()
    }

    /// Sign data using Transit engine
    pub async fn sign(
        &self,
        key_name: &str,
        data: &[u8],
        key_version: Option<i32>,
    ) -> Result<(String, i32)> {
        let input = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);

        let url = format!("{}/v1/transit/sign/{}", self.addr, key_name);
        let request = TransitSignRequest {
            input: &input,
            key_version,
            signature_algorithm: Some("pkcs1v15"), // For RSA
        };

        let response: TransitSignResponse = self
            .client
            .post(&url)
            .header("X-Vault-Token", self.get_token().await)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok((response.data.signature, response.data.key_version))
    }

    /// Verify signature using Transit engine
    pub async fn verify(&self, key_name: &str, data: &[u8], signature: &str) -> Result<bool> {
        let input = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);

        let url = format!("{}/v1/transit/verify/{}", self.addr, key_name);
        let request = TransitVerifyRequest {
            input: &input,
            signature,
        };

        let response: TransitVerifyResponse = self
            .client
            .post(&url)
            .header("X-Vault-Token", self.get_token().await)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.data.valid)
    }

    /// Encrypt data using Transit engine
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        key_version: Option<i32>,
    ) -> Result<(String, i32)> {
        let input = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plaintext);

        let url = format!("{}/v1/transit/encrypt/{}", self.addr, key_name);
        let request = TransitEncryptRequest {
            plaintext: &input,
            key_version,
        };

        let response: TransitEncryptResponse = self
            .client
            .post(&url)
            .header("X-Vault-Token", self.get_token().await)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok((response.data.ciphertext, response.data.key_version))
    }

    /// Decrypt data using Transit engine
    pub async fn decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>> {
        let url = format!("{}/v1/transit/decrypt/{}", self.addr, key_name);
        let request = TransitDecryptRequest { ciphertext };

        let response: TransitDecryptResponse = self
            .client
            .post(&url)
            .header("X-Vault-Token", self.get_token().await)
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let plaintext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &response.data.plaintext,
        )?;

        Ok(plaintext)
    }

    /// Rotate a key in Transit engine
    pub async fn rotate_key(&self, key_name: &str) -> Result<i32> {
        let url = format!("{}/v1/transit/keys/{}/rotate", self.addr, key_name);

        self.client
            .post(&url)
            .header("X-Vault-Token", self.get_token().await)
            .send()
            .await?
            .error_for_status()?;

        // Get the new version
        let key_info = self.get_key_info(key_name).await?;
        Ok(key_info.latest_version)
    }

    /// Get key information
    pub async fn get_key_info(&self, key_name: &str) -> Result<TransitKeyData> {
        let url = format!("{}/v1/transit/keys/{}", self.addr, key_name);

        let response: TransitKeyResponse = self
            .client
            .get(&url)
            .header("X-Vault-Token", self.get_token().await)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.data)
    }

    /// Get public key for a specific version (for JWT verification without Vault)
    pub async fn get_public_key(&self, key_name: &str, version: i32) -> Result<Option<String>> {
        let key_info = self.get_key_info(key_name).await?;
        Ok(key_info
            .keys
            .get(&version.to_string())
            .and_then(|v| v.public_key.clone()))
    }

    /// Read a secret from KV v2 engine
    pub async fn read_secret(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}/v1/secret/data/{}", self.addr, path);

        let response: serde_json::Value = self
            .client
            .get(&url)
            .header("X-Vault-Token", self.get_token().await)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response["data"]["data"].clone())
    }
}

/// Separate struct for token renewal to avoid holding references
struct VaultClientRenewal {
    client: Client,
    addr: String,
    token: Arc<RwLock<String>>,
    k8s_role: Option<String>,
}

impl VaultClientRenewal {
    async fn token_renewal_loop(&self) {
        // Renew token every 30 minutes
        let mut interval = tokio::time::interval(Duration::from_secs(30 * 60));

        loop {
            interval.tick().await;

            if let Some(ref role) = self.k8s_role {
                match VaultClient::k8s_login(&self.client, &self.addr, role).await {
                    Ok(new_token) => {
                        let mut token = self.token.write().await;
                        *token = new_token;
                        tracing::debug!("Vault token renewed via K8s auth");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to renew Vault token");
                    }
                }
            }
        }
    }
}
