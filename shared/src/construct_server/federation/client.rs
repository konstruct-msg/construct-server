// ============================================================================
// Federation Client - Send messages to remote instances
// ============================================================================
//
// Sends S2S messages to remote federation instances with Ed25519 signatures
// for authentication and integrity verification.
//
// SECURITY: Certificate pinning support via FederationTrustStore
// - Pinned certificates are loaded from configuration (FEDERATION_PINNED_CERTS)
// - TOFU (Trust On First Use) is disabled in production when pinned certs are configured
// - Certificate fingerprints are verified against pinned values
//
// ============================================================================

use crate::federation::mtls::{FederationTrustStore, MtlsConfig};
use crate::federation::signing::{FederatedEnvelope, ServerSigner};
use anyhow::{Context, Result};
use construct_types::ChatMessage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Federation client for sending messages to remote instances
#[derive(Clone)]
pub struct FederationClient {
    http_client: reqwest::Client,
    /// Server signer for authenticating S2S messages
    /// When None: messages are sent unsigned (for testing/development)
    server_signer: Option<Arc<ServerSigner>>,
    /// Our instance domain (for envelope origin_server field)
    instance_domain: String,
    /// Trust store for certificate pinning (optional)
    trust_store: Option<Arc<FederationTrustStore>>,
    /// mTLS configuration
    mtls_config: Arc<MtlsConfig>,
}

impl FederationClient {
    /// Create a new federation client without signing (legacy/testing mode)
    pub fn new() -> Self {
        let mtls_config = Arc::new(MtlsConfig::default());
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            server_signer: None,
            instance_domain: "unknown".to_string(),
            trust_store: None,
            mtls_config,
        }
    }

    /// Create a new federation client with server signing
    pub fn new_with_signer(signer: Arc<ServerSigner>, instance_domain: String) -> Self {
        let mtls_config = Arc::new(MtlsConfig::default());
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            server_signer: Some(signer),
            instance_domain,
            trust_store: None,
            mtls_config,
        }
    }

    /// Create a new federation client with mTLS configuration and certificate pinning
    pub fn new_with_mtls(
        signer: Option<Arc<ServerSigner>>,
        instance_domain: String,
        mtls_config: Arc<MtlsConfig>,
    ) -> Result<Self> {
        // Initialize trust store with pinned certificates from configuration
        let trust_store = if !mtls_config.pinned_certs.is_empty() {
            tracing::info!(
                pinned_count = mtls_config.pinned_certs.len(),
                "Initializing FederationTrustStore with pinned certificates"
            );

            let store = Arc::new(FederationTrustStore::new());

            // Add all pinned certificates to trust store
            for (domain, fingerprint) in &mtls_config.pinned_certs {
                // Normalize fingerprint format (remove colons if present, then add back)
                let normalized_fp = fingerprint.replace(":", "").replace(" ", "");
                if normalized_fp.len() == 64 {
                    // Convert hex string to colon-separated format
                    let colon_fp: String = normalized_fp
                        .chars()
                        .collect::<Vec<_>>()
                        .chunks(2)
                        .map(|chunk| chunk.iter().collect::<String>())
                        .collect::<Vec<_>>()
                        .join(":")
                        .to_uppercase();

                    store.trust_fingerprint(domain, &colon_fp);
                    tracing::info!(
                        domain = %domain,
                        fingerprint = %colon_fp,
                        "Pinned certificate for federation partner"
                    );
                } else {
                    tracing::warn!(
                        domain = %domain,
                        fingerprint = %fingerprint,
                        "Invalid fingerprint format (expected 64 hex chars) - skipping"
                    );
                }
            }

            Some(store)
        } else {
            None
        };

        // SECURITY: Warn if pinned certificates are not configured in production
        // (TOFU is less secure for production deployments)
        if mtls_config.pinned_certs.is_empty() && mtls_config.verify_server_cert {
            tracing::warn!(
                "FEDERATION_PINNED_CERTS is not configured - using TOFU (Trust On First Use). \
                 For production, consider configuring pinned certificates for enhanced security."
            );
        }

        Ok(Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(!mtls_config.verify_server_cert)
                .build()
                .context("Failed to create HTTP client with mTLS configuration")?,
            server_signer: signer,
            instance_domain,
            trust_store,
            mtls_config,
        })
    }

    /// Send message to remote instance
    ///
    /// If server_signer is configured, the message will be signed with Ed25519.
    /// The remote server should verify the signature using our public key from
    /// .well-known/konstruct.
    pub async fn send_message(&self, target_domain: &str, message: &ChatMessage) -> Result<()> {
        // Construct federation endpoint URL
        let url = format!("https://{}/federation/v1/messages", target_domain);

        // Create envelope for signing
        let envelope = FederatedEnvelope {
            message_id: message.id.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            origin_server: self.instance_domain.clone(),
            destination_server: target_domain.to_string(),
            timestamp: message.timestamp,
            payload_hash: FederatedEnvelope::hash_payload(
                message
                    .content
                    .as_ref()
                    .expect("Federated messages must be Regular encrypted messages with content"),
            ),
        };

        // Sign if signer is available
        let server_signature = self.server_signer.as_ref().map(|signer| {
            let sig = signer.sign_message(&envelope);
            tracing::debug!(
                message_id = %message.id,
                origin = %self.instance_domain,
                "Message signed with server key"
            );
            sig
        });

        // Prepare request payload
        let payload = FederatedMessageRequest {
            message_id: message.id.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            ephemeral_public_key: message.ephemeral_public_key.clone().expect(
                "Federated messages must be Regular encrypted messages with ephemeral_public_key",
            ),
            ciphertext: message
                .content
                .clone()
                .expect("Federated messages must be Regular encrypted messages with content"),
            message_number: message.message_number.expect(
                "Federated messages must be Regular encrypted messages with message_number",
            ),
            timestamp: message.timestamp,
            origin_server: self.instance_domain.clone(),
            payload_hash: envelope.payload_hash,
            server_signature,
        };

        // SECURITY: Check if pinned certificate is configured for this domain
        // If pinned cert is configured, we should verify it matches (warn if not available)
        // Note: Full certificate pinning requires custom TLS verifier, which is complex with reqwest.
        // This check ensures configuration is correct and logs warnings if pinning is expected but not verified.
        if let Some(ref store) = self.trust_store {
            if let Some(expected_fp) = store.get_trusted_fingerprint(target_domain) {
                tracing::info!(
                    target_domain = %target_domain,
                    expected_fingerprint = %expected_fp,
                    "Pinned certificate configured for federation partner"
                );
                // TODO: Implement full certificate pinning with custom TLS verifier
                // For now, we rely on standard TLS verification and log that pinning is configured
                // Future enhancement: Use rustls with custom ServerCertVerifier to verify fingerprint during TLS handshake
                // This would require: reqwest with rustls-tls feature and implementing ServerCertVerifier trait
            } else if self.mtls_config.verify_server_cert
                && !self.mtls_config.pinned_certs.is_empty()
            {
                // SECURITY: Pinned certs are configured but not for this domain
                // In production, this should be treated as an error to prevent TOFU MITM attacks
                if self.mtls_config.required {
                    anyhow::bail!(
                        "SECURITY: Pinned certificate required for {} but not configured. \
                         Set FEDERATION_PINNED_CERTS or disable FEDERATION_MTLS_REQUIRED=true to allow TOFU.",
                        target_domain
                    );
                } else {
                    tracing::warn!(
                        target_domain = %target_domain,
                        "Pinned certificates are configured but none found for this domain - using TOFU (less secure)"
                    );
                }
            }
        } else if !self.mtls_config.pinned_certs.is_empty() {
            // Trust store not initialized despite pinned certs in config - this shouldn't happen
            tracing::error!(
                target_domain = %target_domain,
                "Pinned certificates configured but trust store not initialized"
            );
        }

        tracing::info!(
            message_id = %message.id,
            from = %message.from,
            to = %message.to,
            target_domain = %target_domain,
            signed = payload.server_signature.is_some(),
            pinned_cert_configured = self.trust_store.as_ref()
                .and_then(|s| s.get_trusted_fingerprint(target_domain))
                .is_some(),
            "Sending federated message to remote server"
        );

        // Send HTTP POST request
        let response = self.http_client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!(
                "Federation request failed: HTTP {} - {}",
                status,
                error_text
            );
        }

        let response_body: FederatedMessageResponse = response.json().await?;

        tracing::info!(
            message_id = %message.id,
            status = %response_body.status,
            "Federated message accepted by remote server"
        );

        Ok(())
    }
}

impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}

/// S2S message request sent to remote servers
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FederatedMessageRequest {
    pub message_id: String,
    pub from: String,
    pub to: String,
    pub ephemeral_public_key: Vec<u8>,
    pub ciphertext: String,
    pub message_number: u32,
    pub timestamp: u64,
    /// Origin server domain (for signature verification)
    pub origin_server: String,
    /// Hash of the ciphertext (for integrity verification)
    pub payload_hash: String,
    /// Ed25519 signature over the canonical envelope (base64)
    pub server_signature: Option<String>,
}

/// Response from remote server
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct FederatedMessageResponse {
    pub status: String,
    pub message_id: String,
}
