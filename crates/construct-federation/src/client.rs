// ============================================================================
// Federation Client — Send messages to remote instances
// ============================================================================
//
// Sends S2S messages to remote federation instances with Ed25519 signatures
// for authentication and integrity verification.
//
// TLS security: custom PinnedCertVerifier in the rustls ClientConfig enforces
// certificate fingerprint pinning at the handshake level (set up via
// `new_with_mtls`).  Plain `new()` / `new_with_signer()` use the default
// platform CA verification.
//
// ============================================================================

use crate::mtls::{build_rustls_client_config, FederationTrustStore, MtlsConfig};
use crate::signing::{FederatedEnvelope, ServerSigner};
use anyhow::{Context, Result};
use base64::Engine as _;
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
}

impl FederationClient {
    /// Create a new federation client without signing (legacy/testing mode)
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            server_signer: None,
            instance_domain: "unknown".to_string(),
        }
    }

    /// Create a new federation client with server signing
    pub fn new_with_signer(signer: Arc<ServerSigner>, instance_domain: String) -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            server_signer: Some(signer),
            instance_domain,
        }
    }

    /// Create a new federation client with mTLS configuration and certificate pinning.
    ///
    /// Builds a custom `rustls::ClientConfig` with a
    /// [`PinnedCertVerifier`](crate::mtls::PinnedCertVerifier) that enforces
    /// SHA-256 fingerprint pinning (or TOFU) at the TLS handshake level.
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

            for (domain, fingerprint) in &mtls_config.pinned_certs {
                let normalized_fp = fingerprint.replace(":", "").replace(" ", "");
                if normalized_fp.len() == 64 {
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
                        "Invalid fingerprint format (expected 64 hex chars) — skipping"
                    );
                }
            }

            Some(store)
        } else {
            None
        };

        if mtls_config.pinned_certs.is_empty() && mtls_config.verify_server_cert {
            tracing::warn!(
                "FEDERATION_PINNED_CERTS is not configured — using TOFU (Trust On First Use). \
                 For production, consider configuring pinned certificates for enhanced security."
            );
        }

        // Build the HTTP client.  When pinned certs are configured we create a
        // custom rustls ClientConfig with our PinnedCertVerifier; otherwise
        // we use the default reqwest TLS backend.
        let http_client = match trust_store {
            Some(store) => {
                let tls_config = build_rustls_client_config(store, &mtls_config)?;
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .tls_backend_preconfigured(tls_config)
                    .build()
                    .context("Failed to create HTTP client with mTLS configuration")?
            }
            None => reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .danger_accept_invalid_certs(!mtls_config.verify_server_cert)
                .build()
                .context("Failed to create HTTP client with mTLS configuration")?,
        };

        Ok(Self {
            http_client,
            server_signer: signer,
            instance_domain,
        })
    }

    /// Send message to remote instance
    ///
    /// If server_signer is configured, the message will be signed with Ed25519.
    /// The remote server should verify the signature using our public key from
    /// .well-known/konstruct.
    pub async fn send_message(&self, target_domain: &str, message: &ChatMessage) -> Result<()> {
        let url = format!("https://{target_domain}/federation/v1/messages");

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

        let server_signature = self.server_signer.as_ref().map(|signer| {
            let sig = signer.sign_message(&envelope);
            tracing::debug!(
                message_id = %message.id,
                origin = %self.instance_domain,
                "Message signed with server key"
            );
            sig
        });

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

        tracing::info!(
            message_id = %message.id,
            from = %message.from,
            to = %message.to,
            target_domain = %target_domain,
            signed = payload.server_signature.is_some(),
            "Sending federated message to remote server"
        );

        let response = self.http_client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Federation request failed: HTTP {status} — {error_text}");
        }

        let response_body: FederatedMessageResponse = response.json().await?;

        tracing::info!(
            message_id = %message.id,
            status = %response_body.status,
            "Federated message accepted by remote server"
        );

        Ok(())
    }

    /// Send a sealed sender message to a remote federation server.
    ///
    /// PRIVACY: The home server forwards `sealed_inner` opaquely — it does NOT
    /// parse sender identity. Only the destination server (and ultimately the
    /// recipient's client) can decrypt the sender certificate.
    pub async fn send_sealed_message(
        &self,
        target_domain: &str,
        message_id: &str,
        sealed_inner: &[u8],
        timestamp: i64,
    ) -> Result<()> {
        let url = format!("https://{target_domain}/federation/v1/sealed");

        let sealed_inner_hash = FederatedEnvelope::hash_payload(
            &base64::engine::general_purpose::STANDARD.encode(sealed_inner),
        );
        let envelope = FederatedEnvelope {
            message_id: message_id.to_string(),
            from: String::new(),
            to: String::new(),
            origin_server: self.instance_domain.clone(),
            destination_server: target_domain.to_string(),
            timestamp: timestamp as u64,
            payload_hash: sealed_inner_hash.clone(),
        };

        let server_signature = self
            .server_signer
            .as_ref()
            .map(|signer| signer.sign_message(&envelope));

        let payload = FederatedSealedRequest {
            message_id: message_id.to_string(),
            sealed_inner: base64::engine::general_purpose::STANDARD.encode(sealed_inner),
            origin_server: self.instance_domain.clone(),
            timestamp: timestamp as u64,
            payload_hash: sealed_inner_hash,
            server_signature,
        };

        tracing::info!(
            message_id = %message_id,
            target_domain = %target_domain,
            signed = payload.server_signature.is_some(),
            "Forwarding sealed sender message to remote server"
        );

        let response = self.http_client.post(&url).json(&payload).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Sealed sender federation failed: HTTP {status} — {error_text}");
        }

        let response_body: FederatedMessageResponse = response.json().await?;
        tracing::info!(
            message_id = %message_id,
            status = %response_body.status,
            "Sealed sender message accepted by remote server"
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
    pub origin_server: String,
    pub payload_hash: String,
    pub server_signature: Option<String>,
}

/// S2S sealed sender forwarding request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FederatedSealedRequest {
    pub message_id: String,
    pub sealed_inner: String,
    pub origin_server: String,
    pub timestamp: u64,
    pub payload_hash: String,
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
