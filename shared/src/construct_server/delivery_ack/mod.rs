// ============================================================================
// Delivery ACK Module - Privacy-Preserving Message Delivery Acknowledgments
// ============================================================================
//
// This module implements a privacy-first system for tracking message delivery
// acknowledgments without revealing the relationship between messages and senders.
//
// ## Security Design
//
// 1. **Anonymous Message Tracking**
//    - Uses HMAC-SHA256 to create one-way hash: messageId → messageHash
//    - Server cannot reverse messageHash to messageId without SECRET_KEY
//    - Even with DB access, cannot link messages to senders
//
// 2. **Minimal Data Retention**
//    - Records automatically expire after DELIVERY_EXPIRY_DAYS (default: 7)
//    - Background cleanup task removes expired records
//    - No long-term storage of delivery metadata
//
// 3. **Configurable Backend**
//    - PostgreSQL (default) - simple, reliable
//    - Redis (optional) - better performance, automatic TTL
//    - Kafka (future) - event sourcing, auto-expiry
//
// ## Flow
//
// 1. Sender sends message → Server stores (messageHash, senderId) in delivery_pending
// 2. Sender receives ACK "sent" (message queued)
// 3. Recipient comes online → receives message
// 4. Recipient sends acknowledgeMessage → Server computes messageHash
// 5. Server looks up senderId by messageHash
// 6. Server sends ACK "delivered" to sender
// 7. Server deletes delivery_pending record
//
// ## Privacy Properties
//
// - ✅ Cannot determine who sent what message without SECRET_KEY
// - ✅ Cannot reconstruct social graph from DB alone
// - ✅ Automatic data deletion minimizes retention
// - ⚠️  Timing correlation possible (see docs for mitigations)
//
// ============================================================================

pub mod batching;
pub mod cleanup;
// pub mod crypto; // MOVED to construct-crypto crate
pub mod models;
pub mod storage;

#[cfg(test)]
mod security_tests;

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use std::sync::Arc;

// Import crypto functions (re-exported for tests)
pub use construct_crypto::compute_message_hash;

pub use batching::AckBatcher;
pub use cleanup::DeliveryCleanupTask;
pub use models::{AcknowledgeMessageData, DeliveryPending};
pub use storage::{DeliveryPendingStorage, KafkaDeliveryStorage, PostgresDeliveryStorage};

/// Delivery ACK operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAckMode {
    /// Delivery ACK system disabled
    Disabled,
    /// PostgreSQL-based storage (legacy, Phases 1-4)
    /// Uses delivery_pending table with manual cleanup
    PostgreSQL,
    /// Kafka-based storage (modern, Phase 5+)
    /// Uses Kafka events with auto-expiry
    Kafka,
}

/// Configuration for delivery ACK system
#[derive(Debug, Clone)]
pub struct DeliveryAckConfig {
    /// Operation mode (PostgreSQL, Kafka, or Disabled)
    pub mode: DeliveryAckMode,

    /// Secret key for HMAC-SHA256 (must be 32 bytes)
    /// CRITICAL: Store this securely (env var, secrets manager)
    /// NEVER commit to git
    pub secret_key: Vec<u8>,

    /// Number of days before delivery pending records expire
    /// Default: 7 days
    pub expiry_days: i64,

    /// Cleanup interval in seconds
    /// How often to run the background cleanup task
    /// Default: 3600 (1 hour)
    /// NOTE: Only used in PostgreSQL mode (Kafka uses retention.ms)
    pub cleanup_interval_secs: u64,

    /// Enable ACK batching for privacy (recommended)
    /// Buffers ACK events for N seconds before sending to Kafka
    /// Helps prevent timing correlation attacks
    /// Default: true (5 second buffer)
    pub enable_batching: bool,

    /// Batch buffer time in seconds (only if enable_batching=true)
    /// Default: 5 seconds
    pub batch_buffer_secs: u64,
}

impl DeliveryAckConfig {
    /// Load configuration from environment variables
    ///
    /// Expected environment variables:
    /// - `DELIVERY_ACK_MODE`: "disabled", "postgres", or "kafka" (defaults to disabled)
    /// - `DELIVERY_SECRET_KEY`: Hex-encoded secret key (64 chars = 32 bytes, required if mode != disabled)
    /// - `DELIVERY_EXPIRY_DAYS`: Optional, defaults to 7
    /// - `DELIVERY_CLEANUP_INTERVAL_SECS`: Optional, defaults to 3600
    /// - `DELIVERY_ACK_ENABLE_BATCHING`: Optional, defaults to true (privacy protection)
    /// - `DELIVERY_ACK_BATCH_BUFFER_SECS`: Optional, defaults to 5
    pub fn from_env() -> Result<Self> {
        // Parse mode
        let mode_str = std::env::var("DELIVERY_ACK_MODE")
            .unwrap_or_else(|_| "disabled".to_string())
            .to_lowercase();

        let mode = match mode_str.as_str() {
            "disabled" | "off" | "false" => DeliveryAckMode::Disabled,
            "postgres" | "postgresql" | "pg" => DeliveryAckMode::PostgreSQL,
            "kafka" => DeliveryAckMode::Kafka,
            _ => {
                tracing::warn!(
                    mode = %mode_str,
                    "Unknown DELIVERY_ACK_MODE, defaulting to 'disabled'"
                );
                DeliveryAckMode::Disabled
            }
        };

        // If disabled, return early with dummy config
        if mode == DeliveryAckMode::Disabled {
            return Ok(Self {
                mode,
                secret_key: vec![0u8; 32], // Dummy key, never used
                expiry_days: 7,
                cleanup_interval_secs: 3600,
                enable_batching: true,
                batch_buffer_secs: 5,
            });
        }

        // Parse SECRET_KEY (required for enabled modes)
        let secret_key_hex = std::env::var("DELIVERY_SECRET_KEY")
            .context("DELIVERY_SECRET_KEY required when DELIVERY_ACK_MODE is enabled")?;

        let secret_key =
            hex::decode(&secret_key_hex).context("DELIVERY_SECRET_KEY must be valid hex")?;

        if secret_key.len() != 32 {
            anyhow::bail!("DELIVERY_SECRET_KEY must be 32 bytes (64 hex chars)");
        }

        // SECURITY: Validate secret key strength (entropy, patterns)
        if let Err(e) = crate::utils::validate_secret_strength(
            &secret_key_hex,
            64, // 32 bytes = 64 hex chars
        ) {
            anyhow::bail!(
                "DELIVERY_SECRET_KEY is too weak: {}. Please use a random secret generated with: openssl rand -hex 32",
                e
            );
        }

        let expiry_days = std::env::var("DELIVERY_EXPIRY_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7);

        let cleanup_interval_secs = std::env::var("DELIVERY_CLEANUP_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);

        let enable_batching = std::env::var("DELIVERY_ACK_ENABLE_BATCHING")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true); // Default: enabled for privacy

        let batch_buffer_secs = std::env::var("DELIVERY_ACK_BATCH_BUFFER_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);

        Ok(Self {
            mode,
            secret_key,
            expiry_days,
            cleanup_interval_secs,
            enable_batching,
            batch_buffer_secs,
        })
    }

    /// Generate a new random secret key (for initial setup)
    ///
    /// # Example
    /// ```ignore
    /// use construct_server::delivery_ack::DeliveryAckConfig;
    ///
    /// let key_hex = DeliveryAckConfig::generate_secret_key();
    /// println!("DELIVERY_SECRET_KEY={}", key_hex);
    /// ```
    pub fn generate_secret_key() -> String {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        hex::encode(key)
    }
}

/// Main delivery ACK manager
///
/// Handles saving delivery pending records when messages are sent
/// and processing acknowledgments when messages are delivered.
pub struct DeliveryAckManager<S: DeliveryPendingStorage> {
    storage: Arc<S>,
    config: DeliveryAckConfig,
}

impl<S: DeliveryPendingStorage> DeliveryAckManager<S> {
    /// Create a new DeliveryAckManager
    pub fn new(storage: Arc<S>, config: DeliveryAckConfig) -> Self {
        Self { storage, config }
    }

    /// Record that a message was sent and is awaiting delivery confirmation
    ///
    /// Call this when a message is sent to an offline recipient or queued.
    ///
    /// # Arguments
    /// * `message_id` - The message ID (should be UUIDv4)
    /// * `sender_id` - The sender's user ID
    ///
    /// # Returns
    /// Ok(()) if successfully saved, Err otherwise
    pub async fn record_pending_delivery(&self, message_id: &str, sender_id: &str) -> Result<()> {
        // Compute anonymous message hash
        let message_hash = compute_message_hash(message_id, &self.config.secret_key);

        // Calculate expiry time
        let expires_at = Utc::now() + Duration::days(self.config.expiry_days);

        // Create record
        let record = DeliveryPending::new(message_hash, sender_id.to_string(), expires_at);

        // Save to storage
        self.storage
            .save(&record)
            .await
            .context("Failed to record pending delivery")?;

        tracing::debug!(
            message_id = %message_id,
            sender_id = %sender_id,
            expires_at = %expires_at,
            "Recorded pending delivery"
        );

        Ok(())
    }

    /// Process a delivery acknowledgment from a recipient
    ///
    /// Call this when a recipient acknowledges receiving a message.
    /// Returns the sender_id if found, None if the record doesn't exist or expired.
    ///
    /// # Arguments
    /// * `message_id` - The message ID being acknowledged
    ///
    /// # Returns
    /// - `Ok(Some(sender_id))` if record found and valid
    /// - `Ok(None)` if record not found or expired
    /// - `Err` on database error
    pub async fn process_acknowledgment(&self, message_id: &str) -> Result<Option<String>> {
        // Compute message hash
        let message_hash = compute_message_hash(message_id, &self.config.secret_key);

        // Find record
        let record = self.storage.find_by_hash(&message_hash).await?;

        match record {
            Some(record) => {
                // Check if expired
                if record.expires_at < Utc::now() {
                    tracing::debug!(
                        message_id = %message_id,
                        "Delivery ACK for expired message, ignoring"
                    );

                    // Clean up expired record
                    self.storage.delete_by_hash(&message_hash).await?;

                    return Ok(None);
                }

                let sender_id = record.sender_id.clone();

                // Delete record (one-time use)
                self.storage.delete_by_hash(&message_hash).await?;

                tracing::debug!(
                    message_id = %message_id,
                    sender_id = %sender_id,
                    "Processed delivery ACK"
                );

                Ok(Some(sender_id))
            }
            None => {
                tracing::debug!(
                    message_id = %message_id,
                    "Delivery ACK for unknown message (already processed or never sent)"
                );
                Ok(None)
            }
        }
    }

    /// Get count of pending deliveries (for metrics/monitoring)
    pub async fn pending_count(&self) -> Result<i64> {
        self.storage.count().await
    }

    /// Delete all delivery ACK records for a specific user (GDPR compliance)
    ///
    /// Implements GDPR Article 17 "Right to Erasure".
    /// Call this when a user requests data deletion.
    ///
    /// **IMPORTANT**: This only deletes delivery ACK records.
    /// You must also delete other user data (messages, keys, profile, etc.).
    ///
    /// # Arguments
    /// * `user_id` - The user ID whose delivery ACK data should be deleted
    ///
    /// # Returns
    /// Number of deleted records
    ///
    /// # Example
    /// ```no_run
    /// # use construct_server::delivery_ack::*;
    /// # use std::sync::Arc;
    /// # async fn example(manager: Arc<DeliveryAckManager<PostgresDeliveryStorage>>) {
    /// // User requests account deletion
    /// let user_id = "550e8400-e29b-41d4-a716-446655440000";
    /// let deleted_count = manager.delete_user_data(user_id).await.unwrap();
    /// println!("Deleted {} delivery ACK records", deleted_count);
    /// # }
    /// ```
    pub async fn delete_user_data(&self, user_id: &str) -> Result<u64> {
        self.storage.delete_by_user_id(user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret_key() {
        let key_hex = DeliveryAckConfig::generate_secret_key();

        // Should be 64 hex chars (32 bytes)
        assert_eq!(key_hex.len(), 64);

        // Should be valid hex
        let key = hex::decode(&key_hex).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_config_validation() {
        // Valid 32-byte key with good entropy (16 different hex characters)
        let valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        unsafe {
            std::env::set_var("DELIVERY_ACK_MODE", "postgres");
            std::env::set_var("DELIVERY_SECRET_KEY", valid_key);
            std::env::set_var("DELIVERY_EXPIRY_DAYS", "7");
        }

        let config = DeliveryAckConfig::from_env().unwrap();
        assert_eq!(config.expiry_days, 7);
        assert_eq!(config.secret_key.len(), 32);

        // Clean up
        unsafe {
            std::env::remove_var("DELIVERY_ACK_MODE");
            std::env::remove_var("DELIVERY_SECRET_KEY");
            std::env::remove_var("DELIVERY_EXPIRY_DAYS");
        }
    }

    #[test]
    fn test_config_invalid_key_length() {
        // Invalid key length (not 32 bytes = 64 hex chars)
        unsafe {
            std::env::set_var("DELIVERY_ACK_MODE", "postgres");
            std::env::set_var("DELIVERY_SECRET_KEY", "0".repeat(32)); // Only 16 bytes (32 hex chars)
        }

        let result = DeliveryAckConfig::from_env();
        assert!(
            result.is_err(),
            "Short key (32 hex chars = 16 bytes) must be rejected"
        );

        // Clean up
        unsafe {
            std::env::remove_var("DELIVERY_ACK_MODE");
            std::env::remove_var("DELIVERY_SECRET_KEY");
        }
    }
}
