// ============================================================================
// Message Router
// ============================================================================
//
// Routes messages to their destination:
// - Local messages: go to Kafka for local delivery
// - Federated messages: sent to remote instance via HTTP
//
// ============================================================================

use crate::federation::mtls::MtlsConfig;
use crate::federation::{FederationClient, ServerSigner};
use crate::kafka::MessageProducer;
use anyhow::{Context, Result};
use construct_types::ChatMessage;
use construct_types::UserId;
use std::sync::Arc;

pub struct MessageRouter {
    kafka_producer: MessageProducer,
    federation_client: Option<FederationClient>,
    local_domain: String,
    federation_enabled: bool,
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(
        kafka_producer: MessageProducer,
        local_domain: String,
        federation_enabled: bool,
    ) -> Self {
        let federation_client = if federation_enabled {
            Some(FederationClient::new())
        } else {
            None
        };

        Self {
            kafka_producer,
            federation_client,
            local_domain,
            federation_enabled,
        }
    }

    /// Create a new message router with server signing for S2S authentication
    pub fn new_with_signer(
        kafka_producer: MessageProducer,
        local_domain: String,
        federation_enabled: bool,
        server_signer: Option<Arc<ServerSigner>>,
    ) -> Self {
        let federation_client = if federation_enabled {
            match server_signer {
                Some(signer) => Some(FederationClient::new_with_signer(
                    signer,
                    local_domain.clone(),
                )),
                None => Some(FederationClient::new()),
            }
        } else {
            None
        };

        Self {
            kafka_producer,
            federation_client,
            local_domain,
            federation_enabled,
        }
    }

    /// Create a new message router with mTLS configuration and certificate pinning
    pub fn new_with_mtls(
        kafka_producer: MessageProducer,
        local_domain: String,
        federation_enabled: bool,
        server_signer: Option<Arc<ServerSigner>>,
        mtls_config: Arc<MtlsConfig>,
    ) -> Result<Self> {
        let federation_client = if federation_enabled {
            Some(
                FederationClient::new_with_mtls(server_signer, local_domain.clone(), mtls_config)
                    .context("Failed to create FederationClient with mTLS configuration")?,
            )
        } else {
            None
        };

        Ok(Self {
            kafka_producer,
            federation_client,
            local_domain,
            federation_enabled,
        })
    }

    /// Route message to destination
    ///
    /// Checks recipient domain:
    /// - Local: routes to Kafka for local delivery
    /// - Remote: sends to remote instance via federation
    pub async fn route_message(&self, msg: &ChatMessage) -> Result<()> {
        // Parse recipient to check if local or federated
        let recipient = UserId::parse(&msg.to)?;

        // Check if recipient is local
        let is_local = if recipient.is_local() {
            // No domain specified - assume local
            true
        } else {
            // Check if recipient domain matches our instance
            recipient.domain() == Some(self.local_domain.as_str())
        };

        if is_local {
            // Local delivery via Kafka
            self.route_to_local_kafka(msg).await?;
        } else if self.federation_enabled {
            // Remote delivery via federation
            // SECURITY: Handle case where domain() returns None
            let domain = recipient.domain().ok_or_else(|| {
                anyhow::anyhow!("Federated recipient has no domain (internal error)")
            })?;
            self.route_to_remote_instance(msg, domain).await?;
        } else {
            // SECURITY: Handle case where domain() returns None
            let domain = recipient.domain().ok_or_else(|| {
                anyhow::anyhow!("Federated recipient has no domain (internal error)")
            })?;
            anyhow::bail!(
                "Cannot route to remote instance {} - federation is disabled",
                domain
            );
        }

        Ok(())
    }

    /// Route to local Kafka
    async fn route_to_local_kafka(&self, msg: &ChatMessage) -> Result<()> {
        let envelope = crate::kafka::KafkaMessageEnvelope::from(msg);

        // Use circuit breaker protection
        if let Err(e) = self.kafka_producer.send_message(&envelope).await {
            tracing::error!(
                error = %e,
                message_id = %msg.id,
                "Circuit breaker: Failed to route message to Kafka"
            );
            return Err(anyhow::anyhow!("Message queue unavailable: {}", e));
        }

        tracing::debug!(
            message_id = %msg.id,
            recipient = %msg.to,
            "Message routed to local Kafka"
        );

        Ok(())
    }

    /// Route to remote instance via federation
    async fn route_to_remote_instance(&self, msg: &ChatMessage, target_domain: &str) -> Result<()> {
        let client = self
            .federation_client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Federation client not initialized"))?;

        client.send_message(target_domain, msg).await?;

        tracing::info!(
            message_id = %msg.id,
            from = %msg.from,
            to = %msg.to,
            target_domain = %target_domain,
            "Message routed to remote instance"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_config::KafkaConfig;

    #[tokio::test]
    async fn test_router_creation() {
        let kafka_config = KafkaConfig {
            enabled: false,
            brokers: "localhost:9092".to_string(),
            topic: "test-topic".to_string(),
            consumer_group: "test-group".to_string(),
            ssl_enabled: false,
            sasl_mechanism: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            producer_compression: "snappy".to_string(),
            producer_acks: "all".to_string(),
            producer_linger_ms: 10,
            producer_batch_size: 16384,
            producer_max_in_flight: 5,
            producer_retries: 2147483647,
            producer_request_timeout_ms: 30000,
            producer_delivery_timeout_ms: 120000,
            producer_enable_idempotence: true,
        };

        let producer = MessageProducer::new(&kafka_config).unwrap();
        let router = MessageRouter::new(
            producer,
            "eu.konstruct.cc".to_string(),
            false, // federation disabled for test
        );

        // Router should be created successfully
        assert!(std::mem::size_of_val(&router) > 0);
    }
}
