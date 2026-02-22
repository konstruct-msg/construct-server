// ============================================================================
// Message Gateway gRPC Client
// ============================================================================
//
// Client wrapper for communicating with Message Gateway Service from
// construct-server (WebSocket gateway).
//
// Usage:
// 1. construct-server receives message via WebSocket
// 2. Forwards to Message Gateway via this client
// 3. Message Gateway validates, rate limits, and routes to Kafka
// 4. Returns success/error response
// 5. construct-server sends ACK/error to WebSocket client
//
// ============================================================================

use crate::message_gateway::grpc::*;
use anyhow::{Result, anyhow};
use construct_types::ChatMessage;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

/// Message Gateway gRPC client
pub struct MessageGatewayClient {
    client: MessageGatewayClient_<Channel>,
    endpoint: String,
}

impl MessageGatewayClient {
    /// Create a new Message Gateway client
    ///
    /// # Arguments
    /// * `endpoint` - gRPC endpoint (e.g., "http://localhost:8080")
    pub async fn new(endpoint: String) -> Result<Self> {
        info!("Connecting to Message Gateway at {}", endpoint);

        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| anyhow!("Invalid endpoint: {}", e))?
            .connect()
            .await
            .map_err(|e| anyhow!("Failed to connect to Message Gateway: {}", e))?;

        let client = MessageGatewayClient_::new(channel);

        info!("Connected to Message Gateway successfully");

        Ok(Self { client, endpoint })
    }

    /// Submit a message for processing
    ///
    /// # Arguments
    /// * `msg` - ChatMessage to submit
    /// * `authenticated_user_id` - User ID from WebSocket session
    ///
    /// # Returns
    /// * `Ok(())` - Message accepted and queued
    /// * `Err(e)` - Validation error, rate limit, or server error
    pub async fn submit_message(
        &mut self,
        msg: &ChatMessage,
        authenticated_user_id: &str,
    ) -> Result<()> {
        debug!(
            message_id = %msg.id,
            from = %msg.from,
            to = %msg.to,
            "Submitting message to Message Gateway"
        );

        // Convert ChatMessage to gRPC request
        // Note: content is base64 in ChatMessage, need to decode to bytes for gRPC
        // Message gateway only handles Regular encrypted messages
        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            msg.content
                .as_ref()
                .expect("Message gateway only handles Regular encrypted messages"),
        )
        .map_err(|e| anyhow!("Failed to decode message content: {}", e))?;

        let request = tonic::Request::new(SubmitMessageRequest {
            message_id: msg.id.clone(),
            from: msg.from.clone(),
            to: msg.to.clone(),
            ephemeral_public_key: msg
                .ephemeral_public_key
                .clone()
                .expect("Message gateway only handles Regular encrypted messages"),
            ciphertext,
            message_number: msg
                .message_number
                .expect("Message gateway only handles Regular encrypted messages"),
            authenticated_user_id: authenticated_user_id.to_string(),
        });

        // Call Message Gateway
        let response = self
            .client
            .submit_message(request)
            .await
            .map_err(|e| anyhow!("gRPC call failed: {}", e))?
            .into_inner();

        // Handle response
        match SubmissionStatus::try_from(response.status) {
            Ok(SubmissionStatus::Success) => {
                debug!(
                    message_id = %msg.id,
                    "Message successfully submitted to Message Gateway"
                );
                Ok(())
            }
            Ok(SubmissionStatus::ValidationError) => {
                let error = response.error.unwrap_or_default();
                warn!(
                    message_id = %msg.id,
                    error_code = %error.error_code,
                    error_message = %error.error_message,
                    "Message validation failed"
                );
                Err(anyhow!("{}: {}", error.error_code, error.error_message))
            }
            Ok(SubmissionStatus::RateLimited) => {
                let error = response.error.unwrap_or_default();
                warn!(
                    message_id = %msg.id,
                    error_code = %error.error_code,
                    "Rate limit exceeded"
                );
                Err(anyhow!("{}: {}", error.error_code, error.error_message))
            }
            Ok(SubmissionStatus::UserBlocked) => {
                let error = response.error.unwrap_or_default();
                warn!(
                    message_id = %msg.id,
                    error_code = %error.error_code,
                    "User is blocked"
                );
                Err(anyhow!("{}: {}", error.error_code, error.error_message))
            }
            Ok(SubmissionStatus::Duplicate) => {
                let error = response.error.unwrap_or_default();
                warn!(
                    message_id = %msg.id,
                    "Duplicate message detected"
                );
                Err(anyhow!("{}: {}", error.error_code, error.error_message))
            }
            Ok(SubmissionStatus::InternalError) => {
                let error = response.error.unwrap_or_default();
                error!(
                    message_id = %msg.id,
                    error_code = %error.error_code,
                    "Message Gateway internal error"
                );
                Err(anyhow!("{}: {}", error.error_code, error.error_message))
            }
            _ => {
                error!(
                    message_id = %msg.id,
                    status = response.status,
                    "Unknown submission status"
                );
                Err(anyhow!("Unknown submission status: {}", response.status))
            }
        }
    }

    /// Health check
    pub async fn health_check(&mut self) -> Result<bool> {
        let request = tonic::Request::new(HealthCheckRequest {});

        match self.client.health_check(request).await {
            Ok(response) => {
                let inner = response.into_inner();
                match HealthStatus::try_from(inner.status) {
                    Ok(HealthStatus::Serving) => Ok(true),
                    Ok(HealthStatus::NotServing) => Ok(false),
                    _ => Ok(false),
                }
            }
            Err(e) => {
                error!(error = %e, "Health check failed");
                Ok(false)
            }
        }
    }

    /// Get endpoint
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

// Implement Clone by reconnecting (gRPC clients are not Clone)
impl MessageGatewayClient {
    pub async fn try_clone(&self) -> Result<Self> {
        Self::new(self.endpoint.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires running Message Gateway
    async fn test_client_connection() {
        let client = MessageGatewayClient::new("http://localhost:8080".to_string())
            .await
            .unwrap();

        assert_eq!(client.endpoint(), "http://localhost:8080");
    }

    #[tokio::test]
    #[ignore] // Requires running Message Gateway
    async fn test_health_check() {
        let mut client = MessageGatewayClient::new("http://localhost:8080".to_string())
            .await
            .unwrap();

        let healthy = client.health_check().await.unwrap();
        assert!(healthy);
    }
}
