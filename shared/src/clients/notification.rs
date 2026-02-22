//! Client for the NotificationService

use crate::shared::proto::services::v1::notification_service_client::NotificationServiceClient;
use tonic::transport::{Channel, Endpoint};

/// A configured gRPC client for NotificationService.
#[derive(Clone)]
pub struct NotificationClient {
    channel: Channel,
}

impl NotificationClient {
    /// Creates a new client for the given endpoint.
    pub async fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;

        Ok(Self { channel })
    }

    /// Gets a client for the NotificationService.
    pub fn get(&self) -> NotificationServiceClient<Channel> {
        NotificationServiceClient::new(self.channel.clone())
    }
}
