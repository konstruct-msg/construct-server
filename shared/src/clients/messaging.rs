//! Client for the MessagingService

use crate::shared::proto::services::v1::messaging_service_client::MessagingServiceClient;
use tonic::transport::{Channel, Endpoint};

/// A configured gRPC client for MessagingService.
#[derive(Clone)]
pub struct MessagingClient {
    channel: Channel,
}

impl MessagingClient {
    /// Creates a new client for the given endpoint.
    pub async fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;

        Ok(Self { channel })
    }

    /// Gets a client for the MessagingService.
    pub fn get(&self) -> MessagingServiceClient<Channel> {
        MessagingServiceClient::new(self.channel.clone())
    }
}
