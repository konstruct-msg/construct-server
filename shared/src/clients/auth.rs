//! Client for the AuthService and DeviceService

use crate::shared::proto::services::v1::{
    auth_service_client::AuthServiceClient, device_service_client::DeviceServiceClient,
};
use tonic::transport::{Channel, Endpoint};

/// A configured gRPC client for both AuthService and DeviceService.
#[derive(Clone)]
pub struct AuthClient {
    channel: Channel,
}

impl AuthClient {
    /// Creates a new client for the given endpoint.
    pub async fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;

        Ok(Self { channel })
    }

    /// Gets a client for the AuthService.
    pub fn auth(&self) -> AuthServiceClient<Channel> {
        AuthServiceClient::new(self.channel.clone())
    }

    /// Gets a client for the DeviceService.
    pub fn device(&self) -> DeviceServiceClient<Channel> {
        DeviceServiceClient::new(self.channel.clone())
    }
}
