//! Client for the UserService

use crate::shared::proto::services::v1::user_service_client::UserServiceClient;
use tonic::transport::{Channel, Endpoint};

/// A configured gRPC client for UserService.
#[derive(Clone)]
pub struct UserClient {
    channel: Channel,
}

impl UserClient {
    /// Creates a new client for the given endpoint.
    pub async fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?
            .connect()
            .await?;

        Ok(Self { channel })
    }

    /// Gets a client for the UserService.
    pub fn get(&self) -> UserServiceClient<Channel> {
        UserServiceClient::new(self.channel.clone())
    }
}
