//! Client for the SentinelService

use crate::sentinel::CheckSendPermissionRequest;
use crate::sentinel::sentinel_service_client::SentinelServiceClient;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};

/// A configured gRPC client for SentinelService.
#[derive(Clone)]
pub struct SentinelClient {
    channel: Channel,
}

impl SentinelClient {
    /// Creates a new client for the given endpoint.
    /// Uses lazy connect — the TCP connection is established on the first RPC call.
    pub fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?.connect_lazy();
        Ok(Self { channel })
    }

    /// Check if `device_id` is permitted to send to `target_device_id`.
    /// Pass `sender_user_id` to also enforce user-level aggregate rate limits.
    ///
    /// Returns `(allowed, denial_reason, retry_after_seconds)`.
    /// Fails open: if the sentinel service is unavailable, returns `(true, "", 0)` so
    /// messaging is not blocked by a sentinel outage.
    pub async fn check_send_permission(
        &self,
        device_id: &str,
        target_device_id: &str,
    ) -> (bool, String, i32) {
        self.check_send_permission_with_user(device_id, target_device_id, "")
            .await
    }

    /// Like `check_send_permission` but also enforces user-level aggregate rate limits.
    pub async fn check_send_permission_with_user(
        &self,
        device_id: &str,
        target_device_id: &str,
        sender_user_id: &str,
    ) -> (bool, String, i32) {
        let mut client = SentinelServiceClient::new(self.channel.clone());

        let device_id_val = match MetadataValue::try_from(device_id) {
            Ok(v) => v,
            Err(_) => return (true, String::new(), 0),
        };

        let mut req = tonic::Request::new(CheckSendPermissionRequest {
            target_device_id: target_device_id.to_string(),
            sender_user_id: sender_user_id.to_string(),
        });
        req.metadata_mut().insert("x-device-id", device_id_val);

        match client.check_send_permission(req).await {
            Ok(resp) => {
                let r = resp.into_inner();
                (r.allowed, r.denial_reason, r.retry_after_seconds)
            }
            Err(e) => {
                tracing::warn!(
                    device_id = %device_id,
                    error = %e,
                    "SentinelClient::check_send_permission failed — failing open"
                );
                (true, String::new(), 0)
            }
        }
    }
}
