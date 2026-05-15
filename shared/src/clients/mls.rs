use crate::shared::proto::services::v1::mls_service_client::MlsServiceClient;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tonic::Request;
use tonic::transport::{Channel, Endpoint};
use uuid::Uuid;

const CIRCUIT_BREAKER_BACKOFF_SECS: u64 = 30;

#[derive(Clone)]
pub struct MlsClient {
    channel: Channel,
    open_until: Arc<AtomicU64>,
}

impl MlsClient {
    pub fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let uri = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.to_string()
        } else {
            format!("http://{endpoint}")
        };
        let channel = Endpoint::from_shared(uri)?.connect_lazy();
        Ok(Self {
            channel,
            open_until: Arc::new(AtomicU64::new(0)),
        })
    }

    fn is_circuit_open(&self) -> bool {
        let until = self.open_until.load(Ordering::Relaxed);
        if until == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < until
    }

    fn record_failure(&self) {
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + CIRCUIT_BREAKER_BACKOFF_SECS;
        self.open_until.store(until, Ordering::Relaxed);
    }

    fn record_success(&self) {
        self.open_until.store(0, Ordering::Relaxed);
    }

    pub async fn create_group(
        &self,
        device_id: &str,
        user_id: &Uuid,
        group_id: &Uuid,
        initial_ratchet_tree: &[u8],
        encrypted_group_context: &[u8],
    ) -> Result<String, String> {
        if self.is_circuit_open() {
            return Err("MLS service circuit breaker open".into());
        }

        let mut client = MlsServiceClient::new(self.channel.clone());
        let mut request = Request::new(crate::shared::proto::services::v1::CreateGroupRequest {
            group_id: group_id.to_string(),
            initial_ratchet_tree: initial_ratchet_tree.to_vec(),
            encrypted_group_context: encrypted_group_context.to_vec(),
            max_members: 500,
            message_retention_days: 90,
            threads_enabled: false,
        });

        request
            .metadata_mut()
            .insert("x-user-id", user_id.to_string().parse().unwrap());
        request
            .metadata_mut()
            .insert("x-device-id", device_id.parse().unwrap());

        match client.create_group(request).await {
            Ok(resp) => {
                self.record_success();
                Ok(resp.into_inner().group_id)
            }
            Err(e) => {
                self.record_failure();
                Err(format!("MLS CreateGroup failed: {}", e))
            }
        }
    }
}
