//! Client for the NotificationService

use crate::shared::proto::services::v1::notification_service_client::NotificationServiceClient;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tonic::transport::{Channel, Endpoint};

/// Minimum backoff after a connection failure: 30 seconds.
const CIRCUIT_BREAKER_BACKOFF_SECS: u64 = 30;

/// A configured gRPC client for NotificationService.
///
/// Includes a simple circuit breaker: after a connection failure the client
/// skips all attempts for `CIRCUIT_BREAKER_BACKOFF_SECS` seconds, then
/// retries. This avoids a new TCP connect + ECONNREFUSED on every message
/// when notification-service is temporarily down.
#[derive(Clone)]
pub struct NotificationClient {
    channel: Channel,
    /// Unix timestamp (seconds) until which all calls are skipped.
    /// 0 = circuit closed (normal operation).
    open_until: Arc<AtomicU64>,
}

impl NotificationClient {
    /// Creates a new client for the given endpoint.
    /// Uses lazy connect — the TCP connection is established on the first RPC call,
    /// not at construction time. This avoids startup warnings when the notification
    /// service is temporarily unavailable or not yet ready.
    pub fn new(endpoint: &str) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from_shared(endpoint.to_string())?.connect_lazy();

        Ok(Self {
            channel,
            open_until: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Returns `true` if the circuit breaker is open (service known to be down).
    pub fn is_circuit_open(&self) -> bool {
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

    /// Record a connection failure — opens the circuit for `CIRCUIT_BREAKER_BACKOFF_SECS`.
    pub fn record_failure(&self) {
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + CIRCUIT_BREAKER_BACKOFF_SECS;
        self.open_until.store(until, Ordering::Relaxed);
    }

    /// Record a successful call — closes the circuit.
    pub fn record_success(&self) {
        self.open_until.store(0, Ordering::Relaxed);
    }

    /// Gets a client for the NotificationService.
    pub fn get(&self) -> NotificationServiceClient<Channel> {
        NotificationServiceClient::new(self.channel.clone())
    }
}
