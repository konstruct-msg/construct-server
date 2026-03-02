// ============================================================================
// Server Registry - Register server instance in Redis
// ============================================================================
//
// Creates and maintains a Redis key to signal that this server instance
// is active and ready to receive messages from delivery-worker.
//
// The delivery-worker uses KEYS delivery_queue:* to discover active servers.
//
// ============================================================================

use crate::queue::MessageQueue;
use construct_config::Config;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

/// Start heartbeat task that registers this server instance in Redis
pub fn spawn_server_heartbeat(
    config: Arc<Config>,
    queue: Arc<Mutex<MessageQueue>>,
    server_instance_id: String,
    delivery_queue_prefix: String,
) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(config.heartbeat_interval_secs as u64));

        loop {
            ticker.tick().await;

            let queue_key = format!("{}:{}", delivery_queue_prefix, server_instance_id);

            // Create/update the delivery queue key with TTL
            // This signals to delivery-worker that this server is alive
            let mut queue_guard = queue.lock().await;

            match queue_guard
                .register_server_instance(&queue_key, config.server_registry_ttl_secs)
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        server_instance_id = %server_instance_id,
                        queue_key = %queue_key,
                        ttl_secs = config.server_registry_ttl_secs,
                        prefix = %delivery_queue_prefix,
                        "Server heartbeat: registered in Redis"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        server_instance_id = %server_instance_id,
                        "Failed to register server instance in Redis"
                    );
                }
            }
        }
    });
}
