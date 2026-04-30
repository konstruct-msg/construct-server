use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use construct_server_shared::shared::proto::services::v1 as proto;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Capacity of each per-group broadcast channel.
/// Old messages are dropped if a slow receiver can't keep up.
const GROUP_BROADCAST_CAPACITY: usize = 256;

/// In-process fan-out hub for real-time group events.
/// Each group gets a `broadcast::Sender`; `MessageStream` subscribers hold a
/// `broadcast::Receiver` cloned from it.
pub(crate) struct GroupHub {
    inner: Mutex<HashMap<Uuid, broadcast::Sender<proto::GroupStreamResponse>>>,
}

impl GroupHub {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Returns a new receiver for the group, creating the channel if needed.
    pub(crate) fn subscribe(
        &self,
        group_id: Uuid,
    ) -> broadcast::Receiver<proto::GroupStreamResponse> {
        let mut map = self.inner.lock().unwrap();
        map.entry(group_id)
            .or_insert_with(|| broadcast::channel(GROUP_BROADCAST_CAPACITY).0)
            .subscribe()
    }

    /// Publishes an event to all active subscribers of `group_id`.
    /// If no subscribers exist, does nothing (sender is created lazily on subscribe).
    pub(crate) fn publish(&self, group_id: Uuid, event: proto::GroupStreamResponse) {
        let map = self.inner.lock().unwrap();
        if let Some(tx) = map.get(&group_id) {
            // Ignore SendError — means no receivers are currently connected.
            let _ = tx.send(event);
        }
    }
}

#[derive(Clone)]
pub(crate) struct MlsServiceImpl {
    pub(crate) db: Arc<sqlx::PgPool>,
    pub(crate) hub: Arc<GroupHub>,
}
