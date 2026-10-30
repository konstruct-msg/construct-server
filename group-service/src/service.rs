use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use construct_auth::AuthManager;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::shared::proto::services::v1 as proto;
use tokio::sync::broadcast;
use uuid::Uuid;

const GROUP_BROADCAST_CAPACITY: usize = 256;

/// What a group's open `MessageStream`s hear from the handlers of this process.
#[derive(Clone, Debug)]
pub(crate) enum HubEvent {
    /// A frame for every subscribed member.
    Frame(proto::GroupStreamResponse),
    /// This device left or was removed: its stream drops the group.
    Removed(String),
}

pub(crate) struct GroupHub {
    capacity: usize,
    inner: Mutex<HashMap<Uuid, broadcast::Sender<HubEvent>>>,
}

impl GroupHub {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_capacity(GROUP_BROADCAST_CAPACITY)
    }

    pub(crate) fn with_capacity(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            inner: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn subscribe(&self, group_id: Uuid) -> broadcast::Receiver<HubEvent> {
        let mut map = self.inner.lock().unwrap();
        map.entry(group_id)
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .subscribe()
    }

    pub(crate) fn publish(&self, group_id: Uuid, frame: proto::GroupStreamResponse) {
        self.send(group_id, HubEvent::Frame(frame));
    }

    pub(crate) fn remove_member(&self, group_id: Uuid, device_id: &str) {
        self.send(group_id, HubEvent::Removed(device_id.to_string()));
    }

    /// Drops the group's sender: every stream subscribed to it sees its end and drops the group.
    pub(crate) fn dissolve(&self, group_id: Uuid) {
        self.inner.lock().unwrap().remove(&group_id);
    }

    fn send(&self, group_id: Uuid, event: HubEvent) {
        let mut map = self.inner.lock().unwrap();
        if let Some(tx) = map.get(&group_id)
            && tx.send(event).is_err()
        {
            // No stream is subscribed any more; the next Subscribe recreates it.
            map.remove(&group_id);
        }
    }
}

#[derive(Clone)]
pub(crate) struct GroupServiceImpl {
    pub(crate) db: Arc<sqlx::PgPool>,
    pub(crate) hub: Arc<GroupHub>,
    pub(crate) notification_client: Option<NotificationClient>,
    pub(crate) redis: redis::aio::ConnectionManager,
    /// Verifies Bearer access tokens; never trusts client x-user-id alone.
    pub(crate) auth: Arc<AuthManager>,
}
