use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::shared::proto::services::v1 as proto;
use tokio::sync::broadcast;
use uuid::Uuid;

const GROUP_BROADCAST_CAPACITY: usize = 256;

pub(crate) struct GroupHub {
    inner: Mutex<HashMap<Uuid, broadcast::Sender<proto::GroupStreamResponse>>>,
}

impl GroupHub {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn subscribe(
        &self,
        group_id: Uuid,
    ) -> broadcast::Receiver<proto::GroupStreamResponse> {
        let mut map = self.inner.lock().unwrap();
        map.entry(group_id)
            .or_insert_with(|| broadcast::channel(GROUP_BROADCAST_CAPACITY).0)
            .subscribe()
    }

    pub(crate) fn publish(&self, group_id: Uuid, event: proto::GroupStreamResponse) {
        let map = self.inner.lock().unwrap();
        if let Some(tx) = map.get(&group_id) {
            let _ = tx.send(event);
        }
    }
}

#[derive(Clone)]
pub(crate) struct GroupServiceImpl {
    pub(crate) db: Arc<sqlx::PgPool>,
    pub(crate) hub: Arc<GroupHub>,
    pub(crate) notification_client: Option<NotificationClient>,
}
