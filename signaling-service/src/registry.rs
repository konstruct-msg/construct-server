use std::collections::HashMap;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::sync::{broadcast, RwLock};
use tokio_stream::StreamExt;
use tonic::Status;
use tracing::{error, info, warn};

use construct_server_shared::metrics;
use construct_server_shared::shared::proto::signaling::v1::{
    web_rtc_signal, CallHangup, HangupReason, SignalErrorCode, WebRtcSignal,
};

use crate::forwarded::{
    decode_signal_response_base64, encode_signal_response_base64, forwarded_from_signal_response,
    signal_response_from_forwarded, ForwardedSignal, InstanceEnvelope, SignalErrorInfo,
};
use crate::time::{unix_millis, unix_seconds};

#[derive(Clone)]
pub(crate) struct CallState {
    pub(crate) call_id: String,
    pub(crate) caller_user_id: String,
    pub(crate) callee_user_id: String,
    pub(crate) caller_device_id: String,
    pub(crate) accepted_callee_device_id: Option<String>,
    pub(crate) call_type: i32,
    pub(crate) created_at: u64,
    pub(crate) offered_at_ms: i64,
    pub(crate) ringing_at_ms: Option<i64>,
    pub(crate) answered_at_ms: Option<i64>,
    pub(crate) caller_last_keepalive_at: u64,
    pub(crate) callee_last_keepalive_at: u64,
}

pub(crate) struct CallRegistry {
    calls: RwLock<HashMap<String, CallState>>,
    active_calls: RwLock<HashMap<String, String>>,
    // user_id -> device_id -> sender
    user_channels: RwLock<HashMap<String, HashMap<String, broadcast::Sender<ForwardedSignal>>>>,
    instance_id: String,
    redis: redis::Client,
    db_pool: Option<Arc<construct_db::DbPool>>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct CallHistoryRow {
    pub call_id: String,
    pub caller_user_id: String,
    pub callee_user_id: String,
    pub call_type: String,
    pub status: String,
    pub offered_at_ms: i64,
    pub answered_at_ms: Option<i64>,
    pub ended_at_ms: i64,
    pub duration_seconds: Option<i32>,
}

impl CallRegistry {
    pub(crate) fn new(
        redis_url: &str,
        instance_id: String,
        db_pool: Option<Arc<construct_db::DbPool>>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            calls: RwLock::new(HashMap::new()),
            active_calls: RwLock::new(HashMap::new()),
            user_channels: RwLock::new(HashMap::new()),
            instance_id,
            redis: redis::Client::open(redis_url)?,
            db_pool,
        })
    }

    pub(crate) fn redis_client(&self) -> redis::Client {
        self.redis.clone()
    }

    fn online_key(user_id: &str, device_id: &str) -> String {
        format!("signaling:online:{}:{}", user_id, device_id)
    }

    fn call_key(call_id: &str) -> String {
        format!("call:{}", call_id)
    }

    pub(crate) async fn register_user(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> broadcast::Sender<ForwardedSignal> {
        let (tx, _) = broadcast::channel(256);
        let mut users = self.user_channels.write().await;
        users
            .entry(user_id.to_string())
            .or_default()
            .insert(device_id.to_string(), tx.clone());
        tx
    }

    pub(crate) async fn unregister_user(&self, user_id: &str, device_id: &str) {
        let mut users = self.user_channels.write().await;
        let Some(devices) = users.get_mut(user_id) else {
            return;
        };
        devices.remove(device_id);
        if devices.is_empty() {
            users.remove(user_id);
        }

        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(Self::online_key(user_id, device_id))
                .query_async(&mut conn)
                .await;
        }
    }

    async fn get_user_senders(
        &self,
        user_id: &str,
    ) -> Vec<(String, broadcast::Sender<ForwardedSignal>)> {
        let users = self.user_channels.read().await;
        users
            .get(user_id)
            .map(|devices| {
                devices
                    .iter()
                    .map(|(device_id, tx)| (device_id.clone(), tx.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub(crate) async fn touch_online(&self, user_id: &str, device_id: &str) {
        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let key = Self::online_key(user_id, device_id);
            let _: Result<(), _> = redis::pipe()
                .set_ex(key, &self.instance_id, 90)
                .query_async(&mut conn)
                .await;
        }
    }

    async fn lookup_device_instance(&self, user_id: &str, device_id: &str) -> Option<String> {
        let mut conn = self.redis.get_multiplexed_async_connection().await.ok()?;
        redis::cmd("GET")
            .arg(Self::online_key(user_id, device_id))
            .query_async::<Option<String>>(&mut conn)
            .await
            .ok()
            .flatten()
    }

    pub(crate) async fn list_online_devices(&self, user_id: &str) -> Vec<(String, String)> {
        let mut conn = match self.redis.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let pattern = format!("signaling:online:{}:*", user_id);
        let mut cursor: u64 = 0;
        let mut out: Vec<(String, String)> = Vec::new();
        loop {
            let res: redis::RedisResult<(u64, Vec<String>)> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await;

            let Ok((next_cursor, keys)) = res else {
                break;
            };

            for key in keys {
                let instance: Option<String> = redis::cmd("GET")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .ok()
                    .flatten();
                let Some(instance) = instance else {
                    continue;
                };
                let device_id = key
                    .rsplit_once(':')
                    .map(|(_, d)| d.to_string())
                    .unwrap_or_default();
                if device_id.is_empty() {
                    continue;
                }
                out.push((device_id, instance));
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        out
    }

    async fn publish_to_instance(
        &self,
        instance_id: &str,
        env: InstanceEnvelope,
    ) -> Result<(), anyhow::Error> {
        let payload = serde_json::to_string(&env)?;
        let channel = format!("signaling:instance:{}", instance_id);
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let _: i64 = redis::cmd("PUBLISH")
            .arg(channel)
            .arg(payload)
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    pub(crate) async fn send_to_user(
        &self,
        user_id: &str,
        target_device_id: Option<&str>,
        signal: ForwardedSignal,
    ) -> usize {
        let local_sent = self
            .send_local_to_user(user_id, target_device_id, signal.clone())
            .await;
        let remote_sent = self
            .send_remote_to_user(user_id, target_device_id, None, signal)
            .await;
        local_sent + remote_sent
    }

    pub(crate) async fn send_local_to_user(
        &self,
        user_id: &str,
        target_device_id: Option<&str>,
        signal: ForwardedSignal,
    ) -> usize {
        let targets = self.get_user_senders(user_id).await;
        let mut sent = 0usize;
        for (device_id, tx) in targets {
            if let Some(target_device_id) = target_device_id {
                if device_id != target_device_id {
                    continue;
                }
            }
            if tx.send(signal.clone()).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    async fn send_remote_to_user(
        &self,
        user_id: &str,
        target_device_id: Option<&str>,
        except_device_id: Option<&str>,
        signal: ForwardedSignal,
    ) -> usize {
        let response = signal_response_from_forwarded(&signal);
        let response_b64 = encode_signal_response_base64(response);

        let mut published = 0usize;
        match target_device_id {
            Some(device_id) => {
                if Some(device_id) == except_device_id {
                    return 0;
                }
                let Some(instance) = self.lookup_device_instance(user_id, device_id).await else {
                    return 0;
                };
                if instance == self.instance_id {
                    return 0;
                }
                let env = InstanceEnvelope {
                    user_id: user_id.to_string(),
                    device_id: Some(device_id.to_string()),
                    response_b64,
                };
                if self.publish_to_instance(&instance, env).await.is_ok() {
                    published += 1;
                }
            }
            None => {
                let devices = self.list_online_devices(user_id).await;
                for (device_id, instance) in devices {
                    if Some(device_id.as_str()) == except_device_id {
                        continue;
                    }
                    if instance == self.instance_id {
                        continue;
                    }
                    let env = InstanceEnvelope {
                        user_id: user_id.to_string(),
                        device_id: Some(device_id),
                        response_b64: response_b64.clone(),
                    };
                    if self.publish_to_instance(&instance, env).await.is_ok() {
                        published += 1;
                    }
                }
            }
        }
        published
    }

    pub(crate) async fn send_to_user_except(
        &self,
        user_id: &str,
        except_device_id: &str,
        signal: ForwardedSignal,
    ) -> usize {
        let local_targets = self.get_user_senders(user_id).await;
        let mut local_sent = 0usize;
        for (device_id, tx) in local_targets {
            if device_id == except_device_id {
                continue;
            }
            if tx.send(signal.clone()).is_ok() {
                local_sent += 1;
            }
        }

        let remote_sent = self
            .send_remote_to_user(user_id, None, Some(except_device_id), signal)
            .await;
        local_sent + remote_sent
    }

    pub(crate) async fn create_call(
        &self,
        call_id: &str,
        caller_user_id: &str,
        caller_device_id: &str,
        callee_user_id: &str,
        call_type: i32,
        offered_at_ms: i64,
    ) {
        let now = unix_seconds();

        let state = CallState {
            call_id: call_id.to_string(),
            caller_user_id: caller_user_id.to_string(),
            callee_user_id: callee_user_id.to_string(),
            caller_device_id: caller_device_id.to_string(),
            accepted_callee_device_id: None,
            call_type,
            created_at: now,
            offered_at_ms,
            ringing_at_ms: None,
            answered_at_ms: None,
            caller_last_keepalive_at: now,
            callee_last_keepalive_at: now,
        };

        {
            let mut calls = self.calls.write().await;
            calls.insert(call_id.to_string(), state);
        }
        {
            let mut active = self.active_calls.write().await;
            active.insert(caller_user_id.to_string(), call_id.to_string());
            active.insert(callee_user_id.to_string(), call_id.to_string());
        }

        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let call_key = Self::call_key(call_id);
            let _: Result<(), _> = redis::pipe()
                .cmd("HSET")
                .arg(&call_key)
                .arg("call_id")
                .arg(call_id)
                .arg("caller_user_id")
                .arg(caller_user_id)
                .arg("caller_device_id")
                .arg(caller_device_id)
                .arg("callee_user_id")
                .arg(callee_user_id)
                .arg("accepted_callee_device_id")
                .arg("")
                .arg("call_type")
                .arg(call_type.to_string())
                .arg("offer_b64")
                .arg("")
                .arg("caller_name")
                .arg("")
                .arg("caller_avatar_b64")
                .arg("")
                .arg("created_at_s")
                .arg(now.to_string())
                .arg("offered_at_ms")
                .arg(offered_at_ms.to_string())
                .arg("ringing_at_ms")
                .arg("")
                .arg("answered_at_ms")
                .arg("")
                .arg("caller_last_keepalive_at_s")
                .arg(now.to_string())
                .arg("callee_last_keepalive_at_s")
                .arg(now.to_string())
                .cmd("EXPIRE")
                .arg(&call_key)
                .arg(300)
                .set_ex(format!("user:{}:active_call", caller_user_id), call_id, 300)
                .set_ex(format!("user:{}:active_call", callee_user_id), call_id, 300)
                .query_async(&mut conn)
                .await;
        }

        metrics::ACTIVE_CALLS.inc();
    }

    pub(crate) async fn store_call_metadata(
        &self,
        call_id: &str,
        caller_name: &str,
        caller_avatar: &[u8],
    ) {
        let caller_name: String = caller_name.chars().take(128).collect();
        let avatar_b64 = if caller_avatar.len() <= 4096 {
            BASE64.encode(caller_avatar)
        } else {
            String::new()
        };

        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let key = Self::call_key(call_id);
            let _: Result<(), _> = redis::pipe()
                .cmd("HSET")
                .arg(&key)
                .arg("caller_name")
                .arg(caller_name)
                .arg("caller_avatar_b64")
                .arg(avatar_b64)
                .cmd("EXPIRE")
                .arg(&key)
                .arg(300)
                .query_async(&mut conn)
                .await;
        }
    }

    pub(crate) async fn remove_call(&self, call_id: &str) {
        let state = {
            let mut calls = self.calls.write().await;
            calls.remove(call_id)
        };

        if let Some(state) = state {
            {
                let mut active = self.active_calls.write().await;
                active.remove(&state.caller_user_id);
                active.remove(&state.callee_user_id);
            }

            if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
                let call_key = Self::call_key(call_id);
                let _: Result<(), _> = redis::pipe()
                    .del(call_key)
                    .del(format!("user:{}:active_call", state.caller_user_id))
                    .del(format!("user:{}:active_call", state.callee_user_id))
                    .query_async(&mut conn)
                    .await;
            }

            metrics::ACTIVE_CALLS.dec();
        }
    }

    /// Remove the call from Redis/in-memory and persist a record to PostgreSQL.
    /// `status` — "completed" | "missed" | "declined" | "busy" | "failed"
    pub(crate) async fn save_and_remove_call(&self, call_id: &str, status: &str) {
        // Load state before removal so we have the full snapshot.
        let state = self.load_call_state(call_id).await;
        self.remove_call(call_id).await;

        let Some(state) = state else { return };
        let Some(pool) = self.db_pool.as_deref() else {
            return;
        };

        let ended_at_ms = unix_millis();
        let duration_seconds: Option<i32> = state.answered_at_ms.map(|a| {
            let dur_ms = ended_at_ms.saturating_sub(a);
            (dur_ms / 1000) as i32
        });

        use crate::service::call_type_to_str;
        let call_type_str = call_type_to_str(state.call_type);

        let res = sqlx::query(
            r#"
            INSERT INTO call_records
                (call_id, caller_user_id, callee_user_id, call_type, status,
                 offered_at_ms, answered_at_ms, ended_at_ms, duration_seconds)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (call_id) DO NOTHING
            "#,
        )
        .bind(&state.call_id)
        .bind(&state.caller_user_id)
        .bind(&state.callee_user_id)
        .bind(call_type_str)
        .bind(status)
        .bind(state.offered_at_ms)
        .bind(state.answered_at_ms)
        .bind(ended_at_ms)
        .bind(duration_seconds)
        .execute(pool)
        .await;

        if let Err(e) = res {
            warn!(call_id, error = %e, "failed to persist call record");
        }
    }

    /// Paginated call history for a user.
    /// Returns (records, next_cursor) where each record is
    /// (call_id, caller_user_id, callee_user_id, call_type, status,
    ///  offered_at_ms, answered_at_ms, ended_at_ms, duration_seconds).
    pub(crate) async fn get_call_history(
        &self,
        user_id: &str,
        limit: i64,
        before_offered_at_ms: Option<i64>,
    ) -> Vec<CallHistoryRow> {
        let Some(pool) = self.db_pool.as_deref() else {
            return Vec::new();
        };

        let cutoff = before_offered_at_ms.unwrap_or(i64::MAX);

        let rows = sqlx::query_as::<_, CallHistoryRow>(
            r#"
            SELECT call_id, caller_user_id, callee_user_id, call_type, status,
                   offered_at_ms, answered_at_ms, ended_at_ms, duration_seconds
            FROM call_records
            WHERE (caller_user_id = $1 OR callee_user_id = $1)
              AND offered_at_ms < $2
            ORDER BY offered_at_ms DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(cutoff)
        .bind(limit)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        rows
    }

    pub(crate) async fn load_call_state(&self, call_id: &str) -> Option<CallState> {
        {
            let calls = self.calls.read().await;
            if let Some(state) = calls.get(call_id) {
                return Some(state.clone());
            }
        }

        let mut conn = self.redis.get_multiplexed_async_connection().await.ok()?;
        let key = Self::call_key(call_id);
        let map: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok()?;
        if map.is_empty() {
            return None;
        }

        let caller_user_id = map.get("caller_user_id")?.to_string();
        let callee_user_id = map.get("callee_user_id")?.to_string();
        let caller_device_id = map.get("caller_device_id")?.to_string();
        let accepted_callee_device_id = map.get("accepted_callee_device_id").and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });

        let created_at: u64 = map
            .get("created_at_s")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(unix_seconds);
        let offered_at_ms: i64 = map
            .get("offered_at_ms")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(unix_millis);
        let ringing_at_ms: Option<i64> = map.get("ringing_at_ms").and_then(|s| s.parse().ok());
        let answered_at_ms: Option<i64> = map.get("answered_at_ms").and_then(|s| s.parse().ok());
        let caller_last_keepalive_at: u64 = map
            .get("caller_last_keepalive_at_s")
            .and_then(|s| s.parse().ok())
            .unwrap_or(created_at);
        let callee_last_keepalive_at: u64 = map
            .get("callee_last_keepalive_at_s")
            .and_then(|s| s.parse().ok())
            .unwrap_or(created_at);

        let state = CallState {
            call_id: call_id.to_string(),
            caller_user_id,
            callee_user_id,
            caller_device_id,
            accepted_callee_device_id,
            call_type: map
                .get("call_type")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            created_at,
            offered_at_ms,
            ringing_at_ms,
            answered_at_ms,
            caller_last_keepalive_at,
            callee_last_keepalive_at,
        };

        {
            let mut calls = self.calls.write().await;
            calls.insert(call_id.to_string(), state.clone());
        }
        Some(state)
    }

    pub(crate) async fn get_user_call(&self, user_id: &str) -> Option<String> {
        {
            let active = self.active_calls.read().await;
            if let Some(call_id) = active.get(user_id) {
                return Some(call_id.clone());
            }
        }

        let mut conn = self.redis.get_multiplexed_async_connection().await.ok()?;
        redis::cmd("GET")
            .arg(format!("user:{}:active_call", user_id))
            .query_async::<Option<String>>(&mut conn)
            .await
            .ok()
            .flatten()
    }

    pub(crate) async fn call_ended_by_disconnect(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> Option<CallState> {
        let call_id = self.get_user_call(user_id).await?;
        let state = self.load_call_state(&call_id).await?;
        if state.caller_user_id == user_id && state.caller_device_id == device_id {
            return Some(state.clone());
        }
        if state.callee_user_id == user_id
            && state
                .accepted_callee_device_id
                .as_deref()
                .is_some_and(|d| d == device_id)
        {
            return Some(state.clone());
        }
        None
    }

    pub(crate) async fn note_keepalive(&self, user_id: &str) {
        let Some(call_id) = self.get_user_call(user_id).await else {
            return;
        };
        let now = unix_seconds();
        let Some(mut state) = self.load_call_state(&call_id).await else {
            return;
        };
        let field = if state.caller_user_id == user_id {
            state.caller_last_keepalive_at = now;
            "caller_last_keepalive_at_s"
        } else if state.callee_user_id == user_id {
            state.callee_last_keepalive_at = now;
            "callee_last_keepalive_at_s"
        } else {
            return;
        };

        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let key = Self::call_key(&call_id);
            let _: Result<(), _> = redis::pipe()
                .cmd("HSET")
                .arg(&key)
                .arg(field)
                .arg(now.to_string())
                .cmd("EXPIRE")
                .arg(&key)
                .arg(300)
                .query_async(&mut conn)
                .await;
        }
    }

    pub(crate) async fn note_ringing(&self, call_id: &str) {
        let now_ms = unix_millis();
        let Some(mut state) = self.load_call_state(call_id).await else {
            return;
        };
        if state.ringing_at_ms.is_some() {
            return;
        }
        state.ringing_at_ms = Some(now_ms);

        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let key = Self::call_key(call_id);
            let _: Result<(), _> = redis::pipe()
                .cmd("HSET")
                .arg(&key)
                .arg("ringing_at_ms")
                .arg(now_ms.to_string())
                .cmd("EXPIRE")
                .arg(&key)
                .arg(300)
                .query_async(&mut conn)
                .await;
        }
    }

    pub(crate) async fn accept_call(
        &self,
        call_id: &str,
        callee_device_id: &str,
    ) -> Option<(CallState, bool)> {
        let mut state = self.load_call_state(call_id).await?;
        if state.accepted_callee_device_id.is_some() {
            return Some((state.clone(), false));
        }
        state.accepted_callee_device_id = Some(callee_device_id.to_string());
        state.answered_at_ms = Some(unix_millis());

        if let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await {
            let key = Self::call_key(call_id);
            let answered_at_ms = state.answered_at_ms.unwrap_or_else(unix_millis);
            let _: Result<(), _> = redis::pipe()
                .cmd("HSET")
                .arg(&key)
                .arg("accepted_callee_device_id")
                .arg(callee_device_id)
                .arg("answered_at_ms")
                .arg(answered_at_ms.to_string())
                .cmd("EXPIRE")
                .arg(&key)
                .arg(300)
                .query_async(&mut conn)
                .await;
        }

        Some((state.clone(), true))
    }

    pub(crate) async fn is_user_busy(&self, user_id: &str) -> bool {
        self.get_user_call(user_id).await.is_some()
    }

    pub(crate) async fn forward_signal(
        &self,
        call_id: &str,
        from_user_id: &str,
        from_device_id: &str,
        signal: ForwardedSignal,
    ) -> Result<(), Status> {
        let state = self
            .load_call_state(call_id)
            .await
            .ok_or_else(|| Status::not_found(format!("Call {} not found", call_id)))?;

        let (target_user_id, target_device_id) = if state.caller_user_id == from_user_id {
            (
                state.callee_user_id.clone(),
                state.accepted_callee_device_id.clone(),
            )
        } else if state.callee_user_id == from_user_id {
            (
                state.caller_user_id.clone(),
                Some(state.caller_device_id.clone()),
            )
        } else {
            return Err(Status::permission_denied("Not a participant in this call"));
        };

        let sent = if target_user_id == from_user_id {
            self.send_to_user_except(&target_user_id, from_device_id, signal)
                .await
        } else {
            self.send_to_user(&target_user_id, target_device_id.as_deref(), signal)
                .await
        };

        if sent == 0 {
            return Err(Status::unavailable("Peer is offline"));
        }
        Ok(())
    }

    pub(crate) async fn cleanup_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if !self.try_acquire_cleanup_lock().await {
                continue;
            }
            let now_s = unix_seconds();
            let now_ms = unix_millis();

            #[derive(Clone)]
            enum CleanupAction {
                ErrorToCaller {
                    call_id: String,
                    caller_user_id: String,
                    caller_device_id: String,
                    code: i32,
                    message: String,
                },
                HangupBoth {
                    call_id: String,
                    caller_user_id: String,
                    caller_device_id: String,
                    callee_user_id: String,
                    callee_device_id: Option<String>,
                    reason: i32,
                },
                RemoveCall {
                    call_id: String,
                    status: &'static str,
                },
            }

            let mut actions: Vec<CleanupAction> = Vec::new();
            let call_ids = self.list_active_call_ids().await;
            for call_id in call_ids {
                let Some(state) = self.load_call_state(&call_id).await else {
                    continue;
                };

                if now_s.saturating_sub(state.created_at) > 300 {
                    actions.push(CleanupAction::RemoveCall {
                        call_id: state.call_id.clone(),
                        status: if state.answered_at_ms.is_some() {
                            "completed"
                        } else {
                            "failed"
                        },
                    });
                    continue;
                }

                if state.ringing_at_ms.is_none()
                    && state.answered_at_ms.is_none()
                    && now_ms.saturating_sub(state.offered_at_ms) > 5_000
                {
                    actions.push(CleanupAction::ErrorToCaller {
                        call_id: state.call_id.clone(),
                        caller_user_id: state.caller_user_id.clone(),
                        caller_device_id: state.caller_device_id.clone(),
                        code: SignalErrorCode::CalleeOffline as i32,
                        message: "No ringing from callee".into(),
                    });
                    actions.push(CleanupAction::RemoveCall {
                        call_id: state.call_id.clone(),
                        status: "missed",
                    });
                    continue;
                }

                if state.ringing_at_ms.is_some()
                    && state.answered_at_ms.is_none()
                    && now_ms.saturating_sub(state.ringing_at_ms.unwrap()) > 30_000
                {
                    actions.push(CleanupAction::HangupBoth {
                        call_id: state.call_id.clone(),
                        caller_user_id: state.caller_user_id.clone(),
                        caller_device_id: state.caller_device_id.clone(),
                        callee_user_id: state.callee_user_id.clone(),
                        callee_device_id: state.accepted_callee_device_id.clone(),
                        reason: HangupReason::Timeout as i32,
                    });
                    actions.push(CleanupAction::RemoveCall {
                        call_id: state.call_id.clone(),
                        status: "missed",
                    });
                    continue;
                }

                if now_s.saturating_sub(state.caller_last_keepalive_at) > 60
                    || now_s.saturating_sub(state.callee_last_keepalive_at) > 60
                {
                    actions.push(CleanupAction::HangupBoth {
                        call_id: state.call_id.clone(),
                        caller_user_id: state.caller_user_id.clone(),
                        caller_device_id: state.caller_device_id.clone(),
                        callee_user_id: state.callee_user_id.clone(),
                        callee_device_id: state.accepted_callee_device_id.clone(),
                        reason: HangupReason::ConnectionFailed as i32,
                    });
                    actions.push(CleanupAction::RemoveCall {
                        call_id: state.call_id.clone(),
                        status: if state.answered_at_ms.is_some() {
                            "completed"
                        } else {
                            "failed"
                        },
                    });
                }
            }

            for action in actions {
                match action {
                    CleanupAction::ErrorToCaller {
                        call_id,
                        caller_user_id,
                        caller_device_id,
                        code,
                        message,
                    } => {
                        warn!(
                            call_id,
                            caller_user_id, "call cleanup: sending error to caller"
                        );
                        let code_str = code.to_string();
                        metrics::SIGNALING_ERRORS_TOTAL
                            .with_label_values(&[code_str.as_str()])
                            .inc();
                        let _ = self
                            .send_to_user(
                                &caller_user_id,
                                Some(&caller_device_id),
                                ForwardedSignal::Error(SignalErrorInfo { code, message }),
                            )
                            .await;
                    }
                    CleanupAction::HangupBoth {
                        call_id,
                        caller_user_id,
                        caller_device_id,
                        callee_user_id,
                        callee_device_id,
                        reason,
                    } => {
                        warn!(call_id, "call cleanup: sending synthetic hangup");
                        match reason {
                            r if r == HangupReason::Timeout as i32 => {
                                metrics::CALLS_MISSED_TOTAL.inc();
                            }
                            r if r == HangupReason::ConnectionFailed as i32 => {
                                metrics::CALLS_FAILED_TOTAL.inc();
                            }
                            _ => {}
                        }
                        let hangup = WebRtcSignal {
                            call_id: call_id.clone(),
                            signal: Some(web_rtc_signal::Signal::Hangup(CallHangup {
                                reason,
                                device_id: "server".into(),
                                hangup_at: unix_millis(),
                                message: None,
                            })),
                            sender_device_id: "server".into(),
                            timestamp: unix_millis(),
                        };
                        let _ = self
                            .send_to_user(
                                &caller_user_id,
                                Some(&caller_device_id),
                                ForwardedSignal::Signal(hangup.clone()),
                            )
                            .await;
                        let _ = self
                            .send_to_user(
                                &callee_user_id,
                                callee_device_id.as_deref(),
                                ForwardedSignal::Signal(hangup),
                            )
                            .await;
                    }
                    CleanupAction::RemoveCall { call_id, status } => {
                        warn!(call_id, status, "removing stale/expired call");
                        self.save_and_remove_call(&call_id, status).await;
                    }
                }
            }
        }
    }

    async fn try_acquire_cleanup_lock(&self) -> bool {
        let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await else {
            return false;
        };
        let key = "signaling:cleanup_lock";
        let res: redis::RedisResult<String> = redis::cmd("SET")
            .arg(key)
            .arg(&self.instance_id)
            .arg("NX")
            .arg("EX")
            .arg(4)
            .query_async(&mut conn)
            .await;
        matches!(res.as_deref(), Ok("OK"))
    }

    async fn list_active_call_ids(&self) -> Vec<String> {
        let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await else {
            return Vec::new();
        };

        let mut cursor: u64 = 0;
        let mut out: Vec<String> = Vec::new();
        loop {
            let res: redis::RedisResult<(u64, Vec<String>)> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("call:*")
                .arg("COUNT")
                .arg(200)
                .query_async(&mut conn)
                .await;

            let Ok((next_cursor, keys)) = res else {
                break;
            };
            for key in keys {
                if let Some(call_id) = key.strip_prefix("call:") {
                    if !call_id.is_empty() {
                        out.push(call_id.to_string());
                    }
                }
            }
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        out
    }

    pub(crate) async fn instance_pubsub_loop(self: Arc<Self>) {
        let channel = format!("signaling:instance:{}", self.instance_id);

        let mut pubsub = match self.redis.get_async_pubsub().await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "failed to create redis pubsub connection");
                return;
            }
        };

        if let Err(e) = pubsub.subscribe(&channel).await {
            error!(error = %e, channel, "failed to subscribe to instance pubsub channel");
            return;
        }

        info!(channel, "subscribed to instance pubsub channel");

        let mut messages = pubsub.on_message();
        while let Some(msg) = messages.next().await {
            let payload: String = match msg.get_payload::<String>() {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "failed to read pubsub payload");
                    continue;
                }
            };

            let env: InstanceEnvelope = match serde_json::from_str(&payload) {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "failed to decode pubsub envelope");
                    continue;
                }
            };

            let resp = match decode_signal_response_base64(&env.response_b64) {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "failed to decode pubsub SignalResponse");
                    continue;
                }
            };

            let Some(forwarded) = forwarded_from_signal_response(resp) else {
                continue;
            };

            let _ = self
                .send_local_to_user(&env.user_id, env.device_id.as_deref(), forwarded)
                .await;
        }
    }
}
