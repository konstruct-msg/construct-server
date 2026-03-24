// ============================================================================
// SignalingService — WebRTC Call Signaling Relay
// ============================================================================
//
// Server is relay-only: does NOT participate in media, only forwards
// signals between peers via bidirectional gRPC streams.
//
//   Call history is NOT stored on server. Only active sessions in Redis.
//
// Port: 50060
// ============================================================================

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, RwLock};
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use base64::Engine;
use construct_server_shared::shared::proto::signaling::v1::{
    signal_request,
    signal_response,
    signal_route,
    // SignalingService trait and server
    signaling_service_server::{SignalingService, SignalingServiceServer},
    web_rtc_signal,
    CallHangup,
    // Stream messages
    DeviceTarget,
    // TURN
    GetTurnCredentialsRequest,
    GetTurnCredentialsResponse,
    GroupTarget,
    HangupReason,
    // Call notifications
    IncomingCallNotification,
    RoutedWebRtcSignal,
    // Error types
    SignalError,
    SignalErrorCode,
    SignalPong,
    SignalRequest,
    SignalResponse,
    SignalRoute,
    TurnCredentials,
    UserTarget,
    // WebRTC signal types (from webrtc.proto, same package)
    WebRtcSignal,
};

// ============================================================================
// Types
// ============================================================================

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Wrapper for signals that can be forwarded between streams
#[derive(Clone, Debug)]
enum ForwardedSignal {
    Signal(WebRtcSignal),
    IncomingCall(IncomingCall),
    Error(SignalErrorInfo),
}

#[derive(Clone, Debug)]
struct IncomingCall {
    call_id: String,
    caller_id: String,
    caller_name: String,
    call_type: i32,
    offered_at: i64,
}

#[derive(Clone, Debug)]
struct SignalErrorInfo {
    code: i32,
    message: String,
}

// ============================================================================
// Call Registry (in-memory + Redis backup)
// ============================================================================

struct CallRegistry {
    calls: RwLock<HashMap<String, CallState>>,
    active_calls: RwLock<HashMap<String, String>>,
    // user_id -> device_id -> sender
    user_channels: RwLock<HashMap<String, HashMap<String, broadcast::Sender<ForwardedSignal>>>>,
    redis: redis::Client,
}

#[derive(Clone)]
struct CallState {
    call_id: String,
    caller_user_id: String,
    callee_user_id: String,
    caller_device_id: String,
    accepted_callee_device_id: Option<String>,
    created_at: u64,
    offered_at_ms: i64,
    ringing_at_ms: Option<i64>,
    answered_at_ms: Option<i64>,
    caller_last_keepalive_at: u64,
    callee_last_keepalive_at: u64,
}

impl CallRegistry {
    fn new(redis_url: &str) -> Result<Self, anyhow::Error> {
        Ok(Self {
            calls: RwLock::new(HashMap::new()),
            active_calls: RwLock::new(HashMap::new()),
            user_channels: RwLock::new(HashMap::new()),
            redis: redis::Client::open(redis_url)?,
        })
    }

    async fn register_user(
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

    async fn unregister_user(&self, user_id: &str, device_id: &str) {
        let mut users = self.user_channels.write().await;
        let Some(devices) = users.get_mut(user_id) else {
            return;
        };
        devices.remove(device_id);
        if devices.is_empty() {
            users.remove(user_id);
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

    async fn send_to_user(
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

    async fn send_to_user_except(
        &self,
        user_id: &str,
        except_device_id: &str,
        signal: ForwardedSignal,
    ) -> usize {
        let targets = self.get_user_senders(user_id).await;
        let mut sent = 0usize;
        for (device_id, tx) in targets {
            if device_id == except_device_id {
                continue;
            }
            if tx.send(signal.clone()).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    async fn create_call(
        &self,
        call_id: &str,
        caller_user_id: &str,
        caller_device_id: &str,
        callee_user_id: &str,
        offered_at_ms: i64,
    ) {
        let now = unix_seconds();

        let state = CallState {
            call_id: call_id.to_string(),
            caller_user_id: caller_user_id.to_string(),
            callee_user_id: callee_user_id.to_string(),
            caller_device_id: caller_device_id.to_string(),
            accepted_callee_device_id: None,
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
            let _: Result<(), _> = redis::pipe()
                .set_ex(format!("call:{}", call_id), "1", 300)
                .set_ex(format!("user:{}:active_call", caller_user_id), call_id, 300)
                .set_ex(format!("user:{}:active_call", callee_user_id), call_id, 300)
                .query_async(&mut conn)
                .await;
        }
    }

    async fn remove_call(&self, call_id: &str) {
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
                let _: Result<(), _> = redis::pipe()
                    .del(format!("call:{}", call_id))
                    .del(format!("user:{}:active_call", state.caller_user_id))
                    .del(format!("user:{}:active_call", state.callee_user_id))
                    .query_async(&mut conn)
                    .await;
            }
        }
    }

    async fn call_ended_by_disconnect(&self, user_id: &str, device_id: &str) -> Option<CallState> {
        let call_id = self.get_user_call(user_id).await?;
        let calls = self.calls.read().await;
        let state = calls.get(&call_id)?;
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

    async fn note_keepalive(&self, user_id: &str) {
        let Some(call_id) = self.get_user_call(user_id).await else {
            return;
        };
        let now = unix_seconds();
        let mut calls = self.calls.write().await;
        let Some(state) = calls.get_mut(&call_id) else {
            return;
        };
        if state.caller_user_id == user_id {
            state.caller_last_keepalive_at = now;
        } else if state.callee_user_id == user_id {
            state.callee_last_keepalive_at = now;
        }
    }

    async fn note_ringing(&self, call_id: &str) {
        let mut calls = self.calls.write().await;
        let Some(state) = calls.get_mut(call_id) else {
            return;
        };
        if state.ringing_at_ms.is_none() {
            state.ringing_at_ms = Some(unix_millis());
        }
    }

    async fn accept_call(
        &self,
        call_id: &str,
        callee_device_id: &str,
    ) -> Option<(CallState, bool)> {
        let mut calls = self.calls.write().await;
        let state = calls.get_mut(call_id)?;
        if state.accepted_callee_device_id.is_some() {
            return Some((state.clone(), false));
        }
        state.accepted_callee_device_id = Some(callee_device_id.to_string());
        state.answered_at_ms = Some(unix_millis());
        Some((state.clone(), true))
    }

    async fn is_user_busy(&self, user_id: &str) -> bool {
        let active = self.active_calls.read().await;
        active.contains_key(user_id)
    }

    async fn get_user_call(&self, user_id: &str) -> Option<String> {
        let active = self.active_calls.read().await;
        active.get(user_id).cloned()
    }

    async fn forward_signal(
        &self,
        call_id: &str,
        from_user_id: &str,
        from_device_id: &str,
        signal: ForwardedSignal,
    ) -> Result<(), Status> {
        let (target_user_id, target_device_id) = {
            let calls = self.calls.read().await;
            let state = calls
                .get(call_id)
                .ok_or_else(|| Status::not_found(format!("Call {} not found", call_id)))?;
            if state.caller_user_id == from_user_id {
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
            }
        };

        // Avoid echoing back to the same device if caller and callee are same user (should not happen).
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

    async fn cleanup_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
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
                },
            }

            let mut actions: Vec<CleanupAction> = Vec::new();
            {
                let calls = self.calls.read().await;
                for state in calls.values() {
                    // Hard expiry guard (5 minutes)
                    if now_s.saturating_sub(state.created_at) > 300 {
                        actions.push(CleanupAction::RemoveCall {
                            call_id: state.call_id.clone(),
                        });
                        continue;
                    }

                    // Offer sent, no ringing => treat as callee offline/failed to notify
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
                        });
                        continue;
                    }

                    // Ringing but no answer
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
                        });
                        continue;
                    }

                    // Keepalive timeout
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
                        });
                    }
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
                    CleanupAction::RemoveCall { call_id } => {
                        warn!(call_id, "removing stale/expired call");
                        self.remove_call(&call_id).await;
                    }
                }
            }
        }
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

#[derive(Clone)]
struct RateLimiter {
    redis: redis::Client,
}

impl RateLimiter {
    fn new(redis: redis::Client) -> Self {
        Self { redis }
    }

    async fn check_call_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("ratelimit:calls:{}", user_id);
        let count: i64 = redis::pipe()
            .incr(&key, 1i64)
            .expire(&key, 60)
            .query_async(&mut conn)
            .await?;
        Ok(count <= 10)
    }

    async fn check_peer_rate(&self, user_id: &str, peer_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("ratelimit:calls:{}:{}", user_id, peer_id);
        let count: i64 = redis::pipe()
            .incr(&key, 1i64)
            .expire(&key, 60)
            .query_async(&mut conn)
            .await?;
        Ok(count <= 3)
    }

    async fn check_turn_rate(&self, user_id: &str) -> Result<bool, anyhow::Error> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;
        let key = format!("ratelimit:turn:{}", user_id);
        let count: i64 = redis::pipe()
            .incr(&key, 1i64)
            .expire(&key, 30)
            .query_async(&mut conn)
            .await?;
        Ok(count <= 1)
    }
}

// ============================================================================
// TURN Credentials Generator
// ============================================================================

fn generate_turn_credentials(user_id: &str, secret: &str, ttl: u64) -> TurnCredentials {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + ttl;
    let username = format!("{}:{}", expiry, user_id);

    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let turn_host = env::var("TURN_HOST").unwrap_or_else(|_| "turn.konstruct.cc".into());

    TurnCredentials {
        urls: vec![
            format!("turn:{}:3478?transport=udp", turn_host),
            format!("turn:{}:3478?transport=tcp", turn_host),
            format!("turns:{}:5349?transport=tcp", turn_host),
        ],
        username,
        credential,
        expires_at: (expiry * 1000) as i64,
    }
}

// ============================================================================
// Service Implementation
// ============================================================================

struct SignalingServiceImpl {
    registry: Arc<CallRegistry>,
    rate_limiter: RateLimiter,
    turn_secret: String,
    turn_ttl: u64,
}

fn caller_user_id<T>(req: &Request<T>) -> Result<String, Status> {
    req.metadata()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-user-id header"))
}

fn caller_device_id<T>(req: &Request<T>) -> Result<String, Status> {
    req.metadata()
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing x-device-id header"))
}

#[tonic::async_trait]
impl SignalingService for SignalingServiceImpl {
    type SignalStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<SignalResponse, Status>> + Send>>;

    async fn signal(
        &self,
        request: Request<Streaming<SignalRequest>>,
    ) -> Result<Response<Self::SignalStream>, Status> {
        let user_id = caller_user_id(&request)?;
        let device_id = caller_device_id(&request)?;
        let mut inbound = request.into_inner();
        let registry = Arc::clone(&self.registry);
        let rate_limiter = self.rate_limiter.clone();

        let tx = registry.register_user(&user_id, &device_id).await;
        let mut rx = tx.subscribe();

        info!(user_id, device_id, "signal stream opened");

        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Result<SignalResponse, Status>>(64);

        tokio::spawn(async move {
            let user_id = user_id.clone();

            // Task 1: Forward inbound signals from this client
            let inbound_task = {
                let registry = Arc::clone(&registry);
                let user_id = user_id.clone();
                let device_id_for_inbound = device_id.clone();
                let out_tx = out_tx.clone();
                tokio::spawn(async move {
                    while let Some(msg_result) = inbound.next().await {
                        match msg_result {
                            Ok(msg) => match msg.request {
                                Some(signal_request::Request::RoutedSignal(routed)) => {
                                    registry.note_keepalive(&user_id).await;
                                    if let Err(e) = handle_outbound_signal(
                                        &registry,
                                        &rate_limiter,
                                        &user_id,
                                        &device_id_for_inbound,
                                        routed,
                                        &out_tx,
                                    )
                                    .await
                                    {
                                        error!(user_id, error = %e, "failed to handle signal");
                                    }
                                }
                                Some(signal_request::Request::Ping(ping)) => {
                                    registry.note_keepalive(&user_id).await;
                                    let _ = out_tx
                                        .send(Ok(SignalResponse {
                                            response: Some(signal_response::Response::Pong(
                                                SignalPong {
                                                    timestamp: ping.timestamp,
                                                    server_timestamp: SystemTime::now()
                                                        .duration_since(UNIX_EPOCH)
                                                        .unwrap()
                                                        .as_millis()
                                                        as i64,
                                                },
                                            )),
                                        }))
                                        .await;
                                }
                                None => {}
                            },
                            Err(e) => {
                                error!(user_id, error = %e, "inbound stream error");
                                break;
                            }
                        }
                    }
                    info!(user_id, "inbound stream closed");
                })
            };

            // Task 2: Forward incoming signals to this client
            let outbound_task = {
                let out_tx = out_tx.clone();
                tokio::spawn(async move {
                    while let Ok(signal) = rx.recv().await {
                        let response = match signal {
                            ForwardedSignal::Signal(s) => SignalResponse {
                                response: Some(signal_response::Response::Signal(s)),
                            },
                            ForwardedSignal::IncomingCall(call) => SignalResponse {
                                response: Some(signal_response::Response::IncomingCall(
                                    IncomingCallNotification {
                                        call_id: call.call_id,
                                        caller_id: call.caller_id,
                                        caller_name: call.caller_name,
                                        caller_avatar: Vec::new(),
                                        call_type: call.call_type,
                                        offered_at: call.offered_at,
                                    },
                                )),
                            },
                            ForwardedSignal::Error(err) => SignalResponse {
                                response: Some(signal_response::Response::Error(SignalError {
                                    code: err.code,
                                    message: err.message,
                                })),
                            },
                        };
                        if out_tx.send(Ok(response)).await.is_err() {
                            break;
                        }
                    }
                })
            };

            let _ = tokio::join!(inbound_task, outbound_task);

            if let Some(state) = registry
                .call_ended_by_disconnect(&user_id, &device_id)
                .await
            {
                info!(
                    user_id,
                    call_id = state.call_id,
                    "ending call on stream close"
                );
                let hangup = WebRtcSignal {
                    call_id: state.call_id.clone(),
                    signal: Some(web_rtc_signal::Signal::Hangup(CallHangup {
                        reason: HangupReason::ConnectionFailed as i32,
                        device_id: "server".into(),
                        hangup_at: unix_millis(),
                        message: None,
                    })),
                    sender_device_id: "server".into(),
                    timestamp: unix_millis(),
                };
                let _ = registry
                    .send_to_user(
                        &state.caller_user_id,
                        Some(&state.caller_device_id),
                        ForwardedSignal::Signal(hangup.clone()),
                    )
                    .await;
                let _ = registry
                    .send_to_user(
                        &state.callee_user_id,
                        state.accepted_callee_device_id.as_deref(),
                        ForwardedSignal::Signal(hangup),
                    )
                    .await;
                registry.remove_call(&state.call_id).await;
            }

            registry.unregister_user(&user_id, &device_id).await;
            info!(user_id, "signal stream closed");
        });

        let output = tokio_stream::wrappers::ReceiverStream::new(out_rx);
        Ok(Response::new(Box::pin(output)))
    }

    async fn get_turn_credentials(
        &self,
        request: Request<GetTurnCredentialsRequest>,
    ) -> Result<Response<GetTurnCredentialsResponse>, Status> {
        let user_id = caller_user_id(&request)?;
        if !self
            .rate_limiter
            .check_turn_rate(&user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::resource_exhausted(
                "TURN credentials rate limit exceeded",
            ));
        }
        let credentials = generate_turn_credentials(&user_id, &self.turn_secret, self.turn_ttl);
        Ok(Response::new(GetTurnCredentialsResponse {
            credentials: Some(credentials),
        }))
    }
}

/// Handle outbound signal from a client (to be forwarded to peer)
async fn handle_outbound_signal(
    registry: &Arc<CallRegistry>,
    rate_limiter: &RateLimiter,
    user_id: &str,
    device_id: &str,
    routed: RoutedWebRtcSignal,
    out_tx: &tokio::sync::mpsc::Sender<Result<SignalResponse, Status>>,
) -> Result<(), Status> {
    let signal = routed
        .signal
        .ok_or_else(|| Status::invalid_argument("Missing routed_signal.signal"))?;
    let call_id = signal.call_id.clone();
    let is_answer = matches!(signal.signal, Some(web_rtc_signal::Signal::Answer(_)));
    let sender_device_id = if signal.sender_device_id.is_empty() {
        device_id.to_string()
    } else {
        signal.sender_device_id.clone()
    };

    match &signal.signal {
        Some(web_rtc_signal::Signal::Offer(offer)) => {
            let callee_user_id = callee_user_id_from_route(routed.route.as_ref())?;

            // Rate limiting
            if !rate_limiter
                .check_call_rate(user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            {
                let _ = out_tx
                    .send(Ok(SignalResponse {
                        response: Some(signal_response::Response::Error(SignalError {
                            code: SignalErrorCode::RateLimited as i32,
                            message: "Call rate limit exceeded".into(),
                        })),
                    }))
                    .await;
                return Ok(());
            }
            if !rate_limiter
                .check_peer_rate(user_id, callee_user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            {
                let _ = out_tx
                    .send(Ok(SignalResponse {
                        response: Some(signal_response::Response::Error(SignalError {
                            code: SignalErrorCode::RateLimited as i32,
                            message: "Too many calls to this peer".into(),
                        })),
                    }))
                    .await;
                return Ok(());
            }

            let callee_devices = registry.get_user_senders(callee_user_id).await;
            if !callee_devices.is_empty() {
                if registry.is_user_busy(callee_user_id).await {
                    let _ = out_tx
                        .send(Ok(SignalResponse {
                            response: Some(signal_response::Response::Error(SignalError {
                                code: SignalErrorCode::CalleeBusy as i32,
                                message: "Callee is busy".into(),
                            })),
                        }))
                        .await;
                    return Ok(());
                }

                registry
                    .create_call(
                        &call_id,
                        user_id,
                        &sender_device_id,
                        callee_user_id,
                        offer.offered_at,
                    )
                    .await;

                let incoming = ForwardedSignal::IncomingCall(IncomingCall {
                    call_id: call_id.clone(),
                    caller_id: user_id.to_string(),
                    caller_name: String::new(),
                    call_type: offer.call_type,
                    offered_at: offer.offered_at,
                });
                let _ = registry.send_to_user(callee_user_id, None, incoming).await;
                let _ = registry
                    .send_to_user(
                        callee_user_id,
                        None,
                        ForwardedSignal::Signal(signal.clone()),
                    )
                    .await;
            } else {
                let _ = out_tx
                    .send(Ok(SignalResponse {
                        response: Some(signal_response::Response::Error(SignalError {
                            code: SignalErrorCode::CalleeOffline as i32,
                            message: "Callee is offline".into(),
                        })),
                    }))
                    .await;
            }
        }
        Some(web_rtc_signal::Signal::Answer(_))
        | Some(web_rtc_signal::Signal::IceCandidate(_))
        | Some(web_rtc_signal::Signal::IceCandidates(_))
        | Some(web_rtc_signal::Signal::MediaUpdate(_)) => {
            registry
                .forward_signal(
                    &call_id,
                    user_id,
                    &sender_device_id,
                    ForwardedSignal::Signal(signal),
                )
                .await?;
        }
        Some(web_rtc_signal::Signal::Ringing(_)) => {
            registry.note_ringing(&call_id).await;
            registry
                .forward_signal(
                    &call_id,
                    user_id,
                    &sender_device_id,
                    ForwardedSignal::Signal(signal),
                )
                .await?;
        }
        Some(web_rtc_signal::Signal::Busy(_)) => {
            let _ = registry
                .forward_signal(
                    &call_id,
                    user_id,
                    &sender_device_id,
                    ForwardedSignal::Signal(signal),
                )
                .await;
            registry.remove_call(&call_id).await;
        }
        Some(web_rtc_signal::Signal::Hangup(_)) => {
            let _ = registry
                .forward_signal(
                    &call_id,
                    user_id,
                    &sender_device_id,
                    ForwardedSignal::Signal(signal),
                )
                .await;
            registry.remove_call(&call_id).await;
            info!(user_id, call_id, "call ended");
        }
        None => {}
    }

    // Multi-device: first device that answers "wins"; others get hangup(accepted_elsewhere).
    if is_answer {
        if let Some((state, newly_accepted)) =
            registry.accept_call(&call_id, &sender_device_id).await
        {
            let hangup = WebRtcSignal {
                call_id: call_id.clone(),
                signal: Some(web_rtc_signal::Signal::Hangup(CallHangup {
                    reason: HangupReason::AcceptedElsewhere as i32,
                    device_id: "server".into(),
                    hangup_at: unix_millis(),
                    message: None,
                })),
                sender_device_id: "server".into(),
                timestamp: unix_millis(),
            };
            if newly_accepted {
                // Accepted on this device: notify other callee devices.
                let _ = registry
                    .send_to_user_except(
                        &state.callee_user_id,
                        &sender_device_id,
                        ForwardedSignal::Signal(hangup),
                    )
                    .await;
            } else {
                // Already accepted elsewhere: reject this device only.
                let _ = registry
                    .send_to_user(
                        &state.callee_user_id,
                        Some(&sender_device_id),
                        ForwardedSignal::Signal(hangup),
                    )
                    .await;
            }
        }
    }

    Ok(())
}

fn callee_user_id_from_route(route: Option<&SignalRoute>) -> Result<&str, Status> {
    let route = route.ok_or_else(|| Status::invalid_argument("Offer requires route"))?;
    let target = route
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Offer requires route.target"))?;

    match target {
        signal_route::Target::User(UserTarget { user_id, .. }) => {
            if user_id.is_empty() {
                Err(Status::invalid_argument("route.user.user_id is empty"))
            } else {
                Ok(user_id.as_str())
            }
        }
        signal_route::Target::Device(DeviceTarget { user_id, .. }) => {
            if user_id.is_empty() {
                Err(Status::invalid_argument("route.device.user_id is empty"))
            } else {
                Ok(user_id.as_str())
            }
        }
        signal_route::Target::Group(GroupTarget { .. }) => Err(Status::unimplemented(
            "Group call routing is not implemented yet (use route.user)",
        )),
    }
}

// ============================================================================
// Entry Point
// ============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "signaling_service=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "50060".into())
        .parse()?;
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    let turn_secret = env::var("TURN_SECRET").unwrap_or_else(|_| "changeme".into());
    let turn_ttl: u64 = env::var("TURN_CREDENTIALS_TTL_SECONDS")
        .unwrap_or_else(|_| "86400".into())
        .parse()?;

    let registry = Arc::new(CallRegistry::new(&redis_url)?);

    tokio::spawn(Arc::clone(&registry).cleanup_loop());

    info!("SignalingService listening on {}", addr);

    let http_port: u16 = env::var("METRICS_PORT")
        .unwrap_or_else(|_| "8091".into())
        .parse()?;
    let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port).parse()?;
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/health", axum::routing::get(|| async { "ok" }))
            .route(
                "/metrics",
                axum::routing::get(construct_server_shared::metrics::metrics_handler),
            );
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        info!("SignalingService HTTP/metrics listening on {}", http_addr);
        axum::serve(listener, app).await.unwrap();
    });

    let service = SignalingServiceImpl {
        registry: Arc::clone(&registry),
        rate_limiter: RateLimiter::new(registry.redis.clone()),
        turn_secret,
        turn_ttl,
    };

    Server::builder()
        .add_service(SignalingServiceServer::new(service))
        .serve_with_shutdown(addr, construct_server_shared::shutdown_signal())
        .await?;

    Ok(())
}
