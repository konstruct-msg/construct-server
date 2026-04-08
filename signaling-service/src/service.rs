use std::sync::Arc;

use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info};
use uuid::Uuid;

use construct_auth::AuthManager;
use construct_crypto::hmac_sha256;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::metrics;
use construct_server_shared::shared::proto::services::v1 as services_proto;
use construct_server_shared::shared::proto::signaling::v1::{
    signal_request, signal_response, signaling_service_server::SignalingService, web_rtc_signal,
    CallHangup, GetTurnCredentialsRequest, GetTurnCredentialsResponse, HangupReason,
    IncomingCallNotification, InitiateCallRequest, InitiateCallResponse, RoutedWebRtcSignal,
    SignalError, SignalErrorCode, SignalPong, SignalRequest, SignalResponse, WebRtcSignal,
};

use crate::forwarded::{ForwardedSignal, IncomingCall};
use crate::rate_limiter::RateLimiter;
use crate::registry::CallRegistry;
use crate::routing::callee_user_id_from_route;
use crate::time::unix_millis;
use crate::turn::generate_turn_credentials;

/// Simple per-stream token bucket rate limiter (no external crates).
/// Refills at `rate_per_sec` tokens per second. Each `check()` consumes 1 token.
struct TokenBucket {
    tokens: f64,
    rate_per_sec: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(rate_per_sec: u32) -> Self {
        Self {
            tokens: rate_per_sec as f64,
            rate_per_sec: rate_per_sec as f64,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate limit exceeded.
    fn check(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.rate_per_sec);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub(crate) struct SignalingServiceImpl {
    pub(crate) registry: Arc<CallRegistry>,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) turn_secret: String,
    pub(crate) turn_ttl: u64,
    pub(crate) notification_client: Option<NotificationClient>,
    pub(crate) db_pool: Option<Arc<construct_db::DbPool>>,
    pub(crate) contact_hmac_secret: Arc<Vec<u8>>,
    pub(crate) auth: Arc<AuthManager>,
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

/// Extract and verify device_id from both x-device-id header and JWT token.
/// This prevents header forgery attacks where an attacker spoofs x-device-id.
fn verified_caller_device_id<T>(req: &Request<T>, auth: &AuthManager) -> Result<String, Status> {
    let header_device_id = caller_device_id(req)?;

    let token = req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing Authorization header"))?;

    let claims = auth
        .verify_token(&token)
        .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

    auth.verify_device_id(&header_device_id, &claims)
        .map_err(|e| Status::permission_denied(format!("Device ID mismatch: {}", e)))
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
        let device_id = verified_caller_device_id(&request, &self.auth)?;
        let mut inbound = request.into_inner();
        let registry = Arc::clone(&self.registry);
        let rate_limiter = self.rate_limiter.clone();
        let notification_client = self.notification_client.clone();
        let db_pool = self.db_pool.clone();
        let contact_hmac_secret = Arc::clone(&self.contact_hmac_secret);

        let tx = registry.register_user(&user_id, &device_id).await;
        registry.touch_online(&user_id, &device_id).await;
        let mut rx = tx.subscribe();

        info!(user_id, device_id, "signal stream opened");

        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Result<SignalResponse, Status>>(64);

        // Per-stream rate limiter: max 10 RoutedSignal messages per second.
        // Prevents DoS amplification where one attacker floods signals that get
        // forwarded to N devices of the callee.
        let mut signal_limiter = TokenBucket::new(10);

        tokio::spawn(async move {
            let user_id = user_id.clone();

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
                                    // Enforce per-stream signal rate limit before forwarding.
                                    if !signal_limiter.check() {
                                        let _ = out_tx
                                            .send(Ok(SignalResponse {
                                                response: Some(
                                                    signal_response::Response::Error(SignalError {
                                                        code: SignalErrorCode::RateLimited as i32,
                                                        message:
                                                            "Signal rate limit exceeded (max 10/sec)"
                                                                .into(),
                                                    }),
                                                ),
                                            }))
                                            .await;
                                        continue;
                                    }

                                    registry
                                        .touch_online(&user_id, &device_id_for_inbound)
                                        .await;
                                    registry.note_keepalive(&user_id).await;
                                    if let Err(e) = handle_outbound_signal(
                                        &registry,
                                        &rate_limiter,
                                        notification_client.as_ref(),
                                        db_pool.as_deref(),
                                        &contact_hmac_secret,
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
                                    registry
                                        .touch_online(&user_id, &device_id_for_inbound)
                                        .await;
                                    registry.note_keepalive(&user_id).await;
                                    let _ = out_tx
                                        .send(Ok(SignalResponse {
                                            response: Some(signal_response::Response::Pong(
                                                SignalPong {
                                                    timestamp: ping.timestamp,
                                                    server_timestamp: unix_millis(),
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
                                        caller_avatar: call.caller_avatar,
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

    async fn initiate_call(
        &self,
        request: Request<InitiateCallRequest>,
    ) -> Result<Response<InitiateCallResponse>, Status> {
        tracing::info!("InitiateCall received");
        let caller_id = caller_user_id(&request)?;
        let caller_device_id_str = verified_caller_device_id(&request, &self.auth)?;
        let req = request.into_inner();

        let call_id = req.call_id.clone();
        let callee_user_id = req.callee_user_id.as_str();
        let caller_name: String = req.caller_name.chars().take(128).collect();
        let caller_avatar: Vec<u8> = if req.caller_avatar.len() <= 4096 {
            req.caller_avatar.clone()
        } else {
            Vec::new()
        };

        if call_id.is_empty() || callee_user_id.is_empty() {
            return Err(Status::invalid_argument(
                "call_id and callee_user_id are required",
            ));
        }

        // ── Mutual contacts + block check ─────────────────────────────────
        if let Some(pool) = self.db_pool.as_deref() {
            let (Ok(caller_uuid), Ok(callee_uuid)) =
                (Uuid::parse_str(&caller_id), Uuid::parse_str(callee_user_id))
            else {
                return Err(Status::invalid_argument("Invalid user_id UUID"));
            };

            let caller_hmac = hmac_sha256(&self.contact_hmac_secret, caller_uuid.as_bytes());
            let callee_hmac = hmac_sha256(&self.contact_hmac_secret, callee_uuid.as_bytes());
            match construct_db::are_mutual_contacts(pool, &caller_hmac, &callee_hmac).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Status::permission_denied(
                        "Calls allowed only for mutual contacts",
                    ));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to check mutual contacts — denying (fail-closed)");
                    return Err(Status::permission_denied("Calls not allowed"));
                }
            }

            match construct_db::is_blocked_by(pool, &callee_uuid, &caller_uuid).await {
                Ok(true) => return Err(Status::permission_denied("Call not allowed")),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "Failed to check user_blocks — proceeding"),
            }
        } else {
            return Err(Status::permission_denied(
                "Calls allowed only for mutual contacts",
            ));
        }

        // ── Rate limits ────────────────────────────────────────────────────
        if !self
            .rate_limiter
            .check_call_rate(&caller_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::resource_exhausted("Call rate limit exceeded"));
        }
        if !self
            .rate_limiter
            .check_peer_rate(&caller_id, callee_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::resource_exhausted("Too many calls to this peer"));
        }
        if !self
            .rate_limiter
            .check_decline_cooldown(&caller_id, callee_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::resource_exhausted(
                "Callee declined recently (cooldown)",
            ));
        }

        // ── Busy check ─────────────────────────────────────────────────────
        if self.registry.is_user_busy(callee_user_id).await {
            return Err(Status::failed_precondition("Callee is busy"));
        }

        metrics::CALLS_INITIATED_TOTAL
            .with_label_values(&[call_type_to_str(req.call_type)])
            .inc();

        // ── Register call in Redis ─────────────────────────────────────────
        let callee_devices = self.registry.list_online_devices(callee_user_id).await;
        let callee_online = !callee_devices.is_empty();

        self.registry
            .create_call(
                &call_id,
                &caller_id,
                &caller_device_id_str,
                callee_user_id,
                unix_millis(),
            )
            .await;
        self.registry
            .store_call_metadata(&call_id, &caller_name, &caller_avatar)
            .await;

        if callee_online {
            // ── Deliver IncomingCallNotification to online callee ──────────
            // SDP offer is NOT included — callee receives it via E2EE MessagingService.
            let incoming = ForwardedSignal::IncomingCall(IncomingCall {
                call_id: call_id.clone(),
                caller_id: caller_id.clone(),
                caller_name: caller_name.clone(),
                caller_avatar: caller_avatar.clone(),
                call_type: req.call_type,
                offered_at: unix_millis(),
            });
            let _ = self
                .registry
                .send_to_user(callee_user_id, None, incoming)
                .await;
        } else if let Some(client) = self.notification_client.clone() {
            // ── VoIP push to wake offline callee (no SDP in payload) ───────
            let push_req = services_proto::SendVoipIncomingCallRequest {
                user_id: callee_user_id.to_string(),
                call_id: call_id.clone(),
                caller_id: caller_id.clone(),
                caller_name: caller_name.clone(),
                call_type: call_type_to_str(req.call_type).to_string(),
                offered_at: unix_millis(),
            };
            tokio::spawn(async move {
                let mut grpc = client.get();
                if let Err(e) = grpc
                    .send_voip_incoming_call(tonic::Request::new(push_req))
                    .await
                {
                    tracing::warn!(error = %e, "Failed to send VoIP push for InitiateCall");
                }
            });
        }

        info!(
            call_id,
            caller_id, callee_user_id, callee_online, "call initiated"
        );

        Ok(Response::new(InitiateCallResponse {
            callee_online,
            // Capability negotiation not yet implemented — all modern clients support WebRTC.
            callee_has_webrtc: true,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_outbound_signal(
    registry: &Arc<CallRegistry>,
    rate_limiter: &RateLimiter,
    notification_client: Option<&NotificationClient>,
    db_pool: Option<&construct_db::DbPool>,
    contact_hmac_secret: &[u8],
    user_id: &str,
    device_id: &str,
    routed: RoutedWebRtcSignal,
    out_tx: &tokio::sync::mpsc::Sender<Result<SignalResponse, Status>>,
) -> Result<(), Status> {
    let RoutedWebRtcSignal {
        signal,
        route,
        caller_name,
        caller_avatar,
    } = routed;

    let caller_name: String = caller_name.chars().take(128).collect();
    let caller_avatar: Vec<u8> = if caller_avatar.len() <= 4096 {
        caller_avatar
    } else {
        Vec::new()
    };

    let signal = signal.ok_or_else(|| Status::invalid_argument("Missing routed_signal.signal"))?;
    let call_id = signal.call_id.clone();
    let is_answer = matches!(signal.signal, Some(web_rtc_signal::Signal::Answer(_)));
    let sender_device_id = if signal.sender_device_id.is_empty() {
        device_id.to_string()
    } else {
        signal.sender_device_id.clone()
    };

    match &signal.signal {
        Some(web_rtc_signal::Signal::Offer(offer)) => {
            let callee_user_id = callee_user_id_from_route(route.as_ref())?;

            if let Some(pool) = db_pool {
                let (Ok(caller_uuid), Ok(callee_uuid)) =
                    (Uuid::parse_str(user_id), Uuid::parse_str(callee_user_id))
                else {
                    return Err(Status::invalid_argument("Invalid user_id UUID"));
                };

                // Enforce strict mutual contacts for calls.
                let caller_hmac = hmac_sha256(contact_hmac_secret, caller_uuid.as_bytes());
                let callee_hmac = hmac_sha256(contact_hmac_secret, callee_uuid.as_bytes());
                match construct_db::are_mutual_contacts(pool, &caller_hmac, &callee_hmac).await {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::SIGNALING_ERRORS_TOTAL
                            .with_label_values(&[signal_error_code_to_str(
                                SignalErrorCode::Unauthorized,
                            )])
                            .inc();
                        let _ = out_tx
                            .send(Ok(SignalResponse {
                                response: Some(signal_response::Response::Error(SignalError {
                                    code: SignalErrorCode::Unauthorized as i32,
                                    message: "Calls allowed only for mutual contacts".into(),
                                })),
                            }))
                            .await;
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to check mutual contacts - denying call (fail-closed)"
                        );
                        metrics::SIGNALING_ERRORS_TOTAL
                            .with_label_values(&[signal_error_code_to_str(
                                SignalErrorCode::Unauthorized,
                            )])
                            .inc();
                        let _ = out_tx
                            .send(Ok(SignalResponse {
                                response: Some(signal_response::Response::Error(SignalError {
                                    code: SignalErrorCode::Unauthorized as i32,
                                    message: "Calls not allowed".into(),
                                })),
                            }))
                            .await;
                        return Ok(());
                    }
                }

                match construct_db::is_blocked_by(pool, &callee_uuid, &caller_uuid).await {
                    Ok(true) => {
                        metrics::SIGNALING_ERRORS_TOTAL
                            .with_label_values(&[signal_error_code_to_str(
                                SignalErrorCode::Unauthorized,
                            )])
                            .inc();
                        let _ = out_tx
                            .send(Ok(SignalResponse {
                                response: Some(signal_response::Response::Error(SignalError {
                                    code: SignalErrorCode::Unauthorized as i32,
                                    message: "Call not allowed".into(),
                                })),
                            }))
                            .await;
                        return Ok(());
                    }
                    Ok(false) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to check user_blocks - proceeding");
                    }
                }
            } else {
                // Without DB we cannot enforce mutual-contact policy — deny (fail-closed).
                metrics::SIGNALING_ERRORS_TOTAL
                    .with_label_values(&[signal_error_code_to_str(SignalErrorCode::Unauthorized)])
                    .inc();
                let _ = out_tx
                    .send(Ok(SignalResponse {
                        response: Some(signal_response::Response::Error(SignalError {
                            code: SignalErrorCode::Unauthorized as i32,
                            message: "Calls allowed only for mutual contacts".into(),
                        })),
                    }))
                    .await;
                return Ok(());
            }

            if !rate_limiter
                .check_call_rate(user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            {
                metrics::SIGNALING_ERRORS_TOTAL
                    .with_label_values(&[signal_error_code_to_str(SignalErrorCode::RateLimited)])
                    .inc();
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
                metrics::SIGNALING_ERRORS_TOTAL
                    .with_label_values(&[signal_error_code_to_str(SignalErrorCode::RateLimited)])
                    .inc();
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
            if !rate_limiter
                .check_decline_cooldown(user_id, callee_user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
            {
                metrics::SIGNALING_ERRORS_TOTAL
                    .with_label_values(&[signal_error_code_to_str(SignalErrorCode::RateLimited)])
                    .inc();
                let _ = out_tx
                    .send(Ok(SignalResponse {
                        response: Some(signal_response::Response::Error(SignalError {
                            code: SignalErrorCode::RateLimited as i32,
                            message: "Callee declined recently (cooldown)".into(),
                        })),
                    }))
                    .await;
                return Ok(());
            }

            if registry.is_user_busy(callee_user_id).await {
                metrics::SIGNALING_ERRORS_TOTAL
                    .with_label_values(&[signal_error_code_to_str(SignalErrorCode::CalleeBusy)])
                    .inc();
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

            metrics::CALLS_INITIATED_TOTAL
                .with_label_values(&[call_type_to_str(offer.call_type)])
                .inc();

            // Deprecated: SDP offer forwarding via Signal stream.
            // In the E2EE protocol, offer SDP travels through MessagingService.
            // We still honour the legacy path to avoid breaking older clients during
            // the transition, but log a warning so we can track adoption.
            tracing::warn!(
                call_id,
                user_id,
                "Received plaintext Offer via Signal stream (deprecated). \
                 Use InitiateCall + MessagingService for E2EE call signalling."
            );

            let callee_devices = registry.list_online_devices(callee_user_id).await;
            if !callee_devices.is_empty() {
                registry
                    .create_call(
                        &call_id,
                        user_id,
                        &sender_device_id,
                        callee_user_id,
                        unix_millis(),
                    )
                    .await;
                registry
                    .store_call_metadata(&call_id, &caller_name, &caller_avatar)
                    .await;

                // Deliver IncomingCallNotification — callee gets the push notification UI.
                // Do NOT forward the SDP offer; callee receives it via E2EE MessagingService.
                let incoming = ForwardedSignal::IncomingCall(IncomingCall {
                    call_id: call_id.clone(),
                    caller_id: user_id.to_string(),
                    caller_name: caller_name.clone(),
                    caller_avatar: caller_avatar.clone(),
                    call_type: offer.call_type,
                    offered_at: offer.offered_at,
                });
                let _ = registry.send_to_user(callee_user_id, None, incoming).await;
            } else {
                if let Some(client) = notification_client.cloned() {
                    let req = services_proto::SendVoipIncomingCallRequest {
                        user_id: callee_user_id.to_string(),
                        call_id: call_id.clone(),
                        caller_id: user_id.to_string(),
                        caller_name: caller_name.clone(),
                        call_type: call_type_to_str(offer.call_type).to_string(),
                        offered_at: offer.offered_at,
                    };
                    tokio::spawn(async move {
                        let mut grpc = client.get();
                        if let Err(e) = grpc.send_voip_incoming_call(tonic::Request::new(req)).await
                        {
                            tracing::warn!(error = %e, "failed to send voip incoming call push");
                        }
                    });
                }

                registry
                    .create_call(
                        &call_id,
                        user_id,
                        &sender_device_id,
                        callee_user_id,
                        unix_millis(),
                    )
                    .await;
                registry
                    .store_call_metadata(&call_id, &caller_name, &caller_avatar)
                    .await;
                // Pending offer NOT stored — SDP travels via E2EE MessagingService.
            }
        }
        Some(web_rtc_signal::Signal::Answer(_)) => {
            // SDP answer now travels via MessagingService (E2EE).
            // Receiving a plaintext Answer here indicates a legacy client.
            // Do NOT forward the SDP; just update call state so metrics and
            // ACCEPTED_ELSEWHERE logic work correctly.
            tracing::warn!(
                call_id,
                user_id,
                "Received plaintext Answer via Signal stream (deprecated). \
                 Updating call state only — SDP not forwarded."
            );
            // `is_answer = true` → accept_call is called after this match block ✓
        }
        Some(web_rtc_signal::Signal::IceCandidate(_))
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
            if let Some(web_rtc_signal::Signal::Hangup(hangup)) = &signal.signal {
                if hangup.reason == HangupReason::Declined as i32 {
                    if let Some(state) = registry.load_call_state(&call_id).await {
                        if state.callee_user_id == user_id {
                            metrics::CALLS_DECLINED_TOTAL.inc();
                            let _ = rate_limiter
                                .set_decline_cooldown(&state.caller_user_id, &state.callee_user_id)
                                .await;
                        }
                    }
                }
            }

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

    if is_answer {
        if let Some((state, newly_accepted)) =
            registry.accept_call(&call_id, &sender_device_id).await
        {
            if newly_accepted {
                metrics::CALLS_CONNECTED_TOTAL.inc();
                if let Some(answered_at_ms) = state.answered_at_ms {
                    let dur_ms = answered_at_ms.saturating_sub(state.offered_at_ms);
                    metrics::CALL_SETUP_DURATION_SECONDS.observe(dur_ms as f64 / 1000.0);
                }
            }

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
                let _ = registry
                    .send_to_user_except(
                        &state.callee_user_id,
                        &sender_device_id,
                        ForwardedSignal::Signal(hangup),
                    )
                    .await;
            } else {
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

fn call_type_to_str(call_type: i32) -> &'static str {
    match call_type {
        1 => "audio",
        2 => "video",
        3 => "screen",
        4 => "group",
        _ => "audio",
    }
}

fn signal_error_code_to_str(code: SignalErrorCode) -> &'static str {
    match code {
        SignalErrorCode::Unspecified => "unspecified",
        SignalErrorCode::CalleeOffline => "callee_offline",
        SignalErrorCode::CalleeBusy => "callee_busy",
        SignalErrorCode::RateLimited => "rate_limited",
        SignalErrorCode::Unauthorized => "unauthorized",
        SignalErrorCode::CallExpired => "call_expired",
    }
}

pub(crate) fn make_instance_id() -> String {
    format!("signaling-{}-{}", std::process::id(), unix_millis())
}

pub(crate) fn make_default_peer_salt(turn_secret: &str) -> String {
    turn_secret.to_string()
}
