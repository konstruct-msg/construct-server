use std::sync::Arc;

use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info};
use uuid::Uuid;

use construct_auth::AuthManager;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::metrics;
use construct_server_shared::shared::proto::services::v1 as services_proto;
use construct_server_shared::shared::proto::signaling::v1::{
    CallHangup, GetTurnCredentialsRequest, GetTurnCredentialsResponse, HangupReason,
    IncomingCallNotification, InitiateCallRequest, InitiateCallResponse, RoutedWebRtcSignal,
    SignalError, SignalErrorCode, SignalPong, SignalRequest, SignalResponse, WebRtcSignal,
    signal_request, signal_response, signaling_service_server::SignalingService, web_rtc_signal,
};

use crate::forwarded::{ForwardedSignal, IncomingCall};
use crate::rate_limiter::RateLimiter;
use crate::registry::{CallRegistry, CallRole, not_a_participant, not_the_stream_device};
use crate::time::unix_millis;
use crate::turn::generate_turn_credentials;

/// Send a signal response on the gRPC stream; log if the client already hung up.
async fn send_out(
    out_tx: &tokio::sync::mpsc::Sender<Result<SignalResponse, Status>>,
    response: SignalResponse,
) {
    if out_tx.send(Ok(response)).await.is_err() {
        tracing::debug!("signal stream closed; dropped outbound response");
    }
}

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
    /// PASETO auth manager for device_id cross-verification.
    /// `None` when PASETO_PUBLIC_KEY is not available (falls back to trusting
    /// the gateway-injected x-device-id header directly).
    pub(crate) auth: Option<Arc<AuthManager>>,
}

/// Authenticated user_id from Bearer token (optional x-user-id must match).
/// When `auth` is `None` (misconfigured keys), refuse rather than trust headers.
/// Every refusal of a call reads the same: not a mutual contact, blocked by the callee, or the
/// check unavailable. Until 2026-10-18 the block had its own text, so the caller learned they
/// were blocked (TODO 170). Why it was refused stays in the server log.
fn call_refused() -> Status {
    Status::permission_denied("Call not allowed")
}

fn caller_user_id<T>(req: &Request<T>, auth: Option<&AuthManager>) -> Result<String, Status> {
    let auth = auth.ok_or_else(|| {
        Status::failed_precondition(
            "AuthManager not configured — set PASETO public keys on signaling-service",
        )
    })?;
    let caller = construct_server_shared::auth_utils::extract_authed_caller(auth, req.metadata())?;
    Ok(caller.user_id.to_string())
}

/// Authenticated device_id from Bearer token (+ optional x-device-id consistency).
fn verified_caller_device_id<T>(
    req: &Request<T>,
    auth: Option<&AuthManager>,
) -> Result<String, Status> {
    let auth = auth.ok_or_else(|| {
        Status::failed_precondition(
            "AuthManager not configured — set PASETO public keys on signaling-service",
        )
    })?;
    construct_server_shared::auth_utils::extract_device_id(auth, req.metadata())
}

#[tonic::async_trait]
impl SignalingService for SignalingServiceImpl {
    type SignalStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<SignalResponse, Status>> + Send>>;

    async fn signal(
        &self,
        request: Request<Streaming<SignalRequest>>,
    ) -> Result<Response<Self::SignalStream>, Status> {
        let user_id = caller_user_id(&request, self.auth.as_deref())?;
        let device_id = verified_caller_device_id(&request, self.auth.as_deref())?;
        let mut inbound = request.into_inner();
        let registry = Arc::clone(&self.registry);
        let rate_limiter = self.rate_limiter.clone();

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
                                        send_out(&out_tx, SignalResponse {
                                                response: Some(
                                                    signal_response::Response::Error(SignalError {
                                                        code: SignalErrorCode::RateLimited as i32,
                                                        message:
                                                            "Signal rate limit exceeded (max 10/sec)"
                                                                .into(),
                                                    }),
                                                ),
                                            }).await;
                                        continue;
                                    }

                                    registry
                                        .touch_online(&user_id, &device_id_for_inbound)
                                        .await;
                                    registry.note_keepalive(&user_id).await;
                                    if let Err(e) = handle_outbound_signal(
                                        &registry,
                                        &rate_limiter,
                                        &user_id,
                                        &device_id_for_inbound,
                                        routed,
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
                                    send_out(
                                        &out_tx,
                                        SignalResponse {
                                            response: Some(signal_response::Response::Pong(
                                                SignalPong {
                                                    timestamp: ping.timestamp,
                                                    server_timestamp: unix_millis(),
                                                },
                                            )),
                                        },
                                    )
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

            registry.unregister_user(&user_id, &device_id).await;

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

            info!(user_id, "signal stream closed");
        });

        let output = tokio_stream::wrappers::ReceiverStream::new(out_rx);
        Ok(Response::new(Box::pin(output)))
    }

    async fn get_turn_credentials(
        &self,
        request: Request<GetTurnCredentialsRequest>,
    ) -> Result<Response<GetTurnCredentialsResponse>, Status> {
        let user_id = caller_user_id(&request, self.auth.as_deref())?;
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
        let credentials = generate_turn_credentials(&self.turn_secret, self.turn_ttl);
        Ok(Response::new(GetTurnCredentialsResponse {
            credentials: Some(credentials),
        }))
    }

    async fn initiate_call(
        &self,
        request: Request<InitiateCallRequest>,
    ) -> Result<Response<InitiateCallResponse>, Status> {
        tracing::info!("InitiateCall received");
        let caller_id = caller_user_id(&request, self.auth.as_deref())?;
        let caller_device_id_str = verified_caller_device_id(&request, self.auth.as_deref())?;
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
            // Validate UUIDs, but use the canonical string form for HMAC so the
            // computed values match what invite-service stores (String::as_bytes()).
            let (Ok(caller_uuid), Ok(callee_uuid)) =
                (Uuid::parse_str(&caller_id), Uuid::parse_str(callee_user_id))
            else {
                return Err(Status::invalid_argument("Invalid user_id UUID"));
            };

            let caller_hmac =
                construct_db::contact_link_hmac(&self.contact_hmac_secret, &caller_uuid);
            let callee_hmac =
                construct_db::contact_link_hmac(&self.contact_hmac_secret, &callee_uuid);
            match construct_db::are_mutual_contacts(pool, &caller_hmac, &callee_hmac).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        caller_id,
                        callee_user_id,
                        "InitiateCall denied — not mutual contacts"
                    );
                    return Err(call_refused());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to check mutual contacts — denying (fail-closed)");
                    return Err(call_refused());
                }
            }

            match construct_db::is_blocked_by(pool, &callee_uuid, &caller_uuid).await {
                Ok(true) => {
                    tracing::warn!(
                        caller_id,
                        callee_user_id,
                        "InitiateCall denied — caller is blocked"
                    );
                    return Err(call_refused());
                }
                Ok(false) => {}
                Err(e) => {
                    // Fail-closed, like the contact check above. Proceeding let a call ring
                    // someone who had blocked the caller whenever this one query failed.
                    tracing::warn!(error = %e, "Failed to check user_blocks — denying (fail-closed)");
                    return Err(call_refused());
                }
            }
        } else {
            tracing::warn!("InitiateCall denied — db_pool not configured (DATABASE_URL missing?)");
            return Err(call_refused());
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
            let delivered = self
                .registry
                .send_to_user(callee_user_id, None, incoming)
                .await;
            if delivered == 0 {
                // Callee was listed as online (non-empty presence) but their signal stream was
                // already closed (stale presence). Fall back to VoIP push so they are woken up.
                tracing::warn!(
                    call_id,
                    callee_user_id,
                    "callee had stale presence — signal delivery failed, sending VoIP push as fallback"
                );
                if let Some(client) = self.notification_client.clone() {
                    let push_req = services_proto::SendVoipIncomingCallRequest {
                        user_id: callee_user_id.to_string(),
                        call_id: call_id.clone(),
                        caller_id: caller_id.clone(),
                        caller_name: caller_name.clone(),
                        call_type: req.call_type,
                        offered_at: unix_millis(),
                    };
                    tokio::spawn(async move {
                        let mut grpc = client.get();
                        if let Err(e) = grpc
                            .send_voip_incoming_call(tonic::Request::new(push_req))
                            .await
                        {
                            tracing::warn!(error = %e, "Failed to send VoIP push fallback for stale-presence callee");
                        }
                    });
                }
            }
        } else if let Some(client) = self.notification_client.clone() {
            // ── VoIP push to wake offline callee (no SDP in payload) ───────
            let push_req = services_proto::SendVoipIncomingCallRequest {
                user_id: callee_user_id.to_string(),
                call_id: call_id.clone(),
                caller_id: caller_id.clone(),
                caller_name: caller_name.clone(),
                call_type: req.call_type,
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

/// Handle a signal a client sent up the Signal stream.
///
/// Everything call *creation* needs — mutual contacts, blocks, rate limits, busy, the push — lives
/// in `initiate_call`, and only there. This function had a full second copy of all of it in its
/// `Offer` arm until 2026-08-21; the parameters that copy required (`db_pool`,
/// `contact_hmac_secret`, `notification_client`, the route and the caller's display fields) left
/// with it, which is why the signature is short now and no longer needs
/// `allow(clippy::too_many_arguments)`.
async fn handle_outbound_signal(
    registry: &Arc<CallRegistry>,
    rate_limiter: &RateLimiter,
    user_id: &str,
    device_id: &str,
    routed: RoutedWebRtcSignal,
) -> Result<(), Status> {
    let RoutedWebRtcSignal { signal, .. } = routed;

    let signal = signal.ok_or_else(|| Status::invalid_argument("Missing routed_signal.signal"))?;
    let call_id = signal.call_id.clone();
    // The device is the stream's, verified from the token. A signal may repeat it, never name
    // another: the id decides where the peer's replies are routed and which device is recorded
    // as having answered.
    if !signal.sender_device_id.is_empty()
        && !signal.sender_device_id.eq_ignore_ascii_case(device_id)
    {
        return Err(not_the_stream_device());
    }
    let sender_device_id = device_id.to_string();

    // One gate for everything that touches a call: only its two parties. Until 2026-10-29
    // `Busy` and `Hangup` discarded `forward_signal`'s participant check (they must survive an
    // offline peer, so its error was ignored wholesale) and then removed the call regardless —
    // anyone who knew a call_id could end it — and `Ringing` / `Connected` changed call state
    // before any check ran. A call that no longer exists has no parties to check; the arms below
    // treat it as they did.
    let role = match registry.load_call_state(&call_id).await {
        Some(state) => Some(state.role_of(user_id).ok_or_else(not_a_participant)?),
        None => None,
    };

    match &signal.signal {
        Some(web_rtc_signal::Signal::Offer(_)) | Some(web_rtc_signal::Signal::Answer(_)) => {
            // SDP does not travel this stream, in either direction.
            //
            // An offer or answer reaches a peer through MessagingService, inside the Double
            // Ratchet. This arm used to accept a plaintext one and honour it: the Offer half was a
            // second, parallel entry point to call creation — its own copy of the mutual-contact
            // check, the block check, all three rate limits, the busy check and
            // CALLS_INITIATED_TOTAL, duplicating `initiate_call` line for line. Two implementations
            // of one rule, and a new rule added to one of them would have left the other as the way
            // around it. The Answer half drove `accept_call` — see the note further down for what
            // that leaves unowned; `Connected` does not pick it up.
            //
            // Refusing costs nothing today: no shipped client sends SDP here — iOS/macOS calls
            // `InitiateCall` and signals presence on this stream, and Android has no call code at
            // all. What it removes is a way in that nobody was watching.
            let kind = match &signal.signal {
                Some(web_rtc_signal::Signal::Offer(_)) => "offer",
                _ => "answer",
            };
            metrics::SIGNALING_SDP_REFUSED_TOTAL
                .with_label_values(&[kind])
                .inc();
            tracing::warn!(
                call_id,
                user_id,
                kind,
                "Refused SDP on the Signal stream — offers and answers travel E2EE via \
                 MessagingService. Use InitiateCall to create the call."
            );
            return Ok(());
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
            // Ringing is the callee's device announcing itself; a caller cannot ring.
            if role == Some(CallRole::Callee) {
                registry.note_ringing(&call_id).await;
            }
            registry
                .forward_signal(
                    &call_id,
                    user_id,
                    &sender_device_id,
                    ForwardedSignal::Signal(signal),
                )
                .await?;
        }
        Some(web_rtc_signal::Signal::Connected(_)) => {
            if let Some(role) = role {
                let callee_device = (role == CallRole::Callee).then_some(sender_device_id.as_str());
                registry.note_connected(&call_id, callee_device).await;
            }
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
            if let Some(web_rtc_signal::Signal::Hangup(hangup)) = &signal.signal
                && hangup.reason == HangupReason::Declined as i32
                && let Some(state) = registry.load_call_state(&call_id).await
                && state.callee_user_id == user_id
            {
                metrics::CALLS_DECLINED_TOTAL.inc();
                let _ = rate_limiter
                    .set_decline_cooldown(&state.caller_user_id, &state.callee_user_id)
                    .await;
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

    // `accept_call` used to run here, gated on `is_answer`, and it was the only production caller:
    // it incremented CALLS_CONNECTED_TOTAL, observed CALL_SETUP_DURATION_SECONDS, and sent
    // ACCEPTED_ELSEWHERE hangups to the callee's other devices. The Answer arm that reached it is
    // refused as of 2026-08-21, so none of that had a producer left — and none of it had one before
    // either, because no shipped client has sent an Answer on this stream since call signalling
    // moved into MessagingService. Those two metrics have therefore been reporting nothing, and
    // multi-device ACCEPTED_ELSEWHERE has not been happening at all.
    //
    // Not moved to the `Connected` arm in the same change, deliberately. `Connected` is sent by
    // *either* peer once media is up, so the accounting has to establish which side it came from
    // before it can hang up "the callee's other devices" — driving that fan-out from the caller's
    // own signal would hang up devices in a live call. `note_connected` already sets
    // `answered_at_ms`, which is what the reaper needs; the metrics and the fan-out are their own
    // piece of work.

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

pub(crate) fn make_instance_id() -> String {
    format!("signaling-{}-{}", std::process::id(), unix_millis())
}

pub(crate) fn make_default_peer_salt(turn_secret: &str) -> String {
    turn_secret.to_string()
}

#[cfg(test)]
mod call_refusal_tests {
    /// A second text would tell a blocked caller apart from one who is not a contact.
    #[test]
    fn every_call_refusal_reads_the_same() {
        let source = include_str!("service.rs");
        let literal = concat!("Status::permission", "_denied(");
        assert_eq!(
            source.matches(literal).count(),
            1,
            "refuse a call through call_refused()"
        );
    }
}

/// The participant gate in `handle_outbound_signal` (construct-docs todo 230). Needs Redis, like the
/// registry's own tests; each test uses its own call id and users so they do not share state.
#[cfg(test)]
mod signal_gate_tests {
    use super::*;
    use construct_server_shared::shared::proto::signaling::v1::{
        CallBusy, CallConnected, CallRinging,
    };

    struct Call {
        registry: Arc<CallRegistry>,
        limiter: RateLimiter,
        id: String,
        caller: String,
        callee: String,
    }

    async fn new_call() -> Call {
        let url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let registry = Arc::new(
            CallRegistry::new(&url, "gate-test".into())
                .await
                .expect("registry needs Redis"),
        );
        let conn = construct_redis::manager_for(redis::Client::open(url).unwrap())
            .await
            .expect("Redis");
        let limiter = RateLimiter::new(conn, "salt".into(), Default::default());
        let id = format!("gate-{}", Uuid::new_v4());
        let caller = format!("caller-{}", Uuid::new_v4());
        let callee = format!("callee-{}", Uuid::new_v4());
        registry
            .create_call(&id, &caller, "caller-device", &callee, unix_millis())
            .await;
        Call {
            registry,
            limiter,
            id,
            caller,
            callee,
        }
    }

    fn routed(
        call_id: &str,
        sender_device: &str,
        signal: web_rtc_signal::Signal,
    ) -> RoutedWebRtcSignal {
        RoutedWebRtcSignal {
            signal: Some(WebRtcSignal {
                call_id: call_id.into(),
                signal: Some(signal),
                sender_device_id: sender_device.into(),
                timestamp: unix_millis(),
            }),
            route: None,
            ..Default::default()
        }
    }

    async fn send(
        call: &Call,
        user: &str,
        device: &str,
        signal: web_rtc_signal::Signal,
    ) -> Result<(), Status> {
        handle_outbound_signal(
            &call.registry,
            &call.limiter,
            user,
            device,
            routed(&call.id, device, signal),
        )
        .await
    }

    #[tokio::test]
    async fn a_stranger_cannot_touch_someone_elses_call() {
        let stranger = format!("stranger-{}", Uuid::new_v4());
        let signals = [
            web_rtc_signal::Signal::Hangup(CallHangup::default()),
            web_rtc_signal::Signal::Busy(CallBusy::default()),
            web_rtc_signal::Signal::Ringing(CallRinging::default()),
            web_rtc_signal::Signal::Connected(CallConnected::default()),
        ];
        for signal in signals {
            let call = new_call().await;
            let err = send(&call, &stranger, "stranger-device", signal.clone())
                .await
                .expect_err("a non-participant must be refused");
            assert_eq!(err.code(), tonic::Code::PermissionDenied, "{signal:?}");
            let state = call
                .registry
                .load_call_state(&call.id)
                .await
                .expect("the call survives a stranger's signal");
            assert!(state.ringing_at_ms.is_none(), "{signal:?}");
            assert!(state.answered_at_ms.is_none(), "{signal:?}");
            assert!(state.accepted_callee_device_id.is_none(), "{signal:?}");
            call.registry.remove_call(&call.id).await;
        }
    }

    #[tokio::test]
    async fn a_party_still_ends_the_call_when_the_peer_is_offline() {
        // Busy/Hangup ignore forward errors on purpose — "peer offline" must not keep a call alive.
        let call = new_call().await;
        send(
            &call,
            &call.callee,
            "callee-device",
            web_rtc_signal::Signal::Hangup(CallHangup::default()),
        )
        .await
        .expect("the callee may hang up");
        assert!(call.registry.load_call_state(&call.id).await.is_none());
    }

    #[tokio::test]
    async fn the_callers_connected_does_not_name_the_answering_device() {
        let call = new_call().await;
        let _ = send(
            &call,
            &call.caller,
            "caller-device",
            web_rtc_signal::Signal::Connected(CallConnected::default()),
        )
        .await;
        let state = call.registry.load_call_state(&call.id).await.unwrap();
        assert!(state.answered_at_ms.is_some(), "the call reads as answered");
        assert_eq!(state.accepted_callee_device_id, None);
        let answered_at = state.answered_at_ms;

        let _ = send(
            &call,
            &call.callee,
            "callee-device",
            web_rtc_signal::Signal::Connected(CallConnected::default()),
        )
        .await;
        let state = call.registry.load_call_state(&call.id).await.unwrap();
        assert_eq!(
            state.accepted_callee_device_id.as_deref(),
            Some("callee-device")
        );
        assert_eq!(state.answered_at_ms, answered_at, "first answer time kept");
        call.registry.remove_call(&call.id).await;
    }

    #[tokio::test]
    async fn a_signal_naming_another_device_is_refused() {
        let call = new_call().await;
        let err = handle_outbound_signal(
            &call.registry,
            &call.limiter,
            &call.callee,
            "callee-device",
            routed(
                &call.id,
                "some-other-device",
                web_rtc_signal::Signal::Connected(CallConnected::default()),
            ),
        )
        .await
        .expect_err("the stream's device, not the signal's");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let state = call.registry.load_call_state(&call.id).await.unwrap();
        assert!(state.accepted_callee_device_id.is_none());
        call.registry.remove_call(&call.id).await;
    }

    #[test]
    fn role_of_names_each_party_and_nobody_else() {
        let state = crate::registry::CallState {
            call_id: "c".into(),
            caller_user_id: "a".into(),
            callee_user_id: "b".into(),
            caller_device_id: "a1".into(),
            accepted_callee_device_id: None,
            created_at: 0,
            offered_at_ms: 0,
            ringing_at_ms: None,
            answered_at_ms: None,
            caller_last_keepalive_at: 0,
            callee_last_keepalive_at: 0,
        };
        assert_eq!(state.role_of("a"), Some(CallRole::Caller));
        assert_eq!(state.role_of("b"), Some(CallRole::Callee));
        assert_eq!(state.role_of("c"), None);
        assert_eq!(state.role_of(""), None);
    }
}
