use std::sync::Arc;

use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info};

use construct_server_shared::shared::proto::signaling::v1::{
    signal_request, signal_response, signaling_service_server::SignalingService, web_rtc_signal,
    CallHangup, GetTurnCredentialsRequest, GetTurnCredentialsResponse, HangupReason,
    IncomingCallNotification, RoutedWebRtcSignal, SignalError, SignalErrorCode, SignalPong,
    SignalRequest, SignalResponse, WebRtcSignal,
};

use crate::forwarded::{ForwardedSignal, IncomingCall};
use crate::rate_limiter::RateLimiter;
use crate::registry::CallRegistry;
use crate::routing::callee_user_id_from_route;
use crate::time::unix_millis;
use crate::turn::generate_turn_credentials;

pub(crate) struct SignalingServiceImpl {
    pub(crate) registry: Arc<CallRegistry>,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) turn_secret: String,
    pub(crate) turn_ttl: u64,
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
        registry.touch_online(&user_id, &device_id).await;
        let mut rx = tx.subscribe();

        info!(user_id, device_id, "signal stream opened");

        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Result<SignalResponse, Status>>(64);

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

            let callee_devices = registry.list_online_devices(callee_user_id).await;
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

pub(crate) fn make_instance_id() -> String {
    format!("signaling-{}-{}", std::process::id(), unix_millis())
}

pub(crate) fn make_default_peer_salt(turn_secret: &str) -> String {
    turn_secret.to_string()
}
