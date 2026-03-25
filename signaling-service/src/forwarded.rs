use base64::Engine;
use prost::Message;
use serde::{Deserialize, Serialize};

use construct_server_shared::shared::proto::signaling::v1::{
    signal_response, IncomingCallNotification, SignalError, SignalResponse, WebRtcSignal,
};

#[derive(Clone, Debug)]
pub(crate) enum ForwardedSignal {
    Signal(WebRtcSignal),
    IncomingCall(IncomingCall),
    Error(SignalErrorInfo),
}

#[derive(Clone, Debug)]
pub(crate) struct IncomingCall {
    pub(crate) call_id: String,
    pub(crate) caller_id: String,
    pub(crate) caller_name: String,
    pub(crate) call_type: i32,
    pub(crate) offered_at: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct SignalErrorInfo {
    pub(crate) code: i32,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct InstanceEnvelope {
    pub(crate) user_id: String,
    pub(crate) device_id: Option<String>,
    pub(crate) response_b64: String,
}

pub(crate) fn signal_response_from_forwarded(signal: &ForwardedSignal) -> SignalResponse {
    match signal {
        ForwardedSignal::Signal(s) => SignalResponse {
            response: Some(signal_response::Response::Signal(s.clone())),
        },
        ForwardedSignal::IncomingCall(call) => SignalResponse {
            response: Some(signal_response::Response::IncomingCall(
                IncomingCallNotification {
                    call_id: call.call_id.clone(),
                    caller_id: call.caller_id.clone(),
                    caller_name: call.caller_name.clone(),
                    caller_avatar: Vec::new(),
                    call_type: call.call_type,
                    offered_at: call.offered_at,
                },
            )),
        },
        ForwardedSignal::Error(err) => SignalResponse {
            response: Some(signal_response::Response::Error(SignalError {
                code: err.code,
                message: err.message.clone(),
            })),
        },
    }
}

pub(crate) fn forwarded_from_signal_response(resp: SignalResponse) -> Option<ForwardedSignal> {
    match resp.response? {
        signal_response::Response::Signal(s) => Some(ForwardedSignal::Signal(s)),
        signal_response::Response::IncomingCall(call) => {
            Some(ForwardedSignal::IncomingCall(IncomingCall {
                call_id: call.call_id,
                caller_id: call.caller_id,
                caller_name: call.caller_name,
                call_type: call.call_type,
                offered_at: call.offered_at,
            }))
        }
        signal_response::Response::Error(err) => Some(ForwardedSignal::Error(SignalErrorInfo {
            code: err.code,
            message: err.message,
        })),
        signal_response::Response::Pong(_) => None,
    }
}

pub(crate) fn encode_signal_response_base64(resp: SignalResponse) -> String {
    let bytes = resp.encode_to_vec();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn decode_signal_response_base64(b64: &str) -> Result<SignalResponse, anyhow::Error> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
    Ok(SignalResponse::decode(bytes.as_slice())?)
}
