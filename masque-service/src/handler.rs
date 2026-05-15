use std::sync::Arc;

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const MAX_DATAGRAM: usize = 1500;

#[derive(Clone, Debug)]
pub struct Config {
    /// Target UDP address: "host:port" (e.g. "traefik:443" in Docker, "ams.konstruct.cc:443" externally)
    pub target: String,
    /// Optional bearer token. Empty = no auth (dev mode).
    pub auth_token: String,
}

pub async fn masque_ws_handler(
    ws: WebSocketUpgrade,
    State(config): State<Config>,
    headers: HeaderMap,
) -> Response {
    if !config.auth_token.is_empty() {
        let expected = format!("Bearer {}", config.auth_token);
        let ok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == expected)
            .unwrap_or(false);
        if !ok {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    }

    let target = config.target.clone();
    ws.on_upgrade(move |socket| bridge(socket, target))
}

/// One WebSocket connection = one UDP socket bridging iOS QUIC traffic to the Traefik QUIC endpoint.
///
/// Each WS binary frame carries exactly one QUIC datagram (≤1350 bytes in practice).
/// The UDP socket is connected to `target` so responses go back to the same remote address.
async fn bridge(mut ws: WebSocket, target: String) {
    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(error = %e, "failed to bind UDP socket");
            return;
        }
    };

    if let Err(e) = udp.connect(&target).await {
        warn!(error = %e, %target, "failed to connect UDP socket to target");
        return;
    }

    let local_addr = udp.local_addr().map(|a| a.to_string()).unwrap_or_default();
    info!(%target, %local_addr, "MASQUE bridge open");

    // Spawn a task to read UDP responses and forward them into a channel.
    // Channel::recv() is cancellation-safe — safe to use in tokio::select!.
    let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel::<Bytes>(256);
    let udp_reader = tokio::spawn({
        let udp = Arc::clone(&udp);
        async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match udp.recv(&mut buf).await {
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        if udp_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "UDP recv error — closing bridge");
                        break;
                    }
                }
            }
        }
    });

    loop {
        tokio::select! {
            // WS → UDP: iOS sends a QUIC datagram wrapped in a WS binary frame
            msg = ws.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if let Err(e) = udp.send(&data).await {
                            debug!(error = %e, "UDP send error — closing bridge");
                            break;
                        }
                    }
                    // Pings are auto-responded by axum; ignore pong/text
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_))) => {}
                    // WS closed or errored — tear down the bridge
                    None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                }
            }
            // UDP → WS: server sends a QUIC datagram back to iOS
            data = udp_rx.recv() => {
                match data {
                    Some(bytes) => {
                        if ws.send(Message::Binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    udp_reader.abort();
    info!(%target, %local_addr, "MASQUE bridge closed");
}
