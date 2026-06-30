// Network + gRPC server helpers.
//
// Extracted verbatim from `construct_server_shared` so service binaries can
// pull them in via `construct_utils::net::*` without taking a dependency on
// the full shared crate (proto, services, etc.).

use anyhow::{Context, Result};

/// Wait for SIGTERM or Ctrl-C — used for graceful shutdown across all services.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Create a TCP listener that uses MPTCP on Linux when available, falling back to regular TCP.
///
/// On Linux, MPTCP (kernel 5.6+) enables multipath connections — the OS can seamlessly
/// switch between Wi-Fi and cellular subflows without dropping the TCP connection.
/// On macOS/other platforms, or when the kernel does not support MPTCP, falls back to TCP.
///
/// The listening socket has TCP keepalive enabled so accepted connections inherit the setting.
pub async fn mptcp_or_tcp_listener(addr: &str) -> Result<tokio::net::TcpListener> {
    #[cfg(target_os = "linux")]
    {
        use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
        use std::time::Duration;

        const IPPROTO_MPTCP: i32 = 262;

        let sock_addr: std::net::SocketAddr = addr
            .parse()
            .with_context(|| format!("invalid bind address: {addr}"))?;
        let domain = if sock_addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        match Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_MPTCP))) {
            Ok(socket) => {
                socket.set_reuse_address(true)?;
                socket.set_reuse_port(true)?;
                socket.set_nonblocking(true)?;
                // TCP keepalive on the listen socket — accepted connections inherit it.
                let keepalive = TcpKeepalive::new()
                    .with_time(Duration::from_secs(30))
                    .with_interval(Duration::from_secs(10));
                socket.set_tcp_keepalive(&keepalive)?;
                socket.bind(&sock_addr.into())?;
                socket.listen(1024)?;
                let std_listener: std::net::TcpListener = socket.into();
                let listener = tokio::net::TcpListener::from_std(std_listener)?;
                tracing::info!("MPTCP listener bound on {}", addr);
                return Ok(listener);
            }
            Err(e) => {
                tracing::warn!("MPTCP unavailable ({}), falling back to TCP on {}", e, addr);
            }
        }
    }
    tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind TCP listener on {addr}"))
}

/// Create an MPTCP (or TCP fallback) listener and return it as a `TcpListenerStream`
/// suitable for use with tonic's `serve_with_incoming_shutdown`.
pub async fn mptcp_incoming(addr: &str) -> Result<tokio_stream::wrappers::TcpListenerStream> {
    let listener = mptcp_or_tcp_listener(addr).await?;
    Ok(tokio_stream::wrappers::TcpListenerStream::new(listener))
}

/// Create a pre-configured tonic gRPC server with HTTP/2 keepalive and tuned window sizes.
///
/// - Keepalive pings the client every `keepalive_interval_secs` seconds and closes
///   unresponsive connections after `keepalive_timeout_secs`. iOS suspends sockets for
///   up to ~30s when the app backgrounds; the default 45s avoids false-positive
///   disconnects while still cleaning up truly dead connections. Configurable via
///   `GRPC_KEEPALIVE_INTERVAL_SECS`.
/// - Application-level heartbeats in MessageStream keep streams active (configurable
///   via `MSG_STREAM_HEARTBEAT_INTERVAL_SECS`), ensuring the HTTP/2 PING fires even
///   during idle periods (tonic 0.14 does not expose keepalive_while_idle).
/// - HTTP/2 window sizes are set to 4 MB (connection) and 2 MB (per-stream) to
///   prevent flow-control stalls when delivering large GetPendingMessages responses
///   without extra RTTs for window updates.
/// - tcp_keepalive probes the underlying TCP connection every 30s; prevents the OS
///   from silently dropping idle connections behind NAT/firewalls.
pub fn grpc_server(
    keepalive_interval_secs: u64,
    keepalive_timeout_secs: u64,
) -> tonic::transport::Server {
    tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(
            keepalive_interval_secs,
        )))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(keepalive_timeout_secs)))
        .initial_connection_window_size(4 * 1024 * 1024) // 4 MB (default 64 KB)
        .initial_stream_window_size(2 * 1024 * 1024) // 2 MB (default 64 KB)
        .tcp_keepalive(Some(std::time::Duration::from_secs(30)))
}