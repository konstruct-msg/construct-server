use std::{collections::BTreeMap, io, time::Duration};

use construct_utils::net::{decode_limits, grpc_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_stream::StreamExt;
use tonic::service::Routes;

// RFC 9113: client connection preface and empty SETTINGS, then a SETTINGS ACK.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0";
const SETTINGS_ACK: &[u8] = b"\0\0\0\x04\x01\0\0\0\0";

struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

async fn read_frame(peer: &mut DuplexStream) -> Frame {
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.expect("frame header");
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert!(length <= 16_384, "expected an HTTP/2 control frame");
    let mut payload = vec![0; length];
    peer.read_exact(&mut payload).await.expect("frame payload");
    Frame {
        kind: header[3],
        flags: header[4],
        stream: u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff,
        payload,
    }
}

fn start_server(interval: u64, keepalive_timeout: u64) -> (DuplexStream, JoinSet<()>) {
    let (peer, server_io) = tokio::io::duplex(4_096);
    // Keep accepting open but give tonic just one in-process connection. Dropping
    // the JoinSet always cancels the listener task, including on failed asserts.
    let incoming = tokio_stream::once(Ok::<_, io::Error>(server_io)).chain(tokio_stream::pending());
    let mut task = JoinSet::new();
    task.spawn(async move {
        grpc_server(interval, keepalive_timeout)
            .serve_with_incoming(Routes::default(), incoming)
            .await
            .expect("serve HTTP/2");
    });
    (peer, task)
}

#[tokio::test]
async fn grpc_server_advertises_the_stream_budget_and_actual_flow_control_windows() {
    let (mut peer, _server) = start_server(45, 20);
    timeout(Duration::from_secs(3), async {
        peer.write_all(PREFACE).await.expect("write preface");
        let settings = read_frame(&mut peer).await;
        assert_eq!((settings.kind, settings.flags, settings.stream), (4, 0, 0));
        let (entries, remainder) = settings.payload.as_chunks::<6>();
        assert!(remainder.is_empty(), "SETTINGS entries are six bytes");
        let params: BTreeMap<_, _> = entries
            .iter()
            .map(|entry| {
                (
                    u16::from_be_bytes(entry[..2].try_into().unwrap()),
                    u32::from_be_bytes(entry[2..].try_into().unwrap()),
                )
            })
            .collect();
        assert_eq!(
            params.get(&3),
            Some(&128),
            "SETTINGS_MAX_CONCURRENT_STREAMS"
        );
        assert_eq!(
            params.get(&4),
            Some(&2_097_152),
            "SETTINGS_INITIAL_WINDOW_SIZE"
        );
        assert_eq!(
            params.get(&6),
            Some(&65_536),
            "SETTINGS_MAX_HEADER_LIST_SIZE"
        );

        peer.write_all(SETTINGS_ACK).await.expect("ack settings");
        let update = loop {
            let frame = read_frame(&mut peer).await;
            if frame.kind == 8 {
                break frame;
            }
        };
        assert_eq!(
            update.stream, 0,
            "WINDOW_UPDATE on the connection, not a stream"
        );
        let increment = u32::from_be_bytes(update.payload.as_slice().try_into().unwrap());
        assert_eq!(
            65_535 + increment,
            4_194_304,
            "connection window including its RFC default"
        );
    })
    .await
    .expect("server sends settings and connection window in time");
}

#[tokio::test(start_paused = true)]
async fn grpc_server_pings_and_closes_on_the_configured_deadlines() {
    let (mut peer, _server) = start_server(7, 11);
    let start = Instant::now();
    timeout(Duration::from_secs(25), async {
        peer.write_all(PREFACE).await.expect("write preface");
        let settings = read_frame(&mut peer).await;
        assert_eq!(settings.kind, 4);
        peer.write_all(SETTINGS_ACK).await.expect("ack settings");
        let ping = loop {
            let frame = read_frame(&mut peer).await;
            if frame.kind == 6 {
                break frame;
            }
        };
        assert_eq!((ping.flags, ping.stream, ping.payload.len()), (0, 0, 8));
        let ping_at = Instant::now();
        assert_delay(ping_at - start, 7);

        // This peer doesn't answer the keepalive. Read until the real transport closes.
        tokio::io::copy(&mut peer, &mut tokio::io::sink())
            .await
            .expect("read until close");
        assert_delay(ping_at.elapsed(), 11);
    })
    .await
    .expect("keepalive deadlines reached under the paused clock");
}

fn assert_delay(elapsed: Duration, expected_secs: u64) {
    // Allow for the timer wheel's millisecond rounding, not wall-clock scheduling.
    assert!(
        (Duration::from_secs(expected_secs)..=Duration::from_millis(expected_secs * 1000 + 10))
            .contains(&elapsed),
        "expected about {expected_secs}s, observed {elapsed:?}"
    );
}

#[test]
fn service_decode_budgets_match_the_documented_table() {
    // These are the limits supplied to the generated servers, not a stand-in for
    // integration tests of all the RPCs or of the edge proxy.
    assert_eq!(
        [
            decode_limits::IDENTITY,
            decode_limits::KEY,
            decode_limits::MESSAGING,
            decode_limits::NOTIFICATION,
            decode_limits::SENTINEL,
            decode_limits::GROUP,
            decode_limits::SIGNALING,
            decode_limits::VEIL
        ],
        [
            262_144, 1_048_576, 524_288, 65_536, 524_288, 1_048_576, 262_144, 65_536
        ]
    );
}
