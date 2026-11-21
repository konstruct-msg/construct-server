//! One-process, loopback H2 profile. Observer is absent from the service binary.
use super::{
    allocation_profile::{allocations::AllocationSample, process_cpu_seconds},
    make_config, make_ed25519_pems,
};
use crate::{
    context::MessagingServiceContext, grpc::MessagingGrpcService, stream::STREAM_MAILBOX_PAGE,
};
use anyhow::{Context, Result, ensure};
use construct_auth::AuthManager;
use construct_config::StealthTokenPolicy;
use construct_message::MessageEnvelope;
use construct_queue::{MailboxPage, MessageQueue};
use construct_server_shared::shared::proto::{
    core::v1::envelope::MessageIdType,
    services::v1::{
        self as proto, messaging_service_client::MessagingServiceClient,
        messaging_service_server::MessagingServiceServer,
    },
};
use prost::Message;
use std::{
    cell::RefCell,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{
    Request, Streaming,
    transport::{Channel, Endpoint},
};
use uuid::Uuid;

const COUNT: usize = 192;
const DEADLINE: Duration = Duration::from_secs(12);

// Only owned sealed-inner Vec capacity (bytes), not the rest of the response or page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Stock {
    frames: usize,
    bytes: usize,
}

impl Stock {
    fn add(&mut self, bytes: usize) {
        self.frames += 1;
        self.bytes += bytes;
    }

    fn remove(&mut self, bytes: usize) {
        self.frames -= 1;
        self.bytes -= bytes;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Retention {
    queue: Stock,
    page: Stock,
    pending_bytes: usize,
    // Uncompressed gRPC message bytes, from Tokio receiver yield to client decode.
    // This is a backlog proxy, not the actual capacity of tonic/h2/TCP buffers.
    framed_out: usize,
    framed_received: usize,
}

impl Retention {
    fn unread_framed_bytes(self) -> usize {
        self.framed_out - self.framed_received
    }
}

#[derive(Clone, Copy, Default)]
struct Stats {
    frames: usize,
    full: usize,
    at_full_send: bool,
    queue_max: usize,
    prep: Duration,
    wait: Duration,
    output_closed: bool,
    retained: Retention,
    first_send: Option<(Retention, usize)>,
}

// The profiled test uses a current-thread runtime, including its server tasks.
thread_local! {
    static PROBE: RefCell<[(Uuid, Stats); 2]> = RefCell::new([(Uuid::nil(), Stats::default()); 2]);
}

fn armed(user: Uuid) -> bool {
    PROBE.with_borrow(|slots| slots.iter().any(|(id, _)| *id == user))
}

fn update(user: Uuid, f: impl FnOnce(&mut Stats)) {
    PROBE.with_borrow_mut(|slots| {
        if let Some((_, stats)) = slots.iter_mut().find(|(id, _)| *id == user) {
            f(stats);
        }
    });
}

pub(crate) struct PageProbe(Uuid);

impl PageProbe {
    pub(crate) fn start(user: Uuid, page: &MailboxPage) -> Option<Self> {
        if !armed(user) {
            return None;
        }
        update(user, |s| {
            assert_eq!(s.retained.page, Stock::default());
            for env in page.entries.iter().filter_map(|(_, env)| env.as_ref()) {
                if let Some(bytes) = &env.sealed_inner {
                    s.retained.page.add(bytes.capacity());
                }
            }
        });
        Some(Self(user))
    }

    pub(crate) fn take(&self, env: Option<&MessageEnvelope>) -> FrameProbe {
        let started = Instant::now();
        if let Some(bytes) = env.and_then(|env| env.sealed_inner.as_ref()) {
            update(self.0, |s| s.retained.page.remove(bytes.capacity()));
        }
        FrameProbe {
            user: self.0,
            started,
        }
    }
}

impl Drop for PageProbe {
    fn drop(&mut self) {
        // Also runs if the send fails or poll_messages is cancelled mid-page.
        update(self.0, |s| s.retained.page = Stock::default());
    }
}

fn sealed_capacity(response: &proto::MessageStreamResponse) -> Option<usize> {
    match &response.response {
        Some(proto::message_stream_response::Response::Message(env)) => env
            .sealed_sender
            .as_ref()
            .map(|sealed| sealed.sealed_inner.capacity()),
        _ => None,
    }
}

pub(crate) struct FrameProbe {
    user: Uuid,
    started: Instant,
}

impl FrameProbe {
    pub(crate) fn before_send(
        self,
        capacity: usize,
        max: usize,
        response: &proto::MessageStreamResponse,
    ) -> SendProbe {
        let bytes = sealed_capacity(response).expect("profile sends only sealed mailbox frames");
        update(self.user, |s| {
            let occupied = max - capacity;
            // At the sampled stall, every occupied slot must hold a sealed frame; a queued
            // HeartbeatAck isn't included in the payload counters.
            s.frames += 1;
            s.prep += self.started.elapsed();
            s.queue_max = s.queue_max.max(occupied);
            s.at_full_send = capacity == 0;
            s.full += usize::from(s.at_full_send);
            assert_eq!(s.retained.pending_bytes, 0);
            s.retained.pending_bytes = bytes;
            if s.frames == 1 {
                s.first_send = Some((s.retained, AllocationSample::live_bytes()));
            }
        });
        SendProbe {
            user: self.user,
            started: Instant::now(),
            bytes,
        }
    }
}

pub(crate) struct SendProbe {
    user: Uuid,
    started: Instant,
    bytes: usize,
}

impl SendProbe {
    pub(crate) fn after_send(self, sent: bool) {
        if sent {
            // Current-thread fixture: no receiver code runs between send returning and this update.
            update(self.user, |s| s.retained.queue.add(self.bytes));
        }
    }
}

impl Drop for SendProbe {
    fn drop(&mut self) {
        update(self.user, |s| {
            s.wait += self.started.elapsed();
            s.at_full_send = false;
            s.retained.pending_bytes = 0;
        });
    }
}

pub(crate) struct OutputProbe(Uuid);

impl OutputProbe {
    pub(crate) fn start(user: Uuid) -> Option<Self> {
        armed(user).then(|| Self(user))
    }

    pub(crate) fn pulled(&self, item: &Result<proto::MessageStreamResponse, tonic::Status>) {
        if let Ok(frame) = item
            && let Some(bytes) = sealed_capacity(frame)
        {
            update(self.0, |s| {
                s.retained.queue.remove(bytes);
                s.retained.framed_out += frame.encoded_len() + 5;
            });
        }
    }
}

impl Drop for OutputProbe {
    fn drop(&mut self) {
        update(self.0, |s| {
            s.retained.queue = Stock::default();
            s.output_closed = true;
        });
    }
}

fn stats(user: Uuid) -> Stats {
    PROBE.with_borrow(|slots| {
        slots
            .iter()
            .find(|(id, _)| *id == user)
            .expect("armed user")
            .1
    })
}

fn authenticated<T>(
    body: T,
    bearer: &tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
) -> Request<T> {
    let mut request = Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", bearer.clone());
    request
}

struct Mailbox {
    user: Uuid,
    bearer: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    keys: [String; 2],
    presence: String,
}

impl Mailbox {
    async fn seed(ctx: &MessagingServiceContext, size: usize) -> Result<Self> {
        let user = Uuid::new_v4();
        let device = Uuid::new_v4().simple().to_string();
        let (token, _, _) = ctx
            .auth_manager
            .create_token_for_device(&user, Some(&device))?;
        let user_key = format!("{}:offline:{user}", ctx.config.delivery_queue_prefix);
        let keys = [user_key.clone(), format!("{user_key}:{device}")];
        let presence = format!(
            "{}{user}:server_instance_id",
            ctx.config.redis_key_prefixes.user
        );
        let mut conn = ctx.redis_conn.clone();
        for n in 0..COUNT {
            let message_id = format!("message-{n}");
            let envelope = MessageEnvelope::from_sealed_sender(
                message_id.clone(),
                user.to_string(),
                None,
                payload(size, n),
            );
            // Distinct envelopes in the two streams share an ID. Exercise reconnect between peers.
            let redis_id = format!("{}-0", n / 2 + 100);
            let observed: String = redis::cmd("XADD")
                .arg(&keys[n % 2])
                .arg(&redis_id)
                .arg("message_id")
                .arg(message_id)
                .arg("payload")
                .arg(rmp_serde::to_vec_named(&envelope)?)
                .query_async(&mut conn)
                .await?;
            assert_eq!(observed, redis_id);
        }
        Ok(Self {
            user,
            bearer: format!("Bearer {token}").parse()?,
            keys,
            presence,
        })
    }

    async fn clear(self, conn: &mut redis::aio::ConnectionManager) -> Result<()> {
        for key in &self.keys {
            let len: usize = redis::cmd("XLEN").arg(key).query_async(conn).await?;
            assert_eq!(len, COUNT / 2, "stream reads cannot trim the mailbox");
        }
        let removed: usize = redis::cmd("DEL")
            .arg(self.keys.as_slice())
            .query_async(conn)
            .await?;
        assert_eq!(removed, 2);
        Ok(())
    }
}

fn payload(size: usize, n: usize) -> Vec<u8> {
    let mut bytes = vec![0xa5; size];
    bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
    bytes
}

struct Stream {
    user: Uuid,
    requests: mpsc::Sender<proto::MessageStreamRequest>,
    response: Streaming<proto::MessageStreamResponse>,
    client: MessagingServiceClient<Channel>,
}

async fn client(endpoint: &Endpoint) -> Result<MessagingServiceClient<Channel>> {
    Ok(MessagingServiceClient::new(endpoint.connect().await?))
}

async fn open(endpoint: &Endpoint, mailbox: &Mailbox, cursor: String) -> Result<Stream> {
    let mut client = client(endpoint).await?;
    let (requests, rx) = mpsc::channel(1);
    requests
        .send(proto::MessageStreamRequest {
            request: Some(proto::message_stream_request::Request::Subscribe(
                proto::SubscribeRequest {
                    since_cursor: Some(cursor),
                    ..Default::default()
                },
            )),
            ..Default::default()
        })
        .await?;
    let response = client
        .message_stream(authenticated(ReceiverStream::new(rx), &mailbox.bearer))
        .await?
        .into_inner();
    Ok(Stream {
        user: mailbox.user,
        requests,
        response,
        client,
    })
}

async fn receive(stream: &mut Stream, expected: &[u8], n: usize) -> Result<String> {
    loop {
        let frame = stream
            .response
            .message()
            .await?
            .context("stream closed before delivery")?;
        let framed_size = frame.encoded_len() + 5;
        match frame.response {
            Some(proto::message_stream_response::Response::Message(env)) => {
                assert_eq!(
                    env.message_id_type,
                    Some(MessageIdType::MessageId(format!("message-{n}")))
                );
                assert!(env.sender.is_none() && env.encrypted_payload.is_empty());
                assert_eq!(
                    env.sealed_sender
                        .context("missing sealed sender")?
                        .sealed_inner,
                    expected
                );
                let cursor = frame.stream_cursor.context("no resume cursor")?;
                ensure!(
                    cursor.starts_with("mc1:"),
                    "expected source-specific cursor"
                );
                update(stream.user, |s| s.retained.framed_received += framed_size);
                return Ok(cursor);
            }
            Some(proto::message_stream_response::Response::HeartbeatAck(_)) => (),
            _ => anyhow::bail!("unexpected response frame"),
        }
    }
}

async fn drain(stream: &mut Stream, expected: &[Vec<u8>], start: usize) -> Result<()> {
    for (n, bytes) in expected.iter().enumerate().skip(start) {
        receive(stream, bytes, n).await?;
    }
    Ok(())
}

// Give both request EOF and cancellation a chance; check actual teardown, not a sleep.
async fn close(
    stream: Stream,
    ctx: &MessagingServiceContext,
    mailbox: &Mailbox,
    active: i64,
) -> Result<()> {
    drop(stream.requests);
    drop(stream.response);
    drop(stream.client);
    let mut conn = ctx.redis_conn.clone();
    tokio::time::timeout(DEADLINE, async {
        loop {
            let online: bool = redis::cmd("EXISTS")
                .arg(&mailbox.presence)
                .query_async(&mut conn)
                .await?;
            if !online
                && construct_metrics::GRPC_STREAMS_ACTIVE.get() == active
                && stats(mailbox.user).output_closed
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .context("stream or presence did not close")??;
    Ok(())
}

fn report(size: usize, slow: bool, phase: &str, s: Retention, live: usize) {
    println!(
        "mailbox_retention: size={size} slow={slow} phase={phase} queue_frames={} queue_bytes={} pending_bytes={} page_frames={} page_bytes={} unread_grpc_message_bytes={} process_live={live}",
        s.queue.frames,
        s.queue.bytes,
        s.pending_bytes,
        s.page.frames,
        s.page.bytes,
        s.unread_framed_bytes(),
    );
}

fn check_drained(s: Retention) {
    assert_eq!(s.queue, Stock::default());
    assert_eq!(s.page, Stock::default());
    assert_eq!(s.pending_bytes, 0);
    assert_eq!(s.unread_framed_bytes(), 0);
}

async fn sample(
    ctx: &MessagingServiceContext,
    endpoint: &Endpoint,
    boxes: &[Mailbox; 2],
    expected: &[Vec<u8>],
    slow: bool,
) -> Result<()> {
    let [a, b] = boxes;
    PROBE
        .with_borrow_mut(|slots| *slots = [(a.user, Stats::default()), (b.user, Stats::default())]);
    let idle_count = construct_metrics::GRPC_STREAMS_ACTIVE.get();
    let cpu = process_cpu_seconds()?;
    let wall = Instant::now();
    let idle_live = AllocationSample::live_bytes();
    let sample = AllocationSample::start();
    let (mut first, mut second) = tokio::try_join!(
        open(endpoint, a, "0-0".into()),
        open(endpoint, b, "0-0".into())
    )?;
    let checkpoint = receive(&mut second, &expected[0], 0).await?;
    tokio::try_join!(drain(&mut first, expected, 0), async {
        if slow {
            // After just one consumed frame, keep the receiver open but do not poll it.
            while !stats(b.user).at_full_send {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Ok(())
        } else {
            drain(&mut second, expected, 1).await
        }
    })?;
    let observed = [stats(a.user), stats(b.user)];
    assert_eq!(
        observed[0].frames, COUNT,
        "healthy predecessor stalled or replayed"
    );
    let size = expected[0].len();
    let [fast, second_reader] = observed.map(|s| s.retained);
    let (before, before_live) = observed[1]
        .first_send
        .context("missing first-send sample")?;
    assert_eq!(before.queue, Stock::default());
    assert_eq!(before.pending_bytes, size);
    assert_eq!(
        before.page.frames,
        STREAM_MAILBOX_PAGE - 1,
        "exclude the first converted frame"
    );
    assert_eq!(before.page.bytes, (STREAM_MAILBOX_PAGE - 1) * size);
    assert_eq!(before.unread_framed_bytes(), 0);
    check_drained(fast);
    if slow {
        assert!(observed[1].at_full_send && observed[1].full > 0);
        assert_eq!(
            second_reader.queue.frames, observed[1].queue_max,
            "count real channel yields"
        );
        assert_eq!(second_reader.queue.bytes, second_reader.queue.frames * size);
        assert_eq!(second_reader.pending_bytes, size);
        // In this fixture each page is full except the last (no filtered/duplicate rows).
        let page_end =
            (observed[1].frames.div_ceil(STREAM_MAILBOX_PAGE) * STREAM_MAILBOX_PAGE).min(COUNT);
        let remaining = page_end - observed[1].frames;
        assert!(remaining > 0, "fixture must block inside a page");
        assert_eq!(
            second_reader.page.frames, remaining,
            "count only the unread page tail"
        );
        assert_eq!(second_reader.page.bytes, remaining * size);
        assert!(
            second_reader.unread_framed_bytes() > size,
            "tonic took at least one unread frame"
        );
        assert!(
            observed[1].frames < COUNT,
            "fixture must exceed the transport and channel buffers"
        );
    } else {
        assert_eq!(observed[1].frames, COUNT);
        check_drained(second_reader);
    }
    let delta = sample.finish();
    let active = construct_metrics::GRPC_STREAMS_ACTIVE.get();
    assert_eq!(active, idle_count + 2);
    let cpu_ms = (process_cpu_seconds()? - cpu) * 1000.0;
    let wall_ms = wall.elapsed().as_secs_f64() * 1000.0;

    close(second, ctx, b, idle_count + 1).await?;
    let after_close = AllocationSample::live_bytes();
    let waited = stats(b.user);
    assert_eq!(waited.retained.queue, Stock::default());
    assert_eq!(waited.retained.page, Stock::default());
    assert_eq!(waited.retained.pending_bytes, 0);
    report(size, slow, "idle", Retention::default(), idle_live);
    report(size, slow, "first_send", before, before_live);
    report(
        size,
        slow,
        if slow { "blocked" } else { "drained" },
        second_reader,
        delta.live,
    );
    // Any unread framed bytes at cancellation were abandoned, not delivered or measured as freed.
    report(size, slow, "closed", waited.retained, after_close);
    let released = delta.live.saturating_sub(after_close);
    if slow && size == 65_536 {
        assert!(
            released >= 1024 * 1024,
            "closing the blocked reader did not release its queued data"
        );
    }
    close(first, ctx, a, idle_count).await?;
    if slow {
        let mut client = client(endpoint).await?;
        for limit in [0, 1] {
            let page = client
                .get_pending_messages(authenticated(
                    proto::GetPendingMessagesRequest {
                        since_cursor: Some(checkpoint.clone()),
                        limit: Some(limit),
                    },
                    &b.bearer,
                ))
                .await?
                .into_inner();
            assert_eq!(
                page.messages.len(),
                limit as usize,
                "strict pending limit with equal-ID peers"
            );
            assert!(page.has_more && page.gap.is_none());
            if let [message] = page.messages.as_slice() {
                assert_eq!(message.message_id, "message-1");
                assert_eq!(message.sealed_inner_data, expected[1]);
            }
        }
        drop(client);
        update(b.user, |s| *s = Stats::default());
        let mut reopened = open(endpoint, b, checkpoint).await?;
        drain(&mut reopened, expected, 1).await?;
        assert_eq!(stats(b.user).frames, COUNT - 1);
        check_drained(stats(b.user).retained);
        close(reopened, ctx, b, idle_count).await?;
    }
    println!(
        "mailbox_stream: size={size} slow={slow} prepared={}/{} queue_max={}/{} full_sends={}/{} prep_ms={:.3}/{:.3} send_ms={:.3}/{:.3} cpu_ms={cpu_ms:.2} wall_ms={wall_ms:.2} allocations={} requested_bytes={} peak_delta={} live_at_sample={} live_after_close={} released={released}",
        observed[0].frames,
        observed[1].frames,
        observed[0].queue_max,
        observed[1].queue_max,
        observed[0].full,
        observed[1].full,
        observed[0].prep.as_secs_f64() * 1000.0,
        observed[1].prep.as_secs_f64() * 1000.0,
        observed[0].wait.as_secs_f64() * 1000.0,
        waited.wait.as_secs_f64() * 1000.0,
        delta.calls,
        delta.bytes,
        delta.peak_delta,
        delta.live,
        after_close
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires local disposable Redis, run alone"]
async fn profile_local_mailbox_stream() -> Result<()> {
    ensure!(
        std::env::var("PROFILE_LOCAL_REDIS").as_deref() == Ok("1"),
        "use local disposable Redis only"
    );
    let redis_url = std::env::var("REDIS_URL").context("REDIS_URL required")?;
    let redis = redis::Client::open(redis_url.as_str())?;
    ensure!(
        matches!(redis.get_connection_info().addr(), redis::ConnectionAddr::Tcp(host, _) if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())),
        "Redis must be loopback TCP"
    );
    let (private, public) = make_ed25519_pems();
    let mut config = make_config(
        &redis_url,
        "postgres://127.0.0.1:1/unused",
        &private,
        &public,
        StealthTokenPolicy::Enforce,
    );
    config.delivery_queue_prefix = format!("profile:stream:{}", Uuid::new_v4());
    config.redis_key_prefixes.user = format!("{}:presence:", config.delivery_queue_prefix);
    // Authenticated reads must not require PostgreSQL. No DB connection is made by this fixture.
    let db = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy(&config.database_url)?;
    let queue = MessageQueue::new(&config).await?;
    let mut conn = construct_redis::connect_manager(&redis_url).await?;
    let ctx = Arc::new(MessagingServiceContext {
        db_pool: Arc::new(db),
        queue: Arc::new(Mutex::new(queue)),
        auth_manager: Arc::new(AuthManager::new(&config)?),
        notification_context: None,
        sentinel: None,
        server_signer: None,
        server_instance_id: config.delivery_queue_prefix.clone(),
        config: Arc::new(config),
        redis_conn: conn.clone(),
        token_issuer_key: None,
        token_enc_static_secret: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = Endpoint::from_shared(format!("http://{}", listener.local_addr()?))?
        .initial_stream_window_size(16 * 1024)
        .initial_connection_window_size(32 * 1024)
        .http2_adaptive_window(false);
    let mut task = tokio::task::JoinSet::new();
    let service = MessagingServiceServer::new(MessagingGrpcService {
        context: ctx.clone(),
    });
    task.spawn(
        construct_server_shared::grpc_server(45, 5)
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    for size in [1024, 65_536] {
        let boxes = [
            Mailbox::seed(&ctx, size).await?,
            Mailbox::seed(&ctx, size).await?,
        ];
        let expected: Vec<_> = (0..COUNT).map(|n| payload(size, n)).collect();
        for slow in [false, true] {
            tokio::time::timeout(
                DEADLINE * 3,
                sample(&ctx, &endpoint, &boxes, &expected, slow),
            )
            .await
            .context("mailbox stream sample stalled")??;
        }
        for mailbox in boxes {
            mailbox.clear(&mut conn).await?;
        }
    }
    Ok(())
}
