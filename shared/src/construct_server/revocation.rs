//! What a valid signature does not say: whether the device behind the token is still alive.
//!
//! A token is checked here against the store that knows: the `devices` row and, where the
//! service has Redis, the `invalidated_token:{jti}` blocklist. Why, and why messaging stays on its
//! own marker: construct-docs `decisions/a-token-is-worth-what-its-device-is-worth.md`.
//!
//! The layer never decides that a request is authenticated. A request without a token, or with one
//! that does not verify, goes on to its handler, which answers as it always did. The layer only
//! refuses a token that verifies and is no longer worth anything.

use std::sync::Arc;
use std::task::{Context, Poll};

use construct_auth::AuthManager;
use construct_db::DbPool;
use construct_metrics::AUTH_FAILURES_TOTAL;
use redis::aio::ConnectionManager;
use tonic::Status;
use tonic::codegen::{BoxFuture, Service, http};
use tonic::transport::Server;
use tower::Layer;
use tower::layer::util::{Identity, Stack};

/// What a token that verifies is still worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    Good,
    /// Its device is gone or inactive, or the token itself was invalidated.
    Revoked,
    /// A store that would know could not be asked.
    Unknown,
}

impl Standing {
    /// `Err` with the status to answer, counted, or `Ok` for a token still good.
    ///
    /// `UNAUTHENTICATED` carries no `construct-device-refusal` on purpose: the client goes to
    /// refresh, and the one signal that erases a device stays where it was, in identity
    /// (`decisions/sign-out-wipes-the-device.md`). `UNAVAILABLE` makes it retry and leaves its
    /// token alone: a store's outage says nothing about the token.
    pub fn into_result(self) -> Result<(), Status> {
        match self {
            Standing::Good => Ok(()),
            Standing::Revoked => {
                AUTH_FAILURES_TOTAL
                    .with_label_values(&["token_revoked"])
                    .inc();
                Err(Status::unauthenticated("Invalid or expired token"))
            }
            Standing::Unknown => {
                AUTH_FAILURES_TOTAL
                    .with_label_values(&["revocation_unavailable"])
                    .inc();
                Err(Status::unavailable("Cannot verify token"))
            }
        }
    }
}

/// The decision, from what the stores answered (`Err` = could not be asked).
///
/// `device_active` is the device's row: `None` when there is none. Any store saying revoked wins
/// over the other being down: the client should act on what is known.
fn decide(invalidated: Result<bool, ()>, device_active: Result<Option<bool>, ()>) -> Standing {
    if matches!(invalidated, Ok(true)) || matches!(device_active, Ok(None) | Ok(Some(false))) {
        return Standing::Revoked;
    }
    if invalidated.is_err() || device_active.is_err() {
        return Standing::Unknown;
    }
    Standing::Good
}

/// The stores a service can ask. Cheap to clone: both hold shared handles.
#[derive(Clone)]
pub struct RevocationCheck {
    db: Option<Arc<DbPool>>,
    blocklist: Option<ConnectionManager>,
}

impl RevocationCheck {
    /// `db` is `None` only where a service can boot without one (signaling): every token is then
    /// `Unknown`, closed rather than taken on trust. `blocklist` is `None` for the services that
    /// are given no Redis (media, veil), which therefore do not see an invalidated token whose
    /// device is still active.
    pub fn new(db: impl Into<Option<Arc<DbPool>>>, blocklist: Option<ConnectionManager>) -> Self {
        Self {
            db: db.into(),
            blocklist,
        }
    }

    /// `device` is `None` for a token that names none: there is no row to ask about.
    pub async fn standing(&self, jti: &str, device: Option<&str>) -> Standing {
        let invalidated = match self.blocklist.clone() {
            None => Ok(false),
            Some(mut conn) => redis::cmd("EXISTS")
                .arg(construct_queue::invalidated_token_key(jti))
                .query_async::<bool>(&mut conn)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "Token blocklist check failed — closing");
                }),
        };
        let device_active = match (device, self.db.as_deref()) {
            (None, _) => Ok(Some(true)),
            (Some(_), None) => Err(()),
            (Some(id), Some(db)) => construct_db::device_is_active(db, id).await.map_err(|e| {
                tracing::warn!(error = %e, "Device check failed — closing");
            }),
        };
        decide(invalidated, device_active)
    }
}

/// Refuses a token that verifies but is no longer worth anything, before any handler runs.
#[derive(Clone)]
pub struct RevocationLayer {
    auth: Option<Arc<AuthManager>>,
    check: RevocationCheck,
    open_methods: &'static [&'static str],
}

impl RevocationLayer {
    /// `auth` is `None` only where a service can boot without verify keys (signaling): no token
    /// verifies then, and its handlers refuse every call themselves.
    pub fn new(auth: impl Into<Option<Arc<AuthManager>>>, check: RevocationCheck) -> Self {
        Self {
            auth: auth.into(),
            check,
            open_methods: &[],
        }
    }

    /// RPCs, by method name, that never read the bearer and must answer whatever it says. A
    /// client attaching a dead token to `RefreshToken` must still get the refusal that tells it
    /// the device was removed, and to `RecoverAccount` must still recover.
    pub fn with_open_methods(mut self, methods: &'static [&'static str]) -> Self {
        self.open_methods = methods;
        self
    }
}

impl<S> Layer<S> for RevocationLayer {
    type Service = RevocationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RevocationService {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RevocationService<S> {
    inner: S,
    layer: RevocationLayer,
}

impl<S> RevocationService<S> {
    /// The token to ask about: `None` when this layer has nothing to say about the request.
    fn claims_to_check<B>(&self, request: &http::Request<B>) -> Option<construct_auth::Claims> {
        let method = request.uri().path().rsplit('/').next().unwrap_or_default();
        if self.layer.open_methods.contains(&method) {
            return None;
        }
        let token = request
            .headers()
            .get("authorization")?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?
            .trim();
        self.layer.auth.as_ref()?.verify_token(token).ok()
    }
}

impl<S, B, R> Service<http::Request<B>> for RevocationService<S>
where
    S: Service<http::Request<B>, Response = http::Response<R>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
    R: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        // The clone is the one not yet polled ready: the ready one goes into the future.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let claims = self.claims_to_check(&request);
        let check = self.layer.check.clone();
        Box::pin(async move {
            if let Some(claims) = claims {
                let standing = check
                    .standing(&claims.jti, claims.device_id.as_deref())
                    .await;
                if let Err(status) = standing.into_result() {
                    return Ok(status.into_http());
                }
            }
            inner.call(request).await
        })
    }
}

/// The server every service builds, except messaging: nothing mounted on it can skip the check.
///
/// Messaging builds on [`crate::grpc_server`] alone, checks in `extract_authed_identity` against
/// the `revoked_device:` marker, and must not depend on Postgres to deliver. A test in this module
/// holds that it is the only one.
pub fn guarded_grpc_server(
    keepalive_interval_secs: u64,
    keepalive_timeout_secs: u64,
    layer: RevocationLayer,
) -> Server<Stack<RevocationLayer, Identity>> {
    crate::grpc_server(keepalive_interval_secs, keepalive_timeout_secs).layer(layer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tonic::Code;
    use uuid::Uuid;

    #[test]
    fn the_decision_table() {
        use Standing::*;
        let fine = Ok(Some(true));
        for (invalidated, device, expected, why) in [
            (Ok(false), fine, Good, "both stores vouch"),
            (Ok(true), fine, Revoked, "signed out: the row stays active"),
            (
                Ok(false),
                Ok(Some(false)),
                Revoked,
                "the device was revoked",
            ),
            (Ok(false), Ok(None), Revoked, "no such device any more"),
            (Err(()), fine, Unknown, "the blocklist is down"),
            (Ok(false), Err(()), Unknown, "the database is down"),
            (Err(()), Err(()), Unknown, "both are down"),
            (
                Err(()),
                Ok(Some(false)),
                Revoked,
                "known revoked beats down",
            ),
            (Err(()), Ok(None), Revoked, "known missing beats down"),
            (Ok(true), Err(()), Revoked, "known invalidated beats down"),
        ] {
            assert_eq!(decide(invalidated, device), expected, "{why}");
        }
    }

    #[test]
    fn a_revoked_token_is_told_to_refresh_and_an_outage_to_retry() {
        assert!(Standing::Good.into_result().is_ok());

        let revoked = Standing::Revoked.into_result().unwrap_err();
        assert_eq!(revoked.code(), Code::Unauthenticated);
        assert_eq!(revoked.message(), "Invalid or expired token");
        assert!(
            revoked
                .metadata()
                .get(construct_error::DeviceRefusal::METADATA_KEY)
                .is_none(),
            "this layer must not become a second way to erase a device"
        );

        let unknown = Standing::Unknown.into_result().unwrap_err();
        assert_eq!(unknown.code(), Code::Unavailable);
        assert!(
            unknown
                .metadata()
                .get(construct_error::DeviceRefusal::METADATA_KEY)
                .is_none()
        );
    }

    /// The service mains build through the guarded server; only messaging does not. This is what
    /// stands in for a live call per service: forgetting the layer is the failure it would catch.
    #[test]
    fn only_messaging_builds_a_server_without_the_check() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let read = |service: &str| {
            std::fs::read_to_string(root.join(service).join("src/main.rs"))
                .unwrap_or_else(|e| panic!("{service}: {e}"))
        };
        let plain = "construct_server_shared::grpc_server(";
        let guarded = "construct_server_shared::revocation::guarded_grpc_server(";
        for service in [
            "identity-service",
            "key-service",
            "group-service",
            "signaling-service",
            "media-service",
            "veil-service",
        ] {
            let source = read(service);
            assert!(source.contains(guarded), "{service} skips the check");
            assert!(!source.contains(plain), "{service} builds a bare server");
        }
        assert!(read("messaging-service").contains(plain));

        // A service added later has to choose. Every directory with a gRPC server is listed above.
        let mut unlisted = Vec::new();
        for entry in std::fs::read_dir(&root).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            let main = root.join(&name).join("src/main.rs");
            if name == "messaging-service" || !main.exists() {
                continue;
            }
            let source = std::fs::read_to_string(main).unwrap();
            if source.contains(plain) {
                unlisted.push(name);
            }
        }
        assert!(unlisted.is_empty(), "bare gRPC servers: {unlisted:?}");
    }

    // ── against real stores ──────────────────────────────────────────────────

    struct Stand {
        db: Arc<DbPool>,
        redis: ConnectionManager,
        auth: Arc<AuthManager>,
        user: Uuid,
        device: String,
    }

    impl Stand {
        async fn new() -> Self {
            let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
            let db = Arc::new(sqlx::PgPool::connect(&url).await.expect("Postgres"));
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
            let client = redis::Client::open(redis_url).expect("Redis url");
            let redis = construct_redis::manager_for(client).await.expect("Redis");
            let user: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
                .fetch_one(db.as_ref())
                .await
                .unwrap();
            let device = Uuid::new_v4().simple().to_string();
            construct_db::create_device(
                db.as_ref(),
                construct_db::CreateDeviceData {
                    device_id: device.clone(),
                    server_hostname: "test.local".into(),
                    verifying_key: random_bytes(),
                    identity_public: random_bytes(),
                    signed_prekey_public: random_bytes(),
                    signed_prekey_signature: [random_bytes(), random_bytes()].concat(),
                    crypto_suites: "[\"Curve25519+Ed25519\"]".into(),
                    supports_pq_ratchet: false,
                },
                Some(user),
            )
            .await
            .unwrap();
            Self {
                db,
                redis,
                auth: Arc::new(crate::auth_utils::tests::make_test_auth()),
                user,
                device,
            }
        }

        fn layer(&self) -> RevocationLayer {
            RevocationLayer::new(
                self.auth.clone(),
                RevocationCheck::new(self.db.clone(), Some(self.redis.clone())),
            )
        }

        fn token(&self) -> (String, String) {
            let (token, jti, _) = self
                .auth
                .create_token_for_device(&self.user, Some(&self.device))
                .unwrap();
            (token, jti)
        }

        async fn deactivate(&self) {
            sqlx::query("UPDATE devices SET is_active = FALSE WHERE device_id = $1")
                .bind(&self.device)
                .execute(self.db.as_ref())
                .await
                .unwrap();
        }

        async fn cleanup(self) {
            let _ = sqlx::query("DELETE FROM devices WHERE device_id = $1")
                .bind(&self.device)
                .execute(self.db.as_ref())
                .await;
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(self.user)
                .execute(self.db.as_ref())
                .await;
        }
    }

    fn random_bytes() -> Vec<u8> {
        [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()].concat()
    }

    /// A handler that only counts: the question is whether the request reached it.
    #[derive(Clone, Default)]
    struct Handler(Arc<AtomicUsize>);

    impl Service<http::Request<()>> for Handler {
        type Response = http::Response<()>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: http::Request<()>) -> Self::Future {
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(http::Response::new(())))
        }
    }

    /// `(reached the handler, the status the layer answered)`.
    async fn send(
        layer: &RevocationLayer,
        method: &str,
        token: Option<&str>,
    ) -> (bool, Option<String>) {
        let handler = Handler::default();
        let mut service = layer.layer(handler.clone());
        let mut request = http::Request::builder().uri(format!("/pkg.Svc/{method}"));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = service.call(request.body(()).unwrap()).await.unwrap();
        let status = response
            .headers()
            .get("grpc-status")
            .map(|v| v.to_str().unwrap().to_string());
        (handler.0.load(Ordering::SeqCst) == 1, status)
    }

    const UNAUTHENTICATED: &str = "16";
    const UNAVAILABLE: &str = "14";

    #[tokio::test]
    #[ignore = "requires Redis and migrated PostgreSQL"]
    async fn a_live_device_passes_and_a_deactivated_one_never_reaches_the_handler() {
        let stand = Stand::new().await;
        let layer = stand.layer();
        let (token, _) = stand.token();

        assert_eq!(send(&layer, "Any", Some(&token)).await, (true, None));

        stand.deactivate().await;
        assert_eq!(
            send(&layer, "Any", Some(&token)).await,
            (false, Some(UNAUTHENTICATED.into()))
        );
        stand.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires Redis and migrated PostgreSQL"]
    async fn a_device_with_no_row_is_refused() {
        let stand = Stand::new().await;
        let layer = stand.layer();
        let (token, _, _) = stand
            .auth
            .create_token_for_device(&stand.user, Some("no-such-device"))
            .unwrap();
        assert_eq!(
            send(&layer, "Any", Some(&token)).await,
            (false, Some(UNAUTHENTICATED.into()))
        );
        stand.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires Redis and migrated PostgreSQL"]
    async fn a_signed_out_token_is_refused_while_its_device_stays_active() {
        let stand = Stand::new().await;
        let layer = stand.layer();
        let (token, jti) = stand.token();
        let (sibling, _) = stand.token();

        let key = construct_queue::invalidated_token_key(&jti);
        let mut redis = stand.redis.clone();
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(60)
            .query_async(&mut redis)
            .await
            .unwrap();

        assert_eq!(
            send(&layer, "Any", Some(&token)).await,
            (false, Some(UNAUTHENTICATED.into()))
        );
        assert_eq!(
            send(&layer, "Any", Some(&sibling)).await,
            (true, None),
            "another token of the same device was not signed out"
        );
        let _: i64 = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut redis)
            .await
            .unwrap();
        stand.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires Redis and migrated PostgreSQL"]
    async fn the_layer_has_nothing_to_say_about_what_it_cannot_verify_or_was_told_to_leave() {
        let stand = Stand::new().await;
        let layer = stand.layer();
        let (token, _) = stand.token();
        stand.deactivate().await;

        assert_eq!(send(&layer, "Any", None).await, (true, None), "no token");
        assert_eq!(
            send(&layer, "Any", Some("v4.public.garbage")).await,
            (true, None),
            "the handler refuses a bad token, in its own words"
        );
        assert_eq!(
            send(
                &stand.layer().with_open_methods(&["RefreshToken"]),
                "RefreshToken",
                Some(&token)
            )
            .await,
            (true, None),
            "a dead token must not close the door that tells the client so"
        );
        assert_eq!(
            send(
                &stand.layer().with_open_methods(&["RefreshToken"]),
                "Other",
                Some(&token)
            )
            .await,
            (false, Some(UNAUTHENTICATED.into())),
            "open means that method, not every method"
        );
        stand.cleanup().await;
    }

    #[tokio::test]
    #[ignore = "requires Redis and migrated PostgreSQL"]
    async fn a_store_that_cannot_answer_closes_with_unavailable() {
        let stand = Stand::new().await;
        let (token, _) = stand.token();

        // The database down.
        let closed = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
            .unwrap();
        let layer = RevocationLayer::new(
            stand.auth.clone(),
            RevocationCheck::new(Arc::new(closed), Some(stand.redis.clone())),
        );
        assert_eq!(
            send(&layer, "Any", Some(&token)).await,
            (false, Some(UNAVAILABLE.into()))
        );

        // No database configured (signaling can boot so).
        let layer = RevocationLayer::new(stand.auth.clone(), RevocationCheck::new(None, None));
        assert_eq!(
            send(&layer, "Any", Some(&token)).await,
            (false, Some(UNAVAILABLE.into()))
        );

        // No blocklist given: the services without Redis still answer from the row.
        let layer = RevocationLayer::new(
            stand.auth.clone(),
            RevocationCheck::new(stand.db.clone(), None),
        );
        assert_eq!(send(&layer, "Any", Some(&token)).await, (true, None));
        stand.cleanup().await;
    }

    /// Speaks just enough RESP to connect, then answers every `EXISTS` with an error.
    async fn redis_that_fails_its_reads() -> ConnectionManager {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    while let Ok(n) = socket.read(&mut buffer).await {
                        if n == 0 {
                            return;
                        }
                        let received = String::from_utf8_lossy(&buffer[..n]);
                        for command in received.split('*').skip(1) {
                            let reply: &[u8] = if command.contains("EXISTS") {
                                b"-ERR boom\r\n"
                            } else {
                                b"+OK\r\n"
                            };
                            socket.write_all(reply).await.unwrap();
                        }
                    }
                });
            }
        });
        let client = redis::Client::open(format!("redis://127.0.0.1:{port}")).unwrap();
        construct_redis::manager_for(client).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "requires Redis and migrated PostgreSQL"]
    async fn a_blocklist_that_errors_closes_with_unavailable() {
        let stand = Stand::new().await;
        let (token, _) = stand.token();
        let layer = RevocationLayer::new(
            stand.auth.clone(),
            RevocationCheck::new(stand.db.clone(), Some(redis_that_fails_its_reads().await)),
        );
        assert_eq!(
            send(&layer, "Any", Some(&token)).await,
            (false, Some(UNAVAILABLE.into()))
        );
        stand.cleanup().await;
    }
}
