//! Sealed-sender server matrix — Phase 1 (unit + Redis/Postgres integration).
//!
//! Run against local data plane:
//! ```text
//! docker-compose -f ops/docker-compose.dev.yml up -d
//! cargo test -p messaging-service sealed_matrix -- --nocapture
//! ```
//!
//! Tests skip when Redis/Postgres are unavailable on a laptop; under CI a missing service
//! fails them (`service_absent`).
//! See `AUDIT-SEALED-MESSAGING.md` § Test matrix.

use std::sync::Arc;

use construct_auth::AuthManager;
use construct_config::{
    ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
    DeepLinksConfig, FederationConfig, LoggingConfig, MediaConfig, MessagingConfig,
    MicroservicesConfig, MtlsConfig, RedisChannels, RedisKeyPrefixes, SecurityConfig,
    StealthTokenPolicy,
};
use construct_db::DbPool;
use construct_queue::MessageQueue;
use construct_server_shared::shared::proto::core::v1 as core_proto;
use construct_server_shared::shared::proto::services::v1::IntakeVerdict;
use prost::Message;
use serial_test::serial;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::context::MessagingServiceContext;
use crate::envelope::{TokenRejected, dispatch_sealed_sender};
use crate::token_redeem::{TokenRedeemResult, redeem_token_checked};

// ── Env defaults matching ops/docker-compose.dev.yml ─────────────────────────

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn database_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:password@127.0.0.1:5432/construct_test".to_string()
    })
}

/// A missing service skips the test on a laptop and fails it under CI (`CI` is set by
/// GitHub Actions): a run that has the services and still skips proves nothing.
fn service_absent(what: &str, error: impl std::fmt::Display) {
    assert!(
        std::env::var_os("CI").is_none(),
        "sealed_matrix: {what} is required under CI: {error}"
    );
    eprintln!("sealed_matrix: {what} unavailable ({error}) — skipping");
}

async fn try_redis() -> Option<redis::aio::ConnectionManager> {
    let client = redis::Client::open(redis_url()).ok()?;
    match construct_redis::manager_for(client).await {
        Ok(conn) => Some(conn),
        Err(e) => {
            service_absent(&format!("redis at {}", redis_url()), e);
            None
        }
    }
}

async fn try_db_pool() -> Option<Arc<DbPool>> {
    match DbPool::connect(&database_url()).await {
        Ok(pool) => {
            // Best-effort migrations so device lookup exists.
            // Failure is non-fatal: sealed path degrades device fan-out to user stream.
            let _ = sqlx::migrate!("../shared/migrations").run(&pool).await;
            Some(Arc::new(pool))
        }
        Err(e) => {
            service_absent("postgres", e);
            None
        }
    }
}

fn make_ed25519_pems() -> (String, String) {
    use ed25519_compact::KeyPair;
    let kp = KeyPair::generate();
    (
        String::from_utf8(kp.sk.to_pem().as_bytes().to_vec()).expect("priv pem"),
        String::from_utf8(kp.pk.to_pem().as_bytes().to_vec()).expect("pub pem"),
    )
}

fn make_config(
    redis: &str,
    database: &str,
    paseto_priv: &str,
    paseto_pub: &str,
    policy: StealthTokenPolicy,
) -> Config {
    let messaging = MessagingConfig {
        stealth_token_policy: policy,
        ..MessagingConfig::default()
    };

    Config {
        database_url: database.to_string(),
        redis_url: redis.to_string(),
        paseto_private_key: Some(paseto_priv.to_string()),
        paseto_public_key: Some(paseto_pub.to_string()),
        paseto_public_key_previous: Vec::new(),
        port: 50053,
        bind_address: "127.0.0.1".to_string(),
        health_port: 8081,
        heartbeat_interval_secs: 60,
        server_registry_ttl_secs: 120,
        dedup_safety_margin_hours: 2,
        access_token_ttl_hours: 24,
        session_ttl_days: 30,
        refresh_token_ttl_days: 7,
        token_issuer: "construct-test".to_string(),
        online_channel: "online".to_string(),
        offline_queue_prefix: "queue:".to_string(),
        delivery_queue_prefix: "delivery".to_string(),
        delivery_poll_interval_ms: 100,
        grpc_keepalive_interval_secs: 45,
        grpc_keepalive_timeout_secs: 5,
        rust_log: "error".to_string(),
        logging: LoggingConfig {
            enable_message_metadata: false,
            enable_user_identifiers: false,
            hash_salt: "sealed-matrix-test-salt".to_string(),
        },
        security: SecurityConfig {
            prekey_ttl_days: 30,
            prekey_min_ttl_days: 7,
            prekey_max_ttl_days: 90,
            max_messages_per_hour: 1000,
            max_messages_per_ip_per_hour: 5000,
            max_key_rotations_per_day: 10,
            max_password_changes_per_day: 5,
            max_failed_login_attempts: 5,
            max_connections_per_user: 5,
            key_bundle_cache_hours: 1,
            rate_limit_block_duration_seconds: 3600,
            ip_rate_limiting_enabled: false,
            max_requests_per_ip_per_hour: 1000,
            combined_rate_limiting_enabled: false,
            max_requests_per_user_ip_per_hour: 500,
            max_long_poll_requests_per_window: 100,
            long_poll_rate_limit_window_secs: 60,
            request_signing_required: false,
            metrics_auth_enabled: false,
            metrics_ip_whitelist: vec![],
            metrics_bearer_token: None,
            max_pow_challenges_per_hour: 5,
            max_registrations_per_hour: 3,
            pow_difficulty: 1,
            username_hmac_secret: vec![0u8; 32],
            contact_hmac_secret: vec![0u8; 32],
            request_envelope_key: vec![0u8; 32],
        },
        apns: ApnsConfig {
            enabled: false,
            environment: ApnsEnvironment::Development,
            key_path: String::new(),
            key_id: String::new(),
            team_id: String::new(),
            bundle_id: String::new(),
            topic: String::new(),
            voip_topic: None,
            device_token_encryption_key: "0".repeat(64),
        },
        federation: FederationConfig {
            enabled: false,
            instance_domain: "test.local".to_string(),
            base_domain: "test.local".to_string(),
            signing_key_seed: None,
            max_requests_per_origin_per_hour: 1000,
            mtls: MtlsConfig {
                required: false,
                client_cert_path: None,
                client_key_path: None,
                verify_server_cert: false,
                pinned_certs: std::collections::HashMap::new(),
            },
        },
        db: DbConfig {
            max_connections: 2,
            min_connections: 0,
            acquire_timeout_secs: 5,
            idle_timeout_secs: 60,
        },
        deeplinks: DeepLinksConfig {
            apple_team_id: String::new(),
            android_package_name: String::new(),
            android_cert_fingerprint: String::new(),
        },
        redis_key_prefixes: RedisKeyPrefixes {
            processed_msg: "processed_msg:".to_string(),
            user: "user:".to_string(),
            session: "session:".to_string(),
            user_sessions: "user_sessions:".to_string(),
            msg_hash: "msg_hash:".to_string(),
            rate: "rate:".to_string(),
            blocked: "blocked:".to_string(),
            key_bundle: "key_bundle:".to_string(),
            connections: "connections:".to_string(),
        },
        redis_channels: RedisChannels {
            dead_letter_queue: "dlq".to_string(),
            delivery_message: "delivery_message:{}".to_string(),
            delivery_notification: "delivery_notification:{}".to_string(),
        },
        media: MediaConfig {
            enabled: false,
            base_url: String::new(),
            upload_token_secret: String::new(),
            max_file_size: 10 * 1024 * 1024,
            rate_limit_per_hour: 100,
        },
        csrf: CsrfConfig {
            enabled: false,
            secret: "test-csrf-secret-at-least-32-chars!!".to_string(),
            token_ttl_secs: 3600,
            allowed_origins: vec![],
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
        },
        messaging,
        microservices: MicroservicesConfig {
            enabled: false,
            auth_service_url: "http://localhost:8001".to_string(),
            messaging_service_url: "http://localhost:8002".to_string(),
            user_service_url: "http://localhost:8003".to_string(),
            notification_service_url: "http://localhost:8004".to_string(),
            discovery_mode: "static".to_string(),
            service_timeout_secs: 30,
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 2,
                timeout_secs: 60,
            },
        },
        instance_domain: "test.local".to_string(),
        federation_base_domain: "test.local".to_string(),
        federation_enabled: false,
        deep_link_base_url: String::new(),
        veil_enabled: false,
        veil_port: 9443,
        veil_server_key: None,
        veil_iat_mode: 0,
        veil_upstream: "envoy:8080".to_string(),
        veil_tls_cert_path: None,
        veil_tls_key_path: None,
        veil_cover_upstream: None,
        veil_relay_addresses: vec![],
    }
}

struct TestHarness {
    ctx: Arc<MessagingServiceContext>,
    token_issuer_key: [u8; 32],
    token_enc_secret: X25519StaticSecret,
}

async fn build_harness(policy: StealthTokenPolicy) -> Option<TestHarness> {
    build_harness_on(policy, &redis_url(), &redis_url()).await
}

/// `queue_redis` carries the mailbox and the auth blocklist (`MessageQueue`); `abuse_redis` the
/// standalone connection the sealed path keeps its anti-abuse state on — delivery tags, intake
/// tags, spent tokens. Two addresses so a test can take one down and keep the other.
async fn build_harness_on(
    policy: StealthTokenPolicy,
    queue_redis: &str,
    abuse_redis: &str,
) -> Option<TestHarness> {
    try_redis().await?;
    let db_pool = try_db_pool().await?;

    let (priv_pem, pub_pem) = make_ed25519_pems();
    let config = Arc::new(make_config(
        queue_redis,
        &database_url(),
        &priv_pem,
        &pub_pem,
        policy,
    ));

    let message_queue = MessageQueue::new(&config)
        .await
        .expect("MessageQueue::new with live redis");
    let abuse_conn =
        construct_redis::manager_for(redis::Client::open(abuse_redis).expect("abuse redis url"))
            .await
            .expect("abuse redis");
    let queue = Arc::new(Mutex::new(message_queue));

    let auth_manager = Arc::new(AuthManager::new(&config).expect("AuthManager"));

    let mut token_issuer_key = [0u8; 32];
    rand::RngExt::fill(&mut rand::rng(), &mut token_issuer_key);
    let mut enc_seed = [0u8; 32];
    rand::RngExt::fill(&mut rand::rng(), &mut enc_seed);
    let token_enc_secret = X25519StaticSecret::from(enc_seed);

    let ctx = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        notification_context: None,
        sentinel: None,
        config,
        server_signer: None,
        server_instance_id: format!("sealed-matrix-{}", uuid::Uuid::new_v4()),
        redis_conn: abuse_conn,
        token_issuer_key: Some(token_issuer_key),
        token_enc_static_secret: Some(token_enc_secret.clone()),
    });

    Some(TestHarness {
        ctx,
        token_issuer_key,
        token_enc_secret,
    })
}

fn random_bytes32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::RngExt::fill(&mut rand::rng(), &mut b);
    b
}

fn issue_client_token(token_issuer_key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use hkdf::Hkdf;
    use sha2_dalek_compat::{Digest as _, Sha512};

    let k = Scalar::from_bytes_mod_order(*token_issuer_key);
    let mut h = Sha512::new();
    h.update(nonce);
    let t = RistrettoPoint::from_hash(h);
    let r = Scalar::from_bytes_mod_order(random_bytes32());
    let blinded = r * t;
    let z = k * blinded;
    let n = r.invert() * z;
    let n_bytes = n.compress().to_bytes();
    let ikm: Vec<u8> = n_bytes.iter().chain(nonce.iter()).copied().collect();
    let hk = Hkdf::<sha2::Sha512>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"ConstructPP-v1", &mut out).unwrap();
    out
}

fn seal_token_for_server(token: &[u8], server_secret: &X25519StaticSecret) -> Vec<u8> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    use hkdf::Hkdf;
    use sha2::Sha256;

    let server_pub = X25519PublicKey::from(server_secret);
    let ephemeral_secret = X25519StaticSecret::from(random_bytes32());
    let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(b"construct-token-seal-v1", &mut sym_key).unwrap();

    let cipher = ChaCha20Poly1305::new(&Key::from(sym_key));
    let nonce_bytes = random_bytes32();
    let aead_nonce = Nonce::try_from(&nonce_bytes[..12]).expect("12-byte nonce");
    let ciphertext = cipher.encrypt(&aead_nonce, token).unwrap();

    let mut sealed = Vec::with_capacity(32 + 12 + ciphertext.len());
    sealed.extend_from_slice(ephemeral_pub.as_bytes());
    sealed.extend_from_slice(&nonce_bytes[..12]);
    sealed.extend_from_slice(&ciphertext);
    sealed
}

/// A local sealed envelope whose recipient is named by `address` (a UUID or `ed25519:<hex>`).
fn build_sealed_envelope_to(
    address: &str,
    delivery_tag: &[u8],
) -> core_proto::SealedSenderEnvelope {
    let inner = core_proto::SealedInner {
        recipient_user_id: address.to_string(),
        delivery_tag: delivery_tag.to_vec(),
        sender_cert_ciphertext: vec![0u8; 48],
        encrypted_payload: b"fake-e2ee-payload".to_vec(),
        ..core_proto::SealedInner::default()
    };
    core_proto::SealedSenderEnvelope {
        recipient_server: String::new(),
        sealed_inner: inner.encode_to_vec(),
        forwarding_token: vec![],
        timestamp: chrono::Utc::now().timestamp_millis(),
    }
}

fn build_sealed_envelope(
    recipient: &uuid::Uuid,
    delivery_tag: &[u8],
    token_nonce: Option<&[u8]>,
    token_bytes: Option<&[u8]>,
) -> core_proto::SealedSenderEnvelope {
    // content_type / priority / ttl left at proto defaults (deprecated server-visible fields)
    let inner = core_proto::SealedInner {
        recipient_user_id: recipient.to_string(),
        delivery_tag: delivery_tag.to_vec(),
        sender_cert_ciphertext: vec![0u8; 48], // opaque to server
        encrypted_payload: b"fake-e2ee-payload".to_vec(),
        token_nonce: token_nonce.map(|n| n.to_vec()).unwrap_or_default(),
        token_bytes: token_bytes.map(|b| b.to_vec()).unwrap_or_default(),
        ..core_proto::SealedInner::default()
    };

    core_proto::SealedSenderEnvelope {
        recipient_server: String::new(), // local
        sealed_inner: inner.encode_to_vec(),
        forwarding_token: vec![],
        timestamp: chrono::Utc::now().timestamp_millis(),
    }
}

async fn stream_len(conn: &mut redis::aio::ConnectionManager, recipient: &uuid::Uuid) -> i64 {
    let key = format!("delivery:offline:{recipient}");
    redis::cmd("XLEN")
        .arg(&key)
        .query_async::<i64>(conn)
        .await
        .unwrap_or(0)
}

async fn receipt_sender_exists(conn: &mut redis::aio::ConnectionManager, message_id: &str) -> bool {
    let key = format!("receipt:sender:{message_id}");
    let n: i64 = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(conn)
        .await
        .unwrap_or(0);
    n > 0
}

// ── K1/K2: an account addressed by its key (decisions/pubkey-as-identity.md) ─

/// An account that set its recovery key before the address was written with it — the state every
/// production account was in — becomes reachable by `ed25519:<recovery key>` once the backfill
/// runs, and the sealed envelope lands in that account's mailbox.
#[tokio::test]
#[serial]
async fn k1_a_key_address_reaches_the_account_after_the_backfill() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let db = &h.ctx.db_pool;
    let recovery_key = random_bytes32();
    // Set the old way: the key alone, no address.
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (id, recovery_public_key) VALUES (gen_random_uuid(), $1) RETURNING id",
    )
    .bind(recovery_key.as_slice())
    .fetch_one(&**db)
    .await
    .expect("create an account with a recovery key");

    assert!(construct_db::backfill_account_addresses(db).await.unwrap() >= 1);
    assert_eq!(
        construct_db::backfill_account_addresses(db).await.unwrap(),
        0,
        "the backfill is idempotent"
    );

    let address = format!("ed25519:{}", hex::encode(recovery_key));
    let mut conn = h.ctx.redis_conn.clone();
    let before = stream_len(&mut conn, &user_id).await;
    let resp = dispatch_sealed_sender(
        &h.ctx,
        &build_sealed_envelope_to(&address, &random_bytes32()),
    )
    .await
    .expect("a key address of an account here delivers");
    assert!(resp.success);
    // The envelope carries no intake tag; K2 must read the same for an address with no account.
    assert_eq!(resp.intake_verdict, IntakeVerdict::None as i32);
    assert!(
        stream_len(&mut conn, &user_id).await > before,
        "delivered to the account the key names"
    );

    let _: () = redis::cmd("DEL")
        .arg(format!("delivery:offline:{user_id}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&**db)
        .await;
}

/// A key no account here has is answered as a send to an unknown UUID is — accepted — so an
/// unauthenticated sender cannot learn from the reply which keys have accounts. Only the counter
/// tells the two apart.
#[tokio::test]
#[serial]
async fn k2_an_unknown_key_address_is_accepted_and_not_disclosed() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let unresolved = || {
        construct_metrics::MSG_SEALED_KEY_ADDRESS_TOTAL
            .with_label_values(&["unresolved"])
            .get()
    };
    let before = unresolved();
    let address = format!("ed25519:{}", hex::encode(random_bytes32()));
    let resp = dispatch_sealed_sender(
        &h.ctx,
        &build_sealed_envelope_to(&address, &random_bytes32()),
    )
    .await
    .expect("an unknown key address is not an error the sender sees");
    assert!(resp.success);
    assert!(!resp.message_id.is_empty(), "shaped like any accepted send");
    assert_eq!(unresolved(), before + 1);
    // Not UNSPECIFIED: an existing account answers NONE for the same envelope (K1), and a
    // verdict that differed would be the existence oracle `success` exists to deny.
    assert_eq!(resp.intake_verdict, IntakeVerdict::None as i32);

    // Same with a tag that does not open: what an account answers, not a tell that there is none.
    let mut with_tag = build_sealed_envelope_to(&address, &random_bytes32());
    let mut inner = core_proto::SealedInner::decode(with_tag.sealed_inner.as_ref()).unwrap();
    inner.intake_tag_sealed = vec![7u8; 64];
    with_tag.sealed_inner = inner.encode_to_vec();
    let resp = dispatch_sealed_sender(&h.ctx, &with_tag)
        .await
        .expect("still accepted");
    assert_eq!(resp.intake_verdict, IntakeVerdict::Unchecked as i32);

    // A malformed address is the sender's format error, not a disclosure, and stays refused.
    assert!(
        dispatch_sealed_sender(
            &h.ctx,
            &build_sealed_envelope_to("ed25519:zz", &random_bytes32())
        )
        .await
        .is_err()
    );
}

// ── I1: warn + no token still delivers ───────────────────────────────────────

#[tokio::test]
#[serial]
async fn i1_warn_mode_delivers_without_token() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let tag = random_bytes32();
    let sealed = build_sealed_envelope(&recipient, &tag, None, None);

    let mut conn = h.ctx.redis_conn.clone();
    let before = stream_len(&mut conn, &recipient).await;

    let resp = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("warn mode must deliver without token");
    assert!(resp.success);
    assert!(!resp.message_id.is_empty());

    let after = stream_len(&mut conn, &recipient).await;
    assert!(
        after > before,
        "sealed delivery must XADD to offline stream (before={before} after={after})"
    );
    assert!(
        !receipt_sender_exists(&mut conn, &resp.message_id).await,
        "I5: sealed must not write receipt:sender:{{message_id}}"
    );

    // Cleanup stream key
    let _: () = redis::cmd("DEL")
        .arg(format!("delivery:offline:{recipient}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
}

// ── I2: enforce + missing token → TokenRejected ──────────────────────────────

#[tokio::test]
#[serial]
async fn i2_enforce_rejects_missing_token() {
    let Some(h) = build_harness(StealthTokenPolicy::Enforce).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let tag = random_bytes32();
    let sealed = build_sealed_envelope(&recipient, &tag, None, None);

    let err = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect_err("enforce must reject missing token");
    let rejected = err
        .downcast_ref::<TokenRejected>()
        .expect("must be TokenRejected");
    assert_eq!(rejected.label, "missing_token");
    assert_eq!(rejected.to_string(), "privacy_pass:missing_token");
}

// ── I3: valid token once, double-spend second ────────────────────────────────

#[tokio::test]
#[serial]
async fn i3_token_ok_then_double_spent_under_enforce() {
    let Some(h) = build_harness(StealthTokenPolicy::Enforce).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let nonce = random_bytes32();
    let token = issue_client_token(&h.token_issuer_key, &nonce);
    let sealed_token = seal_token_for_server(&token, &h.token_enc_secret);

    // First send — unique delivery tag
    let tag1 = random_bytes32();
    let sealed1 = build_sealed_envelope(&recipient, &tag1, Some(&nonce), Some(&sealed_token));
    let resp = dispatch_sealed_sender(&h.ctx, &sealed1)
        .await
        .expect("first redeem must succeed under enforce");
    assert!(resp.success);

    // Second send — new delivery tag, same token nonce → double_spent
    let tag2 = random_bytes32();
    let sealed2 = build_sealed_envelope(&recipient, &tag2, Some(&nonce), Some(&sealed_token));
    let err = dispatch_sealed_sender(&h.ctx, &sealed2)
        .await
        .expect_err("double spend must fail under enforce");
    let rejected = err.downcast_ref::<TokenRejected>().expect("TokenRejected");
    assert_eq!(rejected.label, "double_spent");

    // Cleanup
    let mut conn = h.ctx.redis_conn.clone();
    let spent_key = format!("spent:{}", hex::encode(Sha256::digest(nonce)));
    let _: () = redis::cmd("DEL")
        .arg(&spent_key)
        .arg(format!("delivery:offline:{recipient}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
}

// ── I4: delivery_tag replay is idempotent success without second stream write ─

#[tokio::test]
#[serial]
async fn i4_delivery_tag_replay_is_silent_success() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let tag = random_bytes32();
    let sealed = build_sealed_envelope(&recipient, &tag, None, None);

    let mut conn = h.ctx.redis_conn.clone();
    let first = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("first delivery");
    assert!(first.success);
    let len_after_first = stream_len(&mut conn, &recipient).await;

    let second = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("replay must return success");
    assert!(second.success);
    // Different server message_id is fine; must not re-XADD
    let len_after_second = stream_len(&mut conn, &recipient).await;
    assert_eq!(
        len_after_first, len_after_second,
        "replay must not write a second stream entry"
    );

    let _: () = redis::cmd("DEL")
        .arg(format!("delivery:offline:{recipient}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
}

// ── I5/I6: no receipt map + stream entry present for sealed ──────────────────

// ── I7: a message that names its sender leaves no message → sender map ───────
//
// The map existed only to route a plaintext stream receipt back, and the server no longer relays
// those (receipts.rs). Mutation: restore `store_message_sender` in `dispatch_envelope` — this
// sees the key.

#[tokio::test]
#[serial]
async fn i7_named_sender_leaves_no_sender_mapping() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let sender = uuid::Uuid::new_v4().to_string();
    let recipient = uuid::Uuid::new_v4();
    let message_id = uuid::Uuid::new_v4().to_string();
    let envelope = construct_message::MessageEnvelope::new_direct_message(
        message_id.clone(),
        sender,
        recipient.to_string(),
        vec![0u8; 32],
        0,
        b"ciphertext".to_vec(),
        String::new(),
    );

    let app_context = Arc::new(h.ctx.to_app_context());
    crate::core::dispatch_envelope(&app_context, envelope, None)
        .await
        .expect("dispatch");

    let mut conn = h.ctx.redis_conn.clone();
    assert!(
        stream_len(&mut conn, &recipient).await >= 1,
        "the message must reach the stream, or the check below proves nothing"
    );
    assert!(
        !receipt_sender_exists(&mut conn, &message_id).await,
        "I7: no receipt:sender mapping for a message with a named sender"
    );

    let _: () = redis::cmd("DEL")
        .arg(format!("delivery:offline:{recipient}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
}

#[tokio::test]
#[serial]
async fn i5_i6_sealed_leaves_no_sender_mapping_but_writes_stream() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let tag = random_bytes32();
    let sealed = build_sealed_envelope(&recipient, &tag, None, None);

    let resp = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("deliver");
    assert!(resp.success);

    let mut conn = h.ctx.redis_conn.clone();
    assert!(
        stream_len(&mut conn, &recipient).await >= 1,
        "I6: offline stream must contain the sealed envelope"
    );
    assert!(
        !receipt_sender_exists(&mut conn, &resp.message_id).await,
        "I5: no receipt:sender mapping for sealed"
    );

    let _: () = redis::cmd("DEL")
        .arg(format!("delivery:offline:{recipient}"))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
}

// ── Redeem helper still returns labels used by enforce path ──────────────────

#[tokio::test]
#[serial]
async fn redeem_missing_token_label_is_stable() {
    let Some(mut conn) = try_redis().await else {
        return;
    };
    let result = redeem_token_checked(
        &mut conn,
        Some(&[1u8; 32]),
        None,
        &[],
        &[],
        &[],
        "user-test",
    )
    .await;
    // server_secret None → NotConfigured takes precedence over empty token in redeem_token_checked
    assert!(
        matches!(
            result,
            TokenRedeemResult::NotConfigured | TokenRedeemResult::MissingToken
        ),
        "got {result:?}"
    );
}

// ── G: intake key generations (decisions/intake-key-is-the-accounts-not-the-devices.md 2-3) ──

/// A higher generation replaces the epoch's set, an equal one adds, a lower one stores nothing,
/// and 0 (a build from before generations) adds only while the account is at 0.
#[tokio::test]
#[serial]
async fn g1_a_higher_generation_replaces_an_equal_one_adds_a_lower_one_is_refused() {
    use crate::intake::{
        IntakeCheck, PublishOutcome, PublishableTag, UnrecognisedReason, intake_epoch,
        intake_state, publish_tags,
    };
    let Some(mut conn) = try_redis().await else {
        return;
    };
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let account = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let epoch = intake_epoch(now);
    let tag = |b: u8| PublishableTag {
        epoch,
        tag: vec![b; crate::intake::INTAKE_TAG_LEN],
        ttl: 3_600,
    };
    async fn presented(
        h: &TestHarness,
        conn: &mut redis::aio::ConnectionManager,
        account: &str,
        now: u64,
        b: u8,
    ) -> IntakeCheck {
        let sealed =
            seal_token_for_server(&[b; crate::intake::INTAKE_TAG_LEN], &h.token_enc_secret);
        crate::intake::check_intake_credential(
            conn,
            Some(&h.token_enc_secret),
            &sealed,
            account,
            now,
        )
        .await
    }
    let check = async |c: &mut redis::aio::ConnectionManager, b: u8| {
        presented(&h, c, &account, now, b).await
    };

    // An old build (generation 0) on a fresh account adds, as before generations.
    assert_eq!(
        publish_tags(&mut conn, &account, 0, &[tag(1)])
            .await
            .unwrap(),
        (0, 1, PublishOutcome::AddedPreGeneration)
    );
    assert_eq!(
        intake_state(&mut conn, &account, now).await.unwrap(),
        (0, true)
    );

    // Generation 1 replaces: the old build's tag stops being accepted now.
    assert_eq!(
        publish_tags(&mut conn, &account, 1, &[tag(2)])
            .await
            .unwrap(),
        (1, 1, PublishOutcome::FirstGeneration)
    );
    assert_eq!(check(&mut conn, 2).await, IntakeCheck::Vouched);
    assert_eq!(
        check(&mut conn, 1).await,
        IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch)
    );

    // Equal adds beside it — two devices that rotated to the same generation both stay valid.
    assert_eq!(
        publish_tags(&mut conn, &account, 1, &[tag(3)])
            .await
            .unwrap(),
        (1, 1, PublishOutcome::Added)
    );
    assert_eq!(check(&mut conn, 2).await, IntakeCheck::Vouched);
    assert_eq!(check(&mut conn, 3).await, IntakeCheck::Vouched);

    // Lower stores nothing and says where the account is; so does 0 once generations exist.
    assert_eq!(
        publish_tags(&mut conn, &account, 0, &[tag(4)])
            .await
            .unwrap(),
        (1, 0, PublishOutcome::RefusedPreGeneration)
    );
    assert_eq!(
        check(&mut conn, 4).await,
        IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch)
    );
    assert_eq!(
        intake_state(&mut conn, &account, now).await.unwrap(),
        (1, true)
    );
    // Monotonic for the life of the account: the generation never expires on its own.
    let ttl: i64 = redis::cmd("TTL")
        .arg(crate::intake::generation_key(&account))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(ttl, -1, "the generation key must carry no TTL");

    // A key written with a TTL (the first cut of generations) loses it on an equal publish.
    let _: () = redis::cmd("EXPIRE")
        .arg(crate::intake::generation_key(&account))
        .arg(3_600)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        publish_tags(&mut conn, &account, 1, &[tag(3)])
            .await
            .unwrap(),
        (1, 1, PublishOutcome::Added)
    );
    let ttl: i64 = redis::cmd("TTL")
        .arg(crate::intake::generation_key(&account))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        ttl, -1,
        "an equal publish makes an expiring generation permanent"
    );

    // A rotation after a block: generation 2 drops both generation-1 tags at once.
    assert_eq!(
        publish_tags(&mut conn, &account, 2, &[tag(5)])
            .await
            .unwrap(),
        (2, 1, PublishOutcome::Rotated)
    );
    for old in [2, 3] {
        assert_eq!(
            check(&mut conn, old).await,
            IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch)
        );
    }
    assert_eq!(check(&mut conn, 5).await, IntakeCheck::Vouched);

    // A replace also drops the pre-2026-09-29 single-tag key for that epoch.
    let legacy = crate::intake::legacy_tag_key(&account, epoch);
    let _: () = redis::cmd("SET")
        .arg(&legacy)
        .arg(vec![6u8; crate::intake::INTAKE_TAG_LEN])
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(check(&mut conn, 6).await, IntakeCheck::Vouched);
    assert_eq!(
        publish_tags(&mut conn, &account, 3, &[tag(7)])
            .await
            .unwrap(),
        (3, 1, PublishOutcome::Rotated)
    );
    assert_eq!(
        check(&mut conn, 6).await,
        IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch)
    );
    // A device left behind by the rotation: its generation is stale, and it stores nothing.
    assert_eq!(
        publish_tags(&mut conn, &account, 2, &[tag(8)])
            .await
            .unwrap(),
        (3, 0, PublishOutcome::RefusedStale)
    );

    let _: () = redis::cmd("DEL")
        .arg(crate::intake::tag_key(&account, epoch))
        .arg(crate::intake::generation_key(&account))
        .query_async(&mut conn)
        .await
        .unwrap_or(());
}

// ── 234: delivery invariants from AGENTS.md that no test held ───────────────────────────────

/// A TCP forwarder to the test Redis that can be cut. After `cut()` every connection through it
/// is closed and every new one dropped at once — a Redis outage as this process sees it, without
/// touching the Redis the other tests share.
struct CuttableRedis {
    url: String,
    cut: tokio::sync::watch::Sender<bool>,
}

impl CuttableRedis {
    async fn start() -> Self {
        let target = redis_url()
            .trim_start_matches("redis://")
            .trim_end_matches('/')
            .to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local port");
        let url = format!("redis://{}", listener.local_addr().expect("local addr"));
        let (cut, cut_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                if *cut_rx.borrow() {
                    continue;
                }
                let target = target.clone();
                let mut cut_rx = cut_rx.clone();
                tokio::spawn(async move {
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                        _ = cut_rx.wait_for(|cut| *cut) => {}
                    }
                });
            }
        });
        Self { url, cut }
    }

    fn cut(&self) {
        let _ = self.cut.send(true);
    }
}

async fn del(conn: &mut redis::aio::ConnectionManager, keys: &[String]) {
    let _: () = redis::cmd("DEL")
        .arg(keys)
        .query_async(conn)
        .await
        .unwrap_or(());
}

/// The token blocklist cannot be read → the caller is not authenticated. A Redis outage must not
/// turn a revoked token back into a valid one. Mutation: let the blocklist `Err` arm fall through
/// — the device-less token is accepted after the cut.
///
/// The device-revoked `Err` arm cannot be isolated this way: both reads go to the same Redis and
/// the blocklist read fails first. Its `Ok(true)` arm is held here.
#[tokio::test]
#[serial]
async fn a1_auth_fails_closed_when_the_blocklist_cannot_be_read() {
    use crate::grpc::extract_authed_identity;
    let proxy = CuttableRedis::start().await;
    let Some(h) = build_harness_on(StealthTokenPolicy::Off, &proxy.url, &redis_url()).await else {
        return;
    };
    let bearer = |token: &str| {
        let mut md = tonic::metadata::MetadataMap::new();
        md.insert("authorization", format!("Bearer {token}").parse().unwrap());
        md
    };
    let user = uuid::Uuid::new_v4();
    let (plain, _, _) = h.ctx.auth_manager.create_token(&user).expect("token");
    let device = hex::encode(&random_bytes32()[..16]);
    let (with_device, _, _) = h
        .ctx
        .auth_manager
        .create_token_for_device(&user, Some(&device))
        .expect("device token");

    assert_eq!(
        extract_authed_identity(&bearer(&plain), &h.ctx).await,
        Some((user, None))
    );
    assert_eq!(
        extract_authed_identity(&bearer(&with_device), &h.ctx).await,
        Some((user, Some(device.clone())))
    );
    h.ctx
        .queue
        .lock()
        .await
        .mark_device_revoked(&device, 60)
        .await
        .expect("revoke");
    assert_eq!(
        extract_authed_identity(&bearer(&with_device), &h.ctx).await,
        None,
        "a removed device's token is refused"
    );

    proxy.cut();
    assert_eq!(
        extract_authed_identity(&bearer(&plain), &h.ctx).await,
        None,
        "with the blocklist unreadable a token is not trusted"
    );
}

/// `msg:dedup:{message_id}` is written after the mailbox entry, never before: marking first turned
/// a failed XADD into an acknowledged message with no stream entry, and the retry into a no-op.
/// The XADD is made to fail by putting a string where the recipient's stream goes. Mutation: mark
/// before the write — the key exists after the failed dispatch.
#[tokio::test]
#[serial]
async fn d1_a_message_is_marked_dispatched_only_once_its_stream_entry_exists() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let message_id = uuid::Uuid::new_v4().to_string();
    let envelope = construct_message::MessageEnvelope::new_direct_message(
        message_id.clone(),
        uuid::Uuid::new_v4().to_string(),
        recipient.to_string(),
        vec![0u8; 32],
        0,
        b"ciphertext".to_vec(),
        String::new(),
    );
    let app_context = Arc::new(h.ctx.to_app_context());
    let mut conn = h.ctx.redis_conn.clone();
    let stream_key = format!("delivery:offline:{recipient}");
    let dedup_key = format!("msg:dedup:{message_id}");
    let dedup_exists = async |conn: &mut redis::aio::ConnectionManager| -> bool {
        redis::cmd("EXISTS")
            .arg(&dedup_key)
            .query_async(conn)
            .await
            .unwrap()
    };

    let _: () = redis::cmd("SET")
        .arg(&stream_key)
        .arg("not-a-stream")
        .query_async(&mut conn)
        .await
        .unwrap();
    crate::core::dispatch_envelope(&app_context, envelope.clone(), None)
        .await
        .expect_err("a mailbox write that failed is an error, not a delivery");
    assert!(
        !dedup_exists(&mut conn).await,
        "nothing was written, so a retry must not be swallowed as a duplicate"
    );

    del(&mut conn, std::slice::from_ref(&stream_key)).await;
    crate::core::dispatch_envelope(&app_context, envelope.clone(), None)
        .await
        .expect("the retry delivers");
    assert!(dedup_exists(&mut conn).await);
    crate::core::dispatch_envelope(&app_context, envelope, None)
        .await
        .expect("a second retry is an idempotent success");
    assert_eq!(
        stream_len(&mut conn, &recipient).await,
        1,
        "and writes nothing more"
    );

    del(&mut conn, &[stream_key, dedup_key]).await;
}

/// A sealed envelope's `delivery_tag` is remembered for 5 minutes exactly and 24 hours as seen,
/// and forgotten again when the mailbox write fails — or the client's retry is answered as a
/// replay with nothing in the stream. Mutation: drop `unmark_delivery_tag` — the retry succeeds
/// and the stream stays empty.
#[tokio::test]
#[serial]
async fn t1_a_delivery_tag_is_kept_5_min_and_24_h_and_released_when_the_write_fails() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let tag = random_bytes32();
    let sealed = build_sealed_envelope(&recipient, &tag, None, None);
    let tag_hex = hex::encode(Sha256::digest(tag));
    let (exact, seen) = (
        format!("sealed:exact:{tag_hex}"),
        format!("sealed:seen:{tag_hex}"),
    );
    let stream_key = format!("delivery:offline:{recipient}");
    let mut conn = h.ctx.redis_conn.clone();
    let ttl = async |conn: &mut redis::aio::ConnectionManager, key: &str| -> i64 {
        redis::cmd("TTL").arg(key).query_async(conn).await.unwrap()
    };

    let _: () = redis::cmd("SET")
        .arg(&stream_key)
        .arg("not-a-stream")
        .query_async(&mut conn)
        .await
        .unwrap();
    dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect_err("the write failed");
    assert_eq!(ttl(&mut conn, &exact).await, -2, "exact mark released");
    assert_eq!(ttl(&mut conn, &seen).await, -2, "seen mark released");

    del(&mut conn, std::slice::from_ref(&stream_key)).await;
    dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("the retry delivers");
    assert_eq!(stream_len(&mut conn, &recipient).await, 1);
    assert!((295..=300).contains(&ttl(&mut conn, &exact).await));
    assert!((86_395..=86_400).contains(&ttl(&mut conn, &seen).await));

    del(&mut conn, &[stream_key, exact, seen]).await;
}

/// Under `enforce` the intake tag is what spares a token. A tag the recipient published delivers
/// with none; a tag it did not publish, and a tag that could not be looked up, owe one — the
/// lookup failing open to the token path, never to delivery. Mutation: treat `Unavailable` as
/// vouched — the third send is delivered.
#[tokio::test]
#[serial]
async fn n1_under_enforce_only_a_published_intake_tag_spares_the_token() {
    use crate::intake::{INTAKE_TAG_LEN, PublishableTag, intake_epoch, publish_tags, tag_key};
    let Some(h) = build_harness(StealthTokenPolicy::Enforce).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let account = recipient.to_string();
    let now = chrono::Utc::now().timestamp() as u64;
    let epoch = intake_epoch(now);
    let mut conn = h.ctx.redis_conn.clone();
    publish_tags(
        &mut conn,
        &account,
        1,
        &[PublishableTag {
            epoch,
            tag: vec![9; INTAKE_TAG_LEN],
            ttl: 3_600,
        }],
    )
    .await
    .expect("publish");
    let with_intake_tag = |tag: u8| {
        let mut sealed = build_sealed_envelope(&recipient, &random_bytes32(), None, None);
        let mut inner = core_proto::SealedInner::decode(sealed.sealed_inner.as_ref()).unwrap();
        inner.intake_tag_sealed =
            seal_token_for_server(&[tag; INTAKE_TAG_LEN], &h.token_enc_secret);
        sealed.sealed_inner = inner.encode_to_vec();
        sealed
    };
    let refusal = |err: anyhow::Error| err.downcast_ref::<TokenRejected>().map(|r| r.label);

    let resp = dispatch_sealed_sender(&h.ctx, &with_intake_tag(9))
        .await
        .expect("a published tag needs no token");
    assert_eq!(resp.intake_verdict, IntakeVerdict::Accepted as i32);
    assert_eq!(stream_len(&mut conn, &recipient).await, 1);

    let err = dispatch_sealed_sender(&h.ctx, &with_intake_tag(8))
        .await
        .expect_err("a tag the recipient never published owes a token");
    assert_eq!(refusal(err), Some("missing_token"));

    // The epoch's set replaced by a string: the lookup errors as it would with Redis failing.
    let set_key = tag_key(&account, epoch);
    del(&mut conn, std::slice::from_ref(&set_key)).await;
    let _: () = redis::cmd("SET")
        .arg(&set_key)
        .arg("not-a-set")
        .query_async(&mut conn)
        .await
        .unwrap();
    let err = dispatch_sealed_sender(&h.ctx, &with_intake_tag(9))
        .await
        .expect_err("a tag that could not be checked owes a token");
    assert_eq!(refusal(err), Some("missing_token"));
    assert_eq!(stream_len(&mut conn, &recipient).await, 1, "nothing more");

    del(
        &mut conn,
        &[
            set_key,
            crate::intake::generation_key(&account),
            format!("delivery:offline:{recipient}"),
        ],
    )
    .await;
}

/// The anti-abuse store down degrades anti-abuse, never delivery: with the delivery-tag cache and
/// the spent-token store unreachable, a sealed message carrying a token is delivered under
/// `enforce` and both bypasses are counted. Mutation: refuse on the delivery-tag `Err` arm, or
/// map `RedisError` to `Reject` — the send fails.
#[tokio::test]
#[serial]
async fn o1_with_the_anti_abuse_store_down_a_sealed_message_is_still_delivered() {
    let proxy = CuttableRedis::start().await;
    let Some(h) = build_harness_on(StealthTokenPolicy::Enforce, &redis_url(), &proxy.url).await
    else {
        return;
    };
    let fail_open = |control: &str| {
        construct_metrics::MSG_ABUSE_FAIL_OPEN_TOTAL
            .with_label_values(&[control])
            .get()
    };
    let (tag_before, token_before) = (fail_open("delivery_tag"), fail_open("stealth_token"));
    let recipient = uuid::Uuid::new_v4();
    let nonce = random_bytes32();
    let token = issue_client_token(&h.token_issuer_key, &nonce);
    let sealed = build_sealed_envelope(
        &recipient,
        &random_bytes32(),
        Some(&nonce),
        Some(&seal_token_for_server(&token, &h.token_enc_secret)),
    );

    proxy.cut();
    let resp = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("delivered without the anti-abuse checks");
    assert!(resp.success);
    let mut mailbox = h.ctx.queue.lock().await.clone_redis_connection();
    assert_eq!(stream_len(&mut mailbox, &recipient).await, 1);
    assert_eq!(fail_open("delivery_tag"), tag_before + 1);
    assert_eq!(fail_open("stealth_token"), token_before + 1);

    del(&mut mailbox, &[format!("delivery:offline:{recipient}")]).await;
}

/// A stream examines a sibling device's user-stream entries once, not on every poll: they are
/// counted as skipped on the first poll and the user position moves past them. On 2026-09-21 a
/// two-device stand re-read the same eight on every 5-second tick. Mutation: drop the
/// `user_stream_id` update in `poll_messages` — the second poll skips all ten again.
#[tokio::test]
#[serial]
async fn p1_a_stream_examines_a_siblings_entries_once() {
    use crate::stream::{StreamCatchupState, poll_messages};
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let user = uuid::Uuid::new_v4();
    let (me, sibling) = ("p1-reader-device", "p1-sibling-device");
    let mut queue = MessageQueue::new(&h.ctx.config).await.expect("queue");
    for _ in 0..10 {
        let mut env =
            construct_message::MessageEnvelope::new_key_sync("alice".into(), user.to_string());
        env.recipient_device = Some(sibling.to_string());
        queue
            .write_message_to_device_streams(&user.to_string(), &[sibling.to_string()], &env)
            .await
            .expect("dispatch to the sibling");
    }
    let skipped = || {
        construct_metrics::MSG_MAILBOX_SIBLING_ENTRIES_SKIPPED_TOTAL
            .with_label_values(&["stream"])
            .get()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let mut catchup = StreamCatchupState::default();

    let before = skipped();
    poll_messages(
        &mut queue,
        &h.ctx.config.messaging,
        user,
        Some(me),
        &mut catchup,
        &tx,
        false,
    )
    .await
    .expect("first poll");
    assert_eq!(skipped() - before, 10);
    assert!(rx.try_recv().is_err(), "none of them is the reader's");

    let before = skipped();
    poll_messages(
        &mut queue,
        &h.ctx.config.messaging,
        user,
        Some(me),
        &mut catchup,
        &tx,
        false,
    )
    .await
    .expect("second poll");
    assert_eq!(skipped() - before, 0, "already examined");

    let mut conn = h.ctx.redis_conn.clone();
    del(
        &mut conn,
        &[
            format!("delivery:offline:{user}"),
            format!("delivery:offline:{user}:{sibling}"),
        ],
    )
    .await;
}
