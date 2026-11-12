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
    ApnsConfig, ApnsEnvironment, Config, DbConfig, DeepLinksConfig, FederationConfig,
    LoggingConfig, MediaConfig, MessagingConfig, MtlsConfig, RedisKeyPrefixes, SecurityConfig,
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

mod cursors;

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

pub(crate) fn make_config(
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

        delivery_queue_prefix: "delivery".to_string(),

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
            user: "user:".to_string(),
        },
        media: MediaConfig {
            enabled: false,
            base_url: String::new(),
            upload_token_secret: String::new(),
            max_file_size: 10 * 1024 * 1024,
            rate_limit_per_hour: 100,
        },

        messaging,

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

/// `queue_redis` carries the mailbox (`MessageQueue`); `abuse_redis` the standalone connection
/// everything that does not need the queue mutex runs on — the sealed path's anti-abuse state
/// (delivery tags, intake tags, spent tokens) and, since the auth blocklist moved off the mutex, the
/// token blocklist and dedup reads too. Two addresses so a test can take one down and keep the other. In production
/// both are clones of the same `ConnectionManager` (`main.rs`: `message_queue.clone_redis_connection()`).
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

// ── K3: under enforce, a key address pays the same whether an account has it ──

/// `address` with the Privacy Pass token `nonce` pays with, sealed for this server.
fn to_key_with_token(
    h: &TestHarness,
    address: &str,
    nonce: Option<&[u8; 32]>,
) -> core_proto::SealedSenderEnvelope {
    let mut sealed = build_sealed_envelope_to(address, &random_bytes32());
    if let Some(nonce) = nonce {
        let token = issue_client_token(&h.token_issuer_key, nonce);
        let mut inner = core_proto::SealedInner::decode(sealed.sealed_inner.as_ref()).unwrap();
        inner.token_nonce = nonce.to_vec();
        inner.token_bytes = seal_token_for_server(&token, &h.token_enc_secret);
        sealed.sealed_inner = inner.encode_to_vec();
    }
    sealed
}

/// What a sender learns from one send: refused with which label, or accepted with which verdict.
async fn answer(h: &TestHarness, sealed: &core_proto::SealedSenderEnvelope) -> String {
    match dispatch_sealed_sender(&h.ctx, sealed).await {
        Ok(resp) => format!(
            "accepted success={} verdict={} devices={}",
            resp.success,
            resp.intake_verdict,
            resp.recipient_active_devices.len()
        ),
        Err(e) => match e.downcast_ref::<TokenRejected>() {
            Some(rejected) => format!("rejected {}", rejected.label),
            None => format!("error {e}"),
        },
    }
}

/// Without a token, an address with an account here was refused and one without was accepted —
/// a free answer to "does this key have an account" (todo/266). Both now pay alike: refused
/// without a token, accepted with one, the same verdict either way.
#[tokio::test]
#[serial]
async fn k3_under_enforce_a_key_address_pays_alike_with_or_without_an_account() {
    let Some(h) = build_harness(StealthTokenPolicy::Enforce).await else {
        return;
    };
    let (user_id, device_ids, known) = account_addressed_by_key(&h).await;
    let unknown = format!("ed25519:{}", hex::encode(random_bytes32()));

    let without = (
        answer(&h, &to_key_with_token(&h, &known, None)).await,
        answer(&h, &to_key_with_token(&h, &unknown, None)).await,
    );
    let (n1, n2) = (random_bytes32(), random_bytes32());
    let with = (
        answer(&h, &to_key_with_token(&h, &known, Some(&n1))).await,
        answer(&h, &to_key_with_token(&h, &unknown, Some(&n2))).await,
    );
    let spent = (
        answer(&h, &to_key_with_token(&h, &known, Some(&n1))).await,
        answer(&h, &to_key_with_token(&h, &unknown, Some(&n2))).await,
    );

    let mut conn = h.ctx.redis_conn.clone();
    let spent_keys: Vec<String> = [n1, n2]
        .iter()
        .map(|n| format!("spent:{}", hex::encode(Sha256::digest(n))))
        .collect();
    let _: () = redis::cmd("DEL")
        .arg(spent_keys)
        .query_async(&mut conn)
        .await
        .unwrap_or(());
    forget_account(&h, user_id, &device_ids).await;

    assert_eq!(without.0, "rejected missing_token");
    assert_eq!(
        without.1, without.0,
        "no token: the same answer with or without an account"
    );
    assert!(with.0.starts_with("accepted success=true"), "{}", with.0);
    assert_eq!(
        with.1, with.0,
        "a token: the same answer with or without an account"
    );
    assert_eq!(spent.0, "rejected double_spent");
    assert_eq!(
        spent.1, spent.0,
        "a spent token: the same answer either way"
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

// ── S1/S2: the answer names the recipient's devices (construct-docs todo/263) ────

/// An account with `recovery_key` and two active devices, and those devices' ids sorted.
async fn account_with_two_devices(
    db: &DbPool,
    recovery_key: &[u8; 32],
) -> (uuid::Uuid, Vec<String>) {
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (id, recovery_public_key) VALUES (gen_random_uuid(), $1) RETURNING id",
    )
    .bind(recovery_key.as_slice())
    .fetch_one(db)
    .await
    .expect("create an account");
    let mut ids = Vec::new();
    for _ in 0..2 {
        let device_id = hex::encode(&random_bytes32()[..16]);
        sqlx::query(
            "INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                                  identity_public, signed_prekey_public, signed_prekey_signature,
                                  crypto_suites, registered_at, is_active)
             VALUES ($1, $2, 'test', $3, $4, $5, $6, '[]'::jsonb, NOW(), TRUE)",
        )
        .bind(&device_id)
        .bind(user_id)
        .bind(random_bytes32().as_slice())
        .bind(random_bytes32().as_slice())
        .bind(random_bytes32().as_slice())
        .bind([0u8; 64].as_slice())
        .execute(db)
        .await
        .expect("create a device");
        ids.push(device_id);
    }
    ids.sort();
    (user_id, ids)
}

async fn forget_account(h: &TestHarness, user_id: uuid::Uuid, device_ids: &[String]) {
    let mut conn = h.ctx.redis_conn.clone();
    let mut keys = vec![format!("delivery:offline:{user_id}")];
    keys.extend(
        device_ids
            .iter()
            .map(|d| format!("delivery:offline:{user_id}:{d}")),
    );
    let _: () = redis::cmd("DEL")
        .arg(keys)
        .query_async(&mut conn)
        .await
        .unwrap_or(());
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&*h.ctx.db_pool)
        .await;
}

/// A send to an account id is answered with that account's devices, and a replay reads the same
/// as the delivery it repeats.
#[tokio::test]
#[serial]
async fn s1_the_answer_names_the_recipients_devices_and_a_replay_reads_the_same() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let (user_id, device_ids) = account_with_two_devices(&h.ctx.db_pool, &random_bytes32()).await;
    let sealed = build_sealed_envelope(&user_id, &random_bytes32(), None, None);

    let first = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("delivered");
    assert_eq!(first.recipient_active_devices, device_ids);
    let replay = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("a replay succeeds");
    assert_eq!(replay.recipient_active_devices, device_ids);

    forget_account(&h, user_id, &device_ids).await;
}

/// An account with two devices and the address it is reached by.
async fn account_addressed_by_key(h: &TestHarness) -> (uuid::Uuid, Vec<String>, String) {
    let recovery_key = random_bytes32();
    let (user_id, device_ids) = account_with_two_devices(&h.ctx.db_pool, &recovery_key).await;
    construct_db::backfill_account_addresses(&h.ctx.db_pool)
        .await
        .expect("the account gets its address");
    (
        user_id,
        device_ids,
        format!("ed25519:{}", hex::encode(recovery_key)),
    )
}

/// The envelope a client sends: addressed by key, naming the one device its copy is for.
fn sealed_to_device(address: &str, device: &str) -> core_proto::SealedSenderEnvelope {
    let mut sealed = build_sealed_envelope_to(address, &random_bytes32());
    let mut inner = core_proto::SealedInner::decode(sealed.sealed_inner.as_ref()).unwrap();
    inner.recipient_device = device.to_string();
    sealed.sealed_inner = inner.encode_to_vec();
    sealed
}

/// The stand of 2026-11-06 was red because an invite makes every contact one addressed by key, and
/// this answer was empty for all of them. A replay reads the same as the delivery it repeats.
#[tokio::test]
#[serial]
async fn s3_a_key_address_naming_its_device_is_answered_with_the_devices() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let (user_id, device_ids, address) = account_addressed_by_key(&h).await;
    let sealed = sealed_to_device(&address, &device_ids[0]);

    let first = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("delivered");
    assert_eq!(first.recipient_active_devices, device_ids);
    let replay = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("a replay succeeds");
    assert_eq!(replay.recipient_active_devices, device_ids);

    forget_account(&h, user_id, &device_ids).await;
}

/// A sender that knows only a signed-out device is the one that most needs the answer: its copy
/// reaches nobody who can open it. The answer names the devices that are active, not the one named.
#[tokio::test]
#[serial]
async fn s4_a_key_address_naming_its_signed_out_device_is_answered_with_the_active_ones() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let (user_id, device_ids, address) = account_addressed_by_key(&h).await;
    sqlx::query("UPDATE devices SET is_active = FALSE WHERE device_id = $1")
        .bind(&device_ids[0])
        .execute(&*h.ctx.db_pool)
        .await
        .expect("sign the device out");

    let resp = dispatch_sealed_sender(&h.ctx, &sealed_to_device(&address, &device_ids[0]))
        .await
        .expect("delivered");
    assert_eq!(resp.recipient_active_devices, vec![device_ids[1].clone()]);

    forget_account(&h, user_id, &device_ids).await;
}

/// The door stays shut for a device of someone else: an address with an account answers as an
/// address with none does (K2), for the same envelope, so the pair says nothing.
#[tokio::test]
#[serial]
async fn s5_a_key_address_naming_another_accounts_device_reads_like_an_unknown_key() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let (user_id, device_ids, address) = account_addressed_by_key(&h).await;
    let (stranger_id, stranger_devices, _) = account_addressed_by_key(&h).await;
    let unknown = format!("ed25519:{}", hex::encode(random_bytes32()));
    let mut conn = h.ctx.redis_conn.clone();
    let before = stream_len(&mut conn, &user_id).await;

    let known = dispatch_sealed_sender(&h.ctx, &sealed_to_device(&address, &stranger_devices[0]))
        .await
        .expect("delivered");
    assert!(
        stream_len(&mut conn, &user_id).await > before,
        "the address must have reached this account, or the empty answer proves nothing"
    );
    let absent = dispatch_sealed_sender(&h.ctx, &sealed_to_device(&unknown, &stranger_devices[0]))
        .await
        .expect("an unknown key address is not an error the sender sees");

    assert!(known.recipient_active_devices.is_empty());
    assert!(absent.recipient_active_devices.is_empty());
    assert_eq!(known.success, absent.success);
    assert_eq!(known.error, absent.error);
    assert_eq!(known.attempt_id, absent.attempt_id);
    assert_eq!(known.message_number, absent.message_number);
    assert_eq!(known.intake_verdict, absent.intake_verdict);

    forget_account(&h, user_id, &device_ids).await;
    forget_account(&h, stranger_id, &stranger_devices).await;
}

/// The key door hides which addresses have accounts: an address with devices answers exactly as an
/// address with no account does (K2), with no devices named, to a sender who names no device.
#[tokio::test]
#[serial]
async fn s2_a_key_address_is_answered_with_no_devices() {
    let Some(h) = build_harness(StealthTokenPolicy::Warn).await else {
        return;
    };
    let recovery_key = random_bytes32();
    let (user_id, device_ids) = account_with_two_devices(&h.ctx.db_pool, &recovery_key).await;
    construct_db::backfill_account_addresses(&h.ctx.db_pool)
        .await
        .expect("the account gets its address");
    let address = format!("ed25519:{}", hex::encode(recovery_key));
    let mut conn = h.ctx.redis_conn.clone();
    let before = stream_len(&mut conn, &user_id).await;

    let resp = dispatch_sealed_sender(
        &h.ctx,
        &build_sealed_envelope_to(&address, &random_bytes32()),
    )
    .await
    .expect("delivered");
    assert!(
        stream_len(&mut conn, &user_id).await > before,
        "the address must have reached this account, or the empty answer proves nothing"
    );
    assert!(resp.recipient_active_devices.is_empty());

    forget_account(&h, user_id, &device_ids).await;
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

    let app_context = h.ctx.clone();
    crate::core::dispatch_envelope(
        &app_context,
        envelope,
        None,
        crate::core::DeviceTargets::LookUp,
    )
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
pub(crate) struct CuttableRedis {
    pub(crate) url: String,
    cut: tokio::sync::watch::Sender<bool>,
}

impl CuttableRedis {
    pub(crate) async fn start() -> Self {
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

    pub(crate) fn cut(&self) {
        let _ = self.cut.send(true);
    }
}

/// A TCP forwarder to the test Redis that answers `-ERR` to any command naming the armed key
/// fragment and forwards everything else. Isolates one read from others on the same connection,
/// which `CuttableRedis` cannot. Commands on a connection here are one at a time.
pub(crate) struct FaultyRedis {
    pub(crate) url: String,
    armed: tokio::sync::watch::Sender<Option<Vec<u8>>>,
}

impl FaultyRedis {
    pub(crate) async fn start() -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = redis_url()
            .trim_start_matches("redis://")
            .trim_end_matches('/')
            .to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local port");
        let url = format!("redis://{}", listener.local_addr().expect("local addr"));
        let (armed, armed_rx) = tokio::sync::watch::channel(None::<Vec<u8>>);
        tokio::spawn(async move {
            while let Ok((inbound, _)) = listener.accept().await {
                let target = target.clone();
                let armed_rx = armed_rx.clone();
                tokio::spawn(async move {
                    let Ok(outbound) = tokio::net::TcpStream::connect(&target).await else {
                        return;
                    };
                    let (mut client_read, client_write) = inbound.into_split();
                    let (mut server_read, mut server_write) = outbound.into_split();
                    let client_write = Arc::new(Mutex::new(client_write));
                    let to_client = client_write.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(n) = server_read.read(&mut buf).await {
                            if n == 0 || to_client.lock().await.write_all(&buf[..n]).await.is_err()
                            {
                                return;
                            }
                        }
                    });
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = client_read.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        let hit = armed_rx.borrow().as_ref().is_some_and(|needle| {
                            buf[..n]
                                .windows(needle.len())
                                .any(|w| w == needle.as_slice())
                        });
                        let sent = if hit {
                            client_write
                                .lock()
                                .await
                                .write_all(b"-ERR injected by FaultyRedis\r\n")
                                .await
                        } else {
                            server_write.write_all(&buf[..n]).await
                        };
                        if sent.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self { url, armed }
    }

    pub(crate) fn fail_commands_naming(&self, fragment: &str) {
        let _ = self.armed.send(Some(fragment.as_bytes().to_vec()));
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
/// the blocklist read fails first. `a2` isolates it; the `Ok(true)` arm is held here.
#[tokio::test]
#[serial]
async fn a1_auth_fails_closed_when_the_blocklist_cannot_be_read() {
    use crate::grpc::extract_authed_identity;
    let proxy = CuttableRedis::start().await;
    // The fault goes on the connection the blocklist is read through, not the mailbox's: the two
    // reads are one `MGET` on `redis_conn` since the auth path left the queue mutex.
    let Some(h) = build_harness_on(StealthTokenPolicy::Off, &redis_url(), &proxy.url).await else {
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

/// The scoped dedup key is written after the mailbox entry, never before: marking first turned
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
    let app_context = h.ctx.clone();
    let mut conn = h.ctx.redis_conn.clone();
    let stream_key = format!("delivery:offline:{recipient}");
    let dedup_key = construct_queue::MessageDedupKey::new(
        &envelope.sender_id,
        &envelope.recipient_id,
        envelope.recipient_device.as_deref(),
        &message_id,
    )
    .as_str()
    .to_string();
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
    crate::core::dispatch_envelope(
        &app_context,
        envelope.clone(),
        None,
        crate::core::DeviceTargets::LookUp,
    )
    .await
    .expect_err("a mailbox write that failed is an error, not a delivery");
    assert!(
        !dedup_exists(&mut conn).await,
        "nothing was written, so a retry must not be swallowed as a duplicate"
    );

    del(&mut conn, std::slice::from_ref(&stream_key)).await;
    crate::core::dispatch_envelope(
        &app_context,
        envelope.clone(),
        None,
        crate::core::DeviceTargets::LookUp,
    )
    .await
    .expect("the retry delivers");
    assert!(dedup_exists(&mut conn).await);
    crate::core::dispatch_envelope(
        &app_context,
        envelope,
        None,
        crate::core::DeviceTargets::LookUp,
    )
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

/// Pin the sequential lookup's decisions before batching it: both carriers must be readable,
/// current epoch wins before previous, and a previous match cannot rescue a current read error.
/// Wrong-length/binary stored values and irrelevant epochs must keep their existing outcomes.
#[tokio::test]
#[serial]
async fn n2_intake_epoch_reads_preserve_matching_and_error_priority() {
    use crate::intake::{
        INTAKE_EPOCH_SECONDS, INTAKE_TAG_LEN, IntakeCheck, UnrecognisedReason,
        check_intake_credential, legacy_tag_key, tag_key,
    };
    #[derive(Clone, Copy)]
    enum Stored {
        Missing,
        Match,
        Other,
        WrongLength,
        WrongType,
    }
    use IntakeCheck::{Unavailable, Unrecognised, Vouched};
    use Stored::*;
    use UnrecognisedReason::{NoMatch, NothingPublished};

    let Some(mut conn) = try_redis().await else {
        return;
    };
    let account = uuid::Uuid::new_v4().to_string();
    let epoch = 20_707;
    let now = epoch * INTAKE_EPOCH_SECONDS;
    let secret = X25519StaticSecret::from(random_bytes32());
    let mut tag = vec![0; INTAKE_TAG_LEN];
    tag[INTAKE_TAG_LEN - 1] = 255;
    let sealed = seal_token_for_server(&tag, &secret);
    let keys = [
        tag_key(&account, epoch),
        legacy_tag_key(&account, epoch),
        tag_key(&account, epoch - 1),
        legacy_tag_key(&account, epoch - 1),
    ];
    let cases = [
        (
            "empty",
            [Missing, Missing, Missing, Missing],
            Unrecognised(NothingPublished),
        ),
        ("current set", [Match, Missing, Missing, Missing], Vouched),
        (
            "current legacy",
            [Missing, Match, Missing, Missing],
            Vouched,
        ),
        ("previous set", [Missing, Missing, Match, Missing], Vouched),
        (
            "previous legacy",
            [Missing, Missing, Missing, Match],
            Vouched,
        ),
        (
            "current mismatch",
            [Other, Missing, Missing, Missing],
            Unrecognised(NoMatch),
        ),
        (
            "previous mismatch",
            [Missing, Missing, Missing, Other],
            Unrecognised(NoMatch),
        ),
        (
            "previous rescues mismatch",
            [Other, Other, Match, Missing],
            Vouched,
        ),
        (
            "short set member",
            [WrongLength, Missing, Missing, Missing],
            Unrecognised(NoMatch),
        ),
        (
            "short legacy",
            [Missing, WrongLength, Missing, Missing],
            Unrecognised(NoMatch),
        ),
        (
            "legacy error despite set match",
            [Match, WrongType, Missing, Missing],
            Unavailable,
        ),
        (
            "set error despite legacy match",
            [WrongType, Match, Missing, Missing],
            Unavailable,
        ),
        (
            "previous cannot rescue current error",
            [WrongType, Missing, Match, Match],
            Unavailable,
        ),
        (
            "previous legacy error despite set match",
            [Missing, Missing, Match, WrongType],
            Unavailable,
        ),
        (
            "previous set error despite legacy match",
            [Missing, Missing, WrongType, Match],
            Unavailable,
        ),
        (
            "current wins before previous error",
            [Match, Missing, WrongType, WrongType],
            Vouched,
        ),
        (
            "current legacy wins before previous error",
            [Missing, Match, WrongType, WrongType],
            Vouched,
        ),
    ];
    // Matching tags outside the accepted epochs (or on another account) never count.
    let irrelevant = [
        tag_key(&account, epoch - 2),
        legacy_tag_key(&account, epoch + 1),
        tag_key(&uuid::Uuid::new_v4().to_string(), epoch),
    ];
    for (index, key) in irrelevant.iter().enumerate() {
        let _: () = redis::cmd(if index == 1 { "SET" } else { "SADD" })
            .arg(key)
            .arg(&tag)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
    for (label, states, expected) in cases {
        del(&mut conn, &keys).await;
        for (index, state) in states.into_iter().enumerate() {
            if matches!(state, Missing) {
                continue;
            }
            let value = match state {
                Match | WrongType => tag.clone(),
                Other => vec![7; INTAKE_TAG_LEN],
                WrongLength => vec![7; INTAKE_TAG_LEN - 1],
                Missing => unreachable!(),
            };
            let use_set = (index % 2 == 0) ^ matches!(state, WrongType);
            let _: redis::Value = redis::cmd(if use_set { "SADD" } else { "SET" })
                .arg(&keys[index])
                .arg(value)
                .query_async(&mut conn)
                .await
                .unwrap();
        }
        let actual =
            check_intake_credential(&mut conn, Some(&secret), &sealed, &account, now).await;
        assert_eq!(actual, expected, "{label}");
        assert_eq!(actual.verdict(), expected.verdict(), "{label}");
        assert_eq!(actual.owes_token(), expected.owes_token(), "{label}");
    }
    del(&mut conn, &keys).await;
    del(&mut conn, &irrelevant).await;

    // Epoch zero has no predecessor, and still accepts the current legacy carrier.
    let zero_key = legacy_tag_key(&account, 0);
    let _: () = redis::cmd("SET")
        .arg(&zero_key)
        .arg(&tag)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(
        check_intake_credential(&mut conn, Some(&secret), &sealed, &account, 0).await,
        Vouched
    );
    del(&mut conn, &[zero_key]).await;
}

/// Exercise the actual sealed-send consumer: grace/legacy matches spare the wallet, while a
/// mismatch or either unreadable carrier keeps its distinct verdict and redeems the token.
#[tokio::test]
#[serial]
async fn n3_intake_epoch_reads_keep_send_verdicts_and_token_spend() {
    use crate::intake::{INTAKE_TAG_LEN, intake_epoch, legacy_tag_key, tag_key};
    #[derive(Clone, Copy)]
    enum Scenario {
        PreviousMatch,
        NoMatch,
        LegacyError,
        SetError,
    }
    use Scenario::*;
    for policy in [StealthTokenPolicy::Warn, StealthTokenPolicy::Enforce] {
        let Some(h) = build_harness(policy).await else {
            return;
        };
        let recipient = uuid::Uuid::new_v4();
        let account = recipient.to_string();
        let epoch = intake_epoch(chrono::Utc::now().timestamp() as u64);
        let keys = [
            tag_key(&account, epoch),
            legacy_tag_key(&account, epoch),
            tag_key(&account, epoch - 1),
            legacy_tag_key(&account, epoch - 1),
        ];
        let tag = vec![9; INTAKE_TAG_LEN];
        let mut conn = h.ctx.redis_conn.clone();
        for (index, (scenario, verdict)) in [
            (PreviousMatch, IntakeVerdict::Accepted),
            (NoMatch, IntakeVerdict::NotAccepted),
            (LegacyError, IntakeVerdict::Unchecked),
            (SetError, IntakeVerdict::Unchecked),
        ]
        .into_iter()
        .enumerate()
        {
            del(&mut conn, &keys).await;
            let mut setup = redis::pipe();
            match scenario {
                PreviousMatch => {
                    setup.cmd("SET").arg(&keys[3]).arg(&tag);
                }
                NoMatch => {
                    setup
                        .cmd("SET")
                        .arg(&keys[3])
                        .arg(vec![8u8; INTAKE_TAG_LEN]);
                }
                LegacyError => {
                    setup
                        .cmd("SADD")
                        .arg(&keys[0])
                        .arg(&tag)
                        .cmd("SADD")
                        .arg(&keys[1])
                        .arg(&tag);
                }
                SetError => {
                    setup
                        .cmd("SET")
                        .arg(&keys[0])
                        .arg(&tag)
                        .cmd("SET")
                        .arg(&keys[1])
                        .arg(&tag);
                }
            }
            setup.query_async::<()>(&mut conn).await.unwrap();
            let nonce = random_bytes32();
            let token = issue_client_token(&h.token_issuer_key, &nonce);
            let delivery_tag = random_bytes32();
            let mut sealed = build_sealed_envelope(
                &recipient,
                &delivery_tag,
                Some(&nonce),
                Some(&seal_token_for_server(&token, &h.token_enc_secret)),
            );
            let mut inner = core_proto::SealedInner::decode(sealed.sealed_inner.as_ref()).unwrap();
            inner.intake_tag_sealed = seal_token_for_server(&tag, &h.token_enc_secret);
            sealed.sealed_inner = inner.encode_to_vec();

            let response = dispatch_sealed_sender(&h.ctx, &sealed)
                .await
                .expect("sealed send");
            assert!(response.success);
            assert_eq!(response.intake_verdict, verdict as i32);
            assert!(response.error.is_none());
            assert_eq!(stream_len(&mut conn, &recipient).await, (index + 1) as i64);
            let spent = format!("spent:{}", hex::encode(Sha256::digest(nonce)));
            let redeemed: bool = redis::cmd("EXISTS")
                .arg(&spent)
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(
                redeemed,
                verdict != IntakeVerdict::Accepted,
                "only a confirmed match spares the token"
            );
            crate::spent_tag::unmark_delivery_tag(&mut conn, &delivery_tag)
                .await
                .unwrap();
            del(&mut conn, &[spent]).await;
        }
        del(&mut conn, &keys).await;
        del(&mut conn, &[format!("delivery:offline:{recipient}")]).await;
    }
}

/// A transport outage is Unchecked, not NotAccepted or free sending. Invalid/absent credentials
/// still finish their local checks without Redis; the valid credential follows token fallback.
#[tokio::test]
#[serial]
async fn n4_intake_outage_keeps_local_checks_and_delivers_unchecked() {
    use crate::intake::{
        INTAKE_TAG_LEN, IntakeCheck, UnrecognisedReason, check_intake_credential, intake_epoch,
        tag_key,
    };
    let proxy = CuttableRedis::start().await;
    let Some(h) = build_harness_on(StealthTokenPolicy::Enforce, &redis_url(), &proxy.url).await
    else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let account = recipient.to_string();
    let now = chrono::Utc::now().timestamp() as u64;
    let key = tag_key(&account, intake_epoch(now));
    let tag = vec![9; INTAKE_TAG_LEN];
    let mut mailbox = h.ctx.queue.lock().await.clone_redis_connection();
    let _: i64 = redis::cmd("SADD")
        .arg(&key)
        .arg(&tag)
        .query_async(&mut mailbox)
        .await
        .unwrap();
    let credential = seal_token_for_server(&tag, &h.token_enc_secret);
    let mut conn = h.ctx.redis_conn.clone();
    assert_eq!(
        check_intake_credential(
            &mut conn,
            Some(&h.token_enc_secret),
            &credential,
            &account,
            now
        )
        .await,
        IntakeCheck::Vouched,
        "known good before the outage"
    );
    proxy.cut();

    let short = seal_token_for_server(&[9; INTAKE_TAG_LEN - 1], &h.token_enc_secret);
    for (presented, secret, expected) in [
        (&[][..], Some(&h.token_enc_secret), IntakeCheck::Absent),
        (
            &credential[..],
            None,
            IntakeCheck::Unrecognised(UnrecognisedReason::NoServerKey),
        ),
        (
            &[7u8; 64][..],
            Some(&h.token_enc_secret),
            IntakeCheck::Unrecognised(UnrecognisedReason::UnsealFailed),
        ),
        (
            &short[..],
            Some(&h.token_enc_secret),
            IntakeCheck::Unrecognised(UnrecognisedReason::WrongLength),
        ),
    ] {
        assert_eq!(
            check_intake_credential(&mut conn, secret, presented, &account, now).await,
            expected
        );
    }

    let nonce = random_bytes32();
    let token = issue_client_token(&h.token_issuer_key, &nonce);
    let mut sealed = build_sealed_envelope(
        &recipient,
        &random_bytes32(),
        Some(&nonce),
        Some(&seal_token_for_server(&token, &h.token_enc_secret)),
    );
    let mut inner = core_proto::SealedInner::decode(sealed.sealed_inner.as_ref()).unwrap();
    inner.intake_tag_sealed = credential;
    sealed.sealed_inner = inner.encode_to_vec();
    let response = dispatch_sealed_sender(&h.ctx, &sealed)
        .await
        .expect("an outage must not stop delivery");
    assert!(response.success);
    assert_eq!(response.intake_verdict, IntakeVerdict::Unchecked as i32);
    assert_eq!(stream_len(&mut mailbox, &recipient).await, 1);
    del(
        &mut mailbox,
        &[key, format!("delivery:offline:{recipient}")],
    )
    .await;
}

/// Withhold both replies until BOTH commands for an epoch arrive. Sequential awaits cannot
/// pass this test; a pipeline can. Parse RESP frames, not TCP packets, to avoid packet-boundary
/// assumptions. Also assert that a current match never asks Redis about the previous epoch.
#[tokio::test]
async fn n5_intake_sends_both_epoch_reads_before_awaiting_either() {
    use crate::intake::{
        INTAKE_EPOCH_SECONDS, INTAKE_TAG_LEN, IntakeCheck, UnrecognisedReason,
        check_intake_credential, legacy_tag_key, tag_key,
    };
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    async fn command(reader: &mut (impl tokio::io::AsyncBufRead + Unpin)) -> Vec<Vec<u8>> {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let count: usize = line
            .strip_prefix('*')
            .expect("RESP array")
            .trim()
            .parse()
            .unwrap();
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let len: usize = line
                .strip_prefix('$')
                .expect("bulk arg")
                .trim()
                .parse()
                .unwrap();
            let mut arg = vec![0; len + 2];
            reader.read_exact(&mut arg).await.unwrap();
            assert_eq!(&arg[len..], b"\r\n");
            arg.truncate(len);
            args.push(arg);
        }
        args
    }
    let account = uuid::Uuid::new_v4().to_string();
    let epoch = 20_707;
    let secret = X25519StaticSecret::from(random_bytes32());
    let credential = seal_token_for_server(&[9; INTAKE_TAG_LEN], &secret);
    for match_at in [Some(0), Some(1), None] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}", listener.local_addr().unwrap());
        let account_for_server = account.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            let mut pair_count = 0;
            loop {
                let args = command(&mut read).await;
                match args[0].as_slice() {
                    b"CLIENT" => {
                        write.write_all(b"+OK\r\n").await.unwrap();
                    }
                    b"PING" => {
                        write.write_all(b"+PONG\r\n").await.unwrap();
                    }
                    b"SMEMBERS" => {
                        let e = epoch - pair_count;
                        assert_eq!(
                            args,
                            vec![
                                b"SMEMBERS".to_vec(),
                                tag_key(&account_for_server, e).into_bytes()
                            ]
                        );
                        // Do not return SMEMBERS yet: the GET must already have been sent.
                        assert_eq!(
                            command(&mut read).await,
                            vec![
                                b"GET".to_vec(),
                                legacy_tag_key(&account_for_server, e).into_bytes()
                            ]
                        );
                        write.write_all(b"*0\r\n").await.unwrap();
                        let matched = match_at == Some(pair_count);
                        if matched {
                            write.write_all(b"$16\r\n").await.unwrap();
                            write.write_all(&[9; INTAKE_TAG_LEN]).await.unwrap();
                            write.write_all(b"\r\n").await.unwrap();
                        } else {
                            write.write_all(b"$-1\r\n").await.unwrap();
                        }
                        pair_count += 1;
                        if matched || pair_count == 2 {
                            return pair_count;
                        }
                    }
                    other => panic!("unexpected command {other:?}"),
                }
            }
        });
        let mut conn = construct_redis::manager_for(redis::Client::open(url).unwrap())
            .await
            .unwrap();
        let actual = check_intake_credential(
            &mut conn,
            Some(&secret),
            &credential,
            &account,
            epoch * INTAKE_EPOCH_SECONDS,
        )
        .await;
        assert_eq!(
            actual,
            if match_at.is_some() {
                IntakeCheck::Vouched
            } else {
                IntakeCheck::Unrecognised(UnrecognisedReason::NothingPublished)
            }
        );
        assert_eq!(
            server.await.unwrap(),
            if match_at == Some(0) { 1 } else { 2 }
        );
    }
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

/// The actual pending RPC keeps its wire result after read batching/merge changes: bytes stay
/// opaque, device wins duplicates, siblings/receipts/corrupt entries do not leak, and even empty
/// pages advance the Redis cursor. A device-less token still reads only the legacy stream.
#[tokio::test]
#[serial]
async fn p5_pending_rpc_preserves_payloads_cursors_and_legacy_reads() {
    use construct_server_shared::shared::proto::services::v1::{
        GetPendingMessagesRequest, PendingMessage, messaging_service_server::MessagingService,
    };
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let device = random_device();
    let account = recipient.to_string();
    let user_key = format!("delivery:offline:{account}");
    let device_key = format!("{user_key}:{device}");
    let payload = vec![0, 255, 128, 1];
    let make = |id: &str| {
        let mut e = construct_message::MessageEnvelope::new_direct_message(
            id.into(),
            "alice".into(),
            account.clone(),
            vec![0; 32],
            0,
            payload.clone(),
            String::new(),
        );
        e.timestamp = 7;
        e
    };
    let mut sibling = make("sibling");
    sibling.recipient_device = Some("other-device".into());
    let own = make("own");
    let user_only = make("user-only");
    let device_only = make("device-only");
    let mut receipt = make("receipt");
    receipt.message_type = construct_message::MessageType::Receipt;
    let mut sealed = make("sealed");
    sealed.is_sealed_sender = true;
    sealed.sealed_inner = Some(vec![255, 0, 128]);
    let mut conn = h.ctx.redis_conn.clone();
    for (key, rows) in [
        (
            &user_key,
            vec![
                ("50-0", sibling),
                ("110-0", own.clone()),
                ("200-0", user_only),
                ("400-0", make("corrupt")),
                ("500-0", receipt),
                ("600-0", sealed.clone()),
            ],
        ),
        (
            &device_key,
            vec![("100-0", own), ("300-0", device_only), ("610-0", sealed)],
        ),
    ] {
        for (id, e) in rows {
            let bytes = if e.message_id == "corrupt" {
                vec![255]
            } else {
                rmp_serde::encode::to_vec_named(&e).unwrap()
            };
            let _: String = redis::cmd("XADD")
                .arg(key)
                .arg(id)
                .arg("message_id")
                .arg(&e.message_id)
                .arg("payload")
                .arg(bytes)
                .query_async(&mut conn)
                .await
                .unwrap();
        }
    }
    let (token, _, _) = h
        .ctx
        .auth_manager
        .create_token_for_device(&recipient, Some(&device))
        .unwrap();
    let (legacy_token, _, _) = h.ctx.auth_manager.create_token(&recipient).unwrap();
    let request = |token: &str, cursor: Option<String>, limit: i32| {
        let mut req = tonic::Request::new(GetPendingMessagesRequest {
            since_cursor: cursor,
            limit: Some(limit),
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    };
    let service = crate::grpc::MessagingGrpcService {
        context: h.ctx.clone(),
    };
    let expected = |id: &str| PendingMessage {
        message_id: id.into(),
        sender_id: if id == "sealed" {
            String::new()
        } else {
            "alice".into()
        },
        encrypted_payload: if id == "sealed" {
            Vec::new()
        } else {
            payload.clone()
        },
        timestamp: 7,
        content_type: core_proto::ContentType::E2eeSignal as i32,
        sealed_inner_data: if id == "sealed" {
            vec![255, 0, 128]
        } else {
            Vec::new()
        },
    };
    let messages: Vec<_> = ["own", "user-only", "device-only", "sealed"]
        .into_iter()
        .map(expected)
        .collect();
    let full = service
        .get_pending_messages(request(&token, None, 100))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(full.messages, messages);
    assert_eq!(
        full.next_cursor,
        "mc1:00000000000000000610-00000000000000000000:00000000000000000600-00000000000000000000"
    );
    assert!(!full.has_more);
    assert!(full.gap.is_none());

    let mut cursor = "0-0".to_string();
    let mut received = Vec::new();
    let mut complete = false;
    let mut empty_pages = 0;
    for _ in 0..20 {
        let page = service
            .get_pending_messages(request(&token, Some(cursor.clone()), 1))
            .await
            .unwrap()
            .into_inner();
        if page.messages.is_empty() {
            empty_pages += 1;
        }
        assert!(page.gap.is_none());
        assert_ne!(
            page.next_cursor, cursor,
            "paging must advance even past corrupt/receipt-only pages"
        );
        received.extend(page.messages);
        cursor = page.next_cursor;
        if !page.has_more {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert!(
        empty_pages > 0,
        "exercise cursor advancement without a client-visible message"
    );
    assert_eq!(received, messages);
    assert_eq!(cursor, full.next_cursor);

    let legacy = service
        .get_pending_messages(request(&legacy_token, None, 100))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        legacy.messages,
        ["sibling", "own", "user-only", "sealed"]
            .into_iter()
            .map(expected)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        legacy.next_cursor,
        "mc1:00000000000000000000-00000000000000000000:00000000000000000600-00000000000000000000"
    );
    assert!(!legacy.has_more);
    assert_eq!(stream_len(&mut conn, &recipient).await, 6);
    let device_len: i64 = redis::cmd("XLEN")
        .arg(&device_key)
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(device_len, 3);
    del(&mut conn, &[user_key, device_key]).await;
}

/// A stream examines a sibling device's user-stream entries once, not on every poll: they are
/// counted as skipped on the first poll and the user position moves past them. On 2026-09-21 a
/// two-device stand re-read the same eight on every 5-second tick. Mutation: drop the
/// final source-cursor update in `poll_messages` — the second poll skips all ten again.
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

/// One wakeup must drain the backlog, including empty pages consisting entirely of sibling
/// entries. After #116 such a page has `has_more = true`: waiting for the next 5-second tick
/// makes catch-up take one tick per page even though Redis already holds the next message.
#[tokio::test]
#[serial]
async fn p2_one_stream_poll_drains_pages_including_an_empty_sibling_page() {
    use crate::stream::{StreamCatchupState, poll_messages};
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let mut queue = MessageQueue::new(&h.ctx.config).await.expect("queue");
    // Both carriers, plus the legacy device-less reader. Each case has more than one page.
    for (device, sibling_count) in [(None, 0), (Some("p2-reader"), 0), (Some("p2-reader"), 205)] {
        let user = uuid::Uuid::new_v4();
        let account = user.to_string();
        let sibling = "p2-sibling";
        for _ in 0..sibling_count {
            let mut env =
                construct_message::MessageEnvelope::new_key_sync("alice".into(), account.clone());
            env.recipient_device = Some(sibling.into());
            queue
                .write_message_to_device_streams(&account, &[sibling.into()], &env)
                .await
                .expect("sibling backlog");
        }
        let mut expected = Vec::new();
        for index in 0..125 {
            let mut env =
                construct_message::MessageEnvelope::new_key_sync("alice".into(), account.clone());
            env.recipient_device = device.map(str::to_string);
            expected.push(env.message_id.clone());
            if let Some(device) = device.filter(|_| index != 60) {
                queue
                    .write_message_to_device_streams(&account, &[device.into()], &env)
                    .await
                    .expect("reader backlog");
            } else {
                // Keep one user-only entry between device pages: neither source can be
                // advanced past the shorter read's horizon without actually delivering it.
                queue
                    .write_message_to_device_streams(&account, &[], &env)
                    .await
                    .expect("legacy backlog");
            }
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mut catchup = StreamCatchupState::default();
        poll_messages(
            &mut queue,
            &h.ctx.config.messaging,
            user,
            device,
            &mut catchup,
            &tx,
            false,
        )
        .await
        .expect("one catch-up poll");
        let mut previous_cursor = construct_queue::MailboxCursor::default();
        let mut received: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|response| {
                let response = response.expect("message, not an error");
                let cursor = response.stream_cursor.expect("resume cursor");
                let cursor: construct_queue::MailboxCursor = cursor.parse().expect("opaque cursor roundtrip");
                assert_eq!(cursor.join(previous_cursor), cursor, "a source regressed: {previous_cursor:?} -> {cursor:?}");
                previous_cursor = cursor;
                let Some(construct_server_shared::shared::proto::services::v1::message_stream_response::Response::Message(env)) = response.response else {
                    panic!("expected a message");
                };
                let Some(core_proto::envelope::MessageIdType::MessageId(id)) = env.message_id_type else {
                    panic!("expected a message id");
                };
                id
            }).collect();
        // Redis orders by each stream's ids; the independent sequence counters can put the
        // legacy-only entry just before a device copy inserted in the same millisecond.
        received.sort();
        // The page merge deduplicates within a page. Independent stream ids can
        // straddle pages; across pages the contract is at-least-once.
        received.dedup();
        expected.sort();
        assert_eq!(
            received, expected,
            "device={device:?}, siblings={sibling_count}"
        );
        poll_messages(
            &mut queue,
            &h.ctx.config.messaging,
            user,
            device,
            &mut catchup,
            &tx,
            false,
        )
        .await
        .expect("idle poll");
        assert!(
            rx.try_recv().is_err(),
            "a second poll must not redeliver the pages"
        );
        let mut conn = h.ctx.redis_conn.clone();
        del(
            &mut conn,
            &[
                format!("delivery:offline:{user}"),
                format!("delivery:offline:{user}:p2-reader"),
                format!("delivery:offline:{user}:{sibling}"),
            ],
        )
        .await;
    }
}

/// A sender chooses its message id. Reusing another sender's id, or addressing a different
/// recipient/device with that id, must not suppress delivery. Only the same routing scope is
/// an idempotent retry. The global key let the first sender reserve an id for everybody.
#[tokio::test]
#[serial]
async fn d2_dispatch_dedup_is_scoped_to_sender_recipient_and_device() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let app = h.ctx.clone();
    let (alice, bob, recipient, other) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let id = uuid::Uuid::new_v4().to_string();
    let mut conn = h.ctx.redis_conn.clone();
    // Old global keys cannot be dual-read safely: another sender may have planted one.
    let old_key = format!("msg:dedup:{id}");
    let _: () = redis::cmd("SET")
        .arg(&old_key)
        .arg("1")
        .arg("EX")
        .arg(60)
        .query_async(&mut conn)
        .await
        .unwrap();
    let mut cleanup = vec![
        format!("delivery:offline:{recipient}"),
        format!("delivery:offline:{other}"),
        old_key,
    ];
    for (sender, to, device, expected_len) in [
        (&alice, recipient, None, 1),
        (&bob, recipient, None, 2),
        (&alice, other, None, 1),
        (&alice, recipient, Some("d2-device-a"), 3),
        (&alice, recipient, Some("d2-device-b"), 4),
    ] {
        let mut env = construct_message::MessageEnvelope::new_direct_message(
            id.clone(),
            sender.clone(),
            to.to_string(),
            vec![0; 32],
            0,
            b"ciphertext".to_vec(),
            String::new(),
        );
        env.recipient_device = device.map(str::to_string);
        cleanup.push(
            construct_queue::MessageDedupKey::new(sender, &to.to_string(), device, &id)
                .as_str()
                .to_string(),
        );
        for _ in 0..2 {
            crate::core::dispatch_envelope(
                &app,
                env.clone(),
                None,
                crate::core::DeviceTargets::LookUp,
            )
            .await
            .expect("dispatch");
            assert_eq!(
                stream_len(&mut conn, &to).await,
                expected_len,
                "sender={sender}, recipient={to}, device={device:?}; only its own retry is a no-op"
            );
        }
    }
    del(&mut conn, &cleanup).await;
}

/// The unary early return and the dispatcher must use the same scope. Exercise the real RPC:
/// a global key here would acknowledge Bob's send before it ever reaches the dispatcher.
#[tokio::test]
#[serial]
async fn d3_send_message_fast_path_uses_the_same_scoped_dedup_as_dispatch() {
    use construct_server_shared::shared::proto::services::v1::{
        SendMessageRequest, messaging_service_server::MessagingService,
    };
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let service = crate::grpc::MessagingGrpcService {
        context: h.ctx.clone(),
    };
    let recipient = uuid::Uuid::new_v4();
    let id = uuid::Uuid::new_v4().to_string();
    let mut conn = h.ctx.redis_conn.clone();
    let old_key = format!("msg:dedup:{id}");
    let _: () = redis::cmd("SET")
        .arg(&old_key)
        .arg("1")
        .arg("EX")
        .arg(60)
        .query_async(&mut conn)
        .await
        .unwrap();
    let mut cleanup = vec![format!("delivery:offline:{recipient}"), old_key];
    for (index, sender) in [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()]
        .into_iter()
        .enumerate()
    {
        let device = hex::encode(&random_bytes32()[..16]);
        let (token, _, _) = h
            .ctx
            .auth_manager
            .create_token_for_device(&sender, Some(&device))
            .expect("authenticated sender");
        let env = construct_message::MessageEnvelope::new_direct_message(
            id.clone(),
            sender.to_string(),
            recipient.to_string(),
            vec![0; 32],
            0,
            b"ciphertext".to_vec(),
            String::new(),
        );
        let proto_env = crate::envelope::convert_envelope_to_proto(env).unwrap();
        for _ in 0..2 {
            let mut req = tonic::Request::new(SendMessageRequest {
                message: Some(proto_env.clone()),
                ..Default::default()
            });
            req.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            assert!(
                service
                    .send_message(req)
                    .await
                    .expect("unary send")
                    .into_inner()
                    .success
            );
            assert_eq!(stream_len(&mut conn, &recipient).await, (index + 1) as i64);
        }
        let hourly: u64 = redis::cmd("GET")
            .arg(format!("rate:msg:{{{sender}}}:hour"))
            .query_async(&mut conn)
            .await
            .expect("hourly send count");
        assert_eq!(
            hourly, 1,
            "a cached retry must not charge the hourly limit twice"
        );
        cleanup.push(
            construct_queue::MessageDedupKey::new(
                &sender.to_string(),
                &recipient.to_string(),
                None,
                &id,
            )
            .as_str()
            .to_string(),
        );
        cleanup.push(format!("trust:{sender}"));
        cleanup.push(format!("rate:msg:{{{sender}}}:hour"));
        let day = chrono::Utc::now().timestamp() / 86_400;
        cleanup.push(format!("fanout:{sender}:{day}"));
        cleanup.push(format!("fanout:{sender}:{day}:probe"));
    }
    del(&mut conn, &cleanup).await;
}

/// A retry already committed to a mailbox must return before rate counters or mailbox writes,
/// even while another send holds the queue. Mutation: put the ingress dedup read under the mutex.
#[tokio::test]
#[serial]
async fn d5_unary_duplicate_does_not_wait_on_the_mailbox_mutex() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let envelope = direct_envelope(&sender, &recipient, vec![7; 8], None);
    let first = unary_send(&h, sender, &device, envelope.clone())
        .await
        .expect("first send");
    assert!(first.success);

    let held = h.ctx.queue.lock().await;
    let started = std::time::Instant::now();
    let retry = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        unary_send(&h, sender, &device, envelope),
    )
    .await;
    let elapsed = started.elapsed();
    drop(held);

    let mut conn = h.ctx.redis_conn.clone();
    let copies = stream_len(&mut conn, &recipient).await;
    let hourly: u64 = redis::cmd("GET")
        .arg(format!("rate:msg:{{{sender}}}:hour"))
        .query_async(&mut conn)
        .await
        .expect("hourly count");
    let dedup = construct_queue::MessageDedupKey::new(
        &sender.to_string(),
        &recipient.to_string(),
        None,
        &first.message_id,
    );
    del(
        &mut conn,
        &[
            format!("delivery:offline:{recipient}"),
            dedup.as_str().to_string(),
        ],
    )
    .await;
    cleanup_sender(&mut conn, &sender).await;

    let retry = retry
        .expect("a cached unary retry must not wait for the mailbox mutex")
        .expect("idempotent success");
    assert!(retry.success);
    assert_eq!(retry.message_id, first.message_id);
    assert_eq!(retry.message_number, 0);
    assert_eq!(retry.error, None);
    assert_eq!(retry.intake_verdict, IntakeVerdict::Unspecified as i32);
    assert!(retry.recipient_active_devices.is_empty());
    assert_eq!(copies, 1, "a retry must not add another mailbox entry");
    assert_eq!(
        hourly, 1,
        "a retry must not charge the hourly counter again"
    );
    eprintln!("cached unary retry with mailbox mutex held: {elapsed:?}");
}

/// Dispatch retains its own dedup recheck, but reading it must not queue behind a mailbox write.
/// Mutation: put the dispatch dedup read under the mutex held below.
#[tokio::test]
#[serial]
async fn d6_dispatch_duplicate_does_not_wait_on_the_mailbox_mutex() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let (sender, recipient) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let envelope = construct_message::MessageEnvelope::new_direct_message(
        uuid::Uuid::new_v4().to_string(),
        sender.to_string(),
        recipient.to_string(),
        vec![0; 32],
        0,
        b"ciphertext".to_vec(),
        String::new(),
    );
    let dedup = construct_queue::MessageDedupKey::new(
        &sender.to_string(),
        &recipient.to_string(),
        None,
        &envelope.message_id,
    );
    let app = h.ctx.clone();
    crate::core::dispatch_envelope(
        &app,
        envelope.clone(),
        None,
        crate::core::DeviceTargets::Known(Vec::new()),
    )
    .await
    .expect("first dispatch");

    let held = h.ctx.queue.lock().await;
    let started = std::time::Instant::now();
    let retry = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::core::dispatch_envelope(
            &app,
            envelope,
            None,
            crate::core::DeviceTargets::Known(Vec::new()),
        ),
    )
    .await;
    let elapsed = started.elapsed();
    drop(held);

    let mut conn = h.ctx.redis_conn.clone();
    let copies = stream_len(&mut conn, &recipient).await;
    del(
        &mut conn,
        &[
            format!("delivery:offline:{recipient}"),
            dedup.as_str().to_string(),
        ],
    )
    .await;
    retry
        .expect("a committed dispatch retry must not wait for the mailbox mutex")
        .expect("idempotent success");
    assert_eq!(copies, 1, "a dispatch retry must not write another entry");
    eprintln!("cached dispatch retry with mailbox mutex held: {elapsed:?}");
}

/// Catch-up checks revocation again between pages. Holding the response channel to one item
/// lets the test revoke after the first read, before another read can start, without sleeps.
#[tokio::test]
#[serial]
async fn p3_a_device_revoked_during_catchup_receives_no_next_page() {
    use crate::stream::{StreamCatchupState, poll_messages};
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let user = uuid::Uuid::new_v4();
    let device = hex::encode(&random_bytes32()[..16]);
    let mut queue = MessageQueue::new(&h.ctx.config).await.expect("queue");
    for _ in 0..75 {
        let mut env =
            construct_message::MessageEnvelope::new_key_sync("alice".into(), user.to_string());
        env.recipient_device = Some(device.clone());
        queue
            .write_message_to_device_streams(&user.to_string(), std::slice::from_ref(&device), &env)
            .await
            .expect("backlog");
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let config = h.ctx.config.clone();
    let reader = device.clone();
    let poll = tokio::spawn(async move {
        poll_messages(
            &mut queue,
            &config.messaging,
            user,
            Some(&reader),
            &mut StreamCatchupState::default(),
            &tx,
            false,
        )
        .await
    });
    rx.recv()
        .await
        .expect("first response")
        .expect("first message");
    h.ctx
        .queue
        .lock()
        .await
        .mark_device_revoked(&device, 60)
        .await
        .expect("revoke");
    let mut received = 1;
    while let Some(response) = rx.recv().await {
        match response {
            Ok(_) => received += 1,
            Err(status) => {
                assert_eq!(status.code(), tonic::Code::Unauthenticated);
                break;
            }
        }
    }
    assert_eq!(received, 50, "the next page is refused");
    poll.await.unwrap().expect_err("revoked stream ends");
    let mut conn = h.ctx.redis_conn.clone();
    assert_eq!(stream_len(&mut conn, &user).await, 75, "reads never delete");
    del(
        &mut conn,
        &[
            format!("delivery:offline:{user}"),
            format!("delivery:offline:{user}:{device}"),
            format!("revoked_device:{device}"),
        ],
    )
    .await;
}

/// The existing Privacy Pass contract spends on every attempt, including a replay and a
/// mailbox write failure. A fresh token can retry the same delivery tag; refunding a nonce or
/// moving the replay guard before redemption would change that anti-abuse policy.
#[tokio::test]
#[serial]
async fn t2_enforce_retries_use_a_fresh_token_after_a_failed_write_or_a_replay() {
    let Some(h) = build_harness(StealthTokenPolicy::Enforce).await else {
        return;
    };
    let recipient = uuid::Uuid::new_v4();
    let tag = random_bytes32();
    let mut conn = h.ctx.redis_conn.clone();
    let stream = format!("delivery:offline:{recipient}");
    let mut cleanup = vec![stream.clone()];
    let mut envelopes = Vec::new();
    for _ in 0..3 {
        let nonce = random_bytes32();
        let token = issue_client_token(&h.token_issuer_key, &nonce);
        envelopes.push(build_sealed_envelope(
            &recipient,
            &tag,
            Some(&nonce),
            Some(&seal_token_for_server(&token, &h.token_enc_secret)),
        ));
        cleanup.push(format!("spent:{}", hex::encode(Sha256::digest(nonce))));
    }
    let _: () = redis::cmd("SET")
        .arg(&stream)
        .arg("not-a-stream")
        .query_async(&mut conn)
        .await
        .unwrap();
    let err = dispatch_sealed_sender(&h.ctx, &envelopes[0])
        .await
        .expect_err("failed write");
    assert!(
        err.downcast_ref::<TokenRejected>().is_none(),
        "token passed; write failed"
    );
    del(&mut conn, std::slice::from_ref(&stream)).await;
    let err = dispatch_sealed_sender(&h.ctx, &envelopes[0])
        .await
        .expect_err("spent nonce");
    assert_eq!(
        err.downcast_ref::<TokenRejected>().unwrap().label,
        "double_spent"
    );
    assert_eq!(stream_len(&mut conn, &recipient).await, 0);
    for envelope in &envelopes[1..] {
        assert!(
            dispatch_sealed_sender(&h.ctx, envelope)
                .await
                .expect("fresh token")
                .success
        );
        assert_eq!(
            stream_len(&mut conn, &recipient).await,
            1,
            "retry delivers once; replay adds nothing"
        );
    }
    for key in &cleanup[1..] {
        assert!(
            redis::cmd("EXISTS")
                .arg(key)
                .query_async::<bool>(&mut conn)
                .await
                .unwrap(),
            "every attempt spent its fresh token"
        );
    }
    let tag_hash = hex::encode(Sha256::digest(tag));
    cleanup.extend([
        format!("sealed:exact:{tag_hash}"),
        format!("sealed:seen:{tag_hash}"),
    ]);
    del(&mut conn, &cleanup).await;
}

#[tokio::test]
#[serial]
async fn t3_a_missing_delivery_tag_is_counted_and_does_not_block_delivery() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let counter = &construct_metrics::MSG_SEALED_DELIVERY_TAG_MISSING_TOTAL;
    let before = counter.get();
    let recipient = uuid::Uuid::new_v4();
    let empty = build_sealed_envelope(&recipient, &[], None, None);
    for _ in 0..2 {
        assert!(
            dispatch_sealed_sender(&h.ctx, &empty)
                .await
                .unwrap()
                .success
        );
    }
    assert_eq!(counter.get() - before, 2);
    let tag = random_bytes32();
    dispatch_sealed_sender(&h.ctx, &build_sealed_envelope(&recipient, &tag, None, None))
        .await
        .unwrap();
    assert_eq!(
        counter.get() - before,
        2,
        "a present tag does not count as missing"
    );
    let mut conn = h.ctx.redis_conn.clone();
    assert_eq!(stream_len(&mut conn, &recipient).await, 3);
    let tag_hash = hex::encode(Sha256::digest(tag));
    del(
        &mut conn,
        &[
            format!("delivery:offline:{recipient}"),
            format!("sealed:exact:{tag_hash}"),
            format!("sealed:seen:{tag_hash}"),
        ],
    )
    .await;
}

// ── Audit residuals: stream wiring, SendMessage gates, fail-open arms, push rejections ───────

fn abuse_fail_open(control: &str) -> u64 {
    construct_metrics::MSG_ABUSE_FAIL_OPEN_TOTAL
        .with_label_values(&[control])
        .get()
}

fn with_sentinel(h: TestHarness) -> TestHarness {
    let TestHarness {
        ctx,
        token_issuer_key,
        token_enc_secret,
    } = h;
    let mut ctx = Arc::try_unwrap(ctx)
        .ok()
        .expect("sole owner of the context");
    ctx.sentinel = Some(Arc::new(
        construct_server_shared::sentinel_service::SentinelCore::new(
            (*ctx.db_pool).clone(),
            ctx.redis_conn.clone(),
        ),
    ));
    TestHarness {
        ctx: Arc::new(ctx),
        token_issuer_key,
        token_enc_secret,
    }
}

fn direct_envelope(
    sender: &uuid::Uuid,
    recipient: &uuid::Uuid,
    payload: Vec<u8>,
    sender_device: Option<&str>,
) -> core_proto::Envelope {
    let env = construct_message::MessageEnvelope::new_direct_message(
        uuid::Uuid::new_v4().to_string(),
        sender.to_string(),
        recipient.to_string(),
        vec![0; 32],
        0,
        payload,
        String::new(),
    );
    let mut proto_env = crate::envelope::convert_envelope_to_proto(env).unwrap();
    proto_env.sender_device = sender_device.map(|device_id| core_proto::DeviceId {
        device_id: device_id.to_string(),
        ..Default::default()
    });
    proto_env
}

fn random_device() -> String {
    hex::encode(&random_bytes32()[..16])
}

/// One `Send` through the real stream handler, as an open `MessageStream` of `token_device`.
async fn stream_send(
    h: &TestHarness,
    sender: uuid::Uuid,
    token_device: Option<&str>,
    envelope: core_proto::Envelope,
) -> (
    anyhow::Result<()>,
    Option<construct_server_shared::shared::proto::services::v1::message_stream_response::Response>,
) {
    use construct_server_shared::shared::proto::services::v1 as proto;
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut user_id = Some(sender);
    let mut queue = MessageQueue::new(&h.ctx.config).await.expect("queue");
    let mut catchup = crate::stream::StreamCatchupState::default();
    let result = crate::stream::handle_stream_request(
        proto::MessageStreamRequest {
            request: Some(proto::message_stream_request::Request::Send(envelope)),
            request_id: "r1".into(),
            ..Default::default()
        },
        &h.ctx,
        &tx,
        &mut user_id,
        token_device,
        &mut queue,
        &mut catchup,
        "127.0.0.1",
    )
    .await;
    drop(tx);
    let frame = rx
        .recv()
        .await
        .and_then(|f| f.ok())
        .and_then(|f| f.response);
    (result, frame)
}

async fn unary_send(
    h: &TestHarness,
    sender: uuid::Uuid,
    token_device: &str,
    envelope: core_proto::Envelope,
) -> Result<construct_server_shared::shared::proto::services::v1::SendMessageResponse, tonic::Status>
{
    use construct_server_shared::shared::proto::services::v1::{
        SendMessageRequest, messaging_service_server::MessagingService,
    };
    let (token, _, _) = h
        .ctx
        .auth_manager
        .create_token_for_device(&sender, Some(token_device))
        .expect("token");
    let mut req = tonic::Request::new(SendMessageRequest {
        message: Some(envelope),
        ..Default::default()
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    crate::grpc::MessagingGrpcService {
        context: h.ctx.clone(),
    }
    .send_message(req)
    .await
    .map(|r| r.into_inner())
}

async fn cleanup_sender(conn: &mut redis::aio::ConnectionManager, sender: &uuid::Uuid) {
    let day = chrono::Utc::now().timestamp() / 86_400;
    del(
        conn,
        &[
            format!("trust:{sender}"),
            format!("rate:msg:{{{sender}}}:hour"),
            format!("fanout:{sender}:{day}"),
            format!("fanout:{sender}:{day}:probe"),
        ],
    )
    .await;
}

/// The stream path has the unary path's 64 KiB cap. Until 2026-10-29 it checked only for empty, so
/// a stream send wrote anything up to the gRPC decode limit into someone's mailbox. The largest
/// allowed payload goes through, so the refusal is not some other failure. Mutation: drop
/// `validate_payload` from `handle_stream_request` — the oversized entry is written.
#[tokio::test]
#[serial]
async fn s1_a_stream_send_is_held_to_the_payload_cap() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let mut conn = h.ctx.redis_conn.clone();

    let over = direct_envelope(&sender, &recipient, vec![7; 64 * 1024 + 1], None);
    let (result, _) = stream_send(&h, sender, Some(&device), over).await;
    assert!(result.is_err(), "65537 bytes must be refused");
    assert_eq!(stream_len(&mut conn, &recipient).await, 0);

    let at_cap = direct_envelope(&sender, &recipient, vec![7; 64 * 1024], None);
    let (result, _) = stream_send(&h, sender, Some(&device), at_cap).await;
    result.expect("64 KiB exactly is allowed");
    assert_eq!(stream_len(&mut conn, &recipient).await, 1);

    del(&mut conn, &[format!("delivery:offline:{recipient}")]).await;
    cleanup_sender(&mut conn, &sender).await;
}

/// The stream charges the token's device and refuses one naming another; a token without a device
/// is refused too. Mutation: skip `sentinel_sender_device` in `handle_stream_request` — either
/// refused send writes an entry.
#[tokio::test]
#[serial]
async fn s2_a_stream_send_cannot_name_another_device() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let mut conn = h.ctx.redis_conn.clone();

    let foreign = direct_envelope(&sender, &recipient, vec![7; 8], Some(&random_device()));
    let (result, _) = stream_send(&h, sender, Some(&device), foreign).await;
    assert!(result.is_err(), "another device's id must be refused");

    let no_device = direct_envelope(&sender, &recipient, vec![7; 8], None);
    let (result, _) = stream_send(&h, sender, None, no_device).await;
    assert!(result.is_err(), "a token without a device must be refused");
    assert_eq!(stream_len(&mut conn, &recipient).await, 0);

    let own = direct_envelope(&sender, &recipient, vec![7; 8], Some(&device));
    let (result, _) = stream_send(&h, sender, Some(&device), own).await;
    result.expect("the token's own device id goes through");
    assert_eq!(stream_len(&mut conn, &recipient).await, 1);

    del(&mut conn, &[format!("delivery:offline:{recipient}")]).await;
    cleanup_sender(&mut conn, &sender).await;
}

/// A banned device cannot escape Sentinel by leaving `sender_device` empty, on either path: the
/// check runs on the token's device (the audit's finding: it used to run only when the envelope
/// named one). Mutations: charge the envelope's field in place of the token's device, or remove
/// the Sentinel block from either path — the banned send is written.
#[tokio::test]
#[serial]
async fn s3_a_banned_device_is_refused_with_an_empty_sender_device() {
    use construct_server_shared::shared::proto::services::v1 as proto;
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let h = with_sentinel(h);
    let (sender, recipient, banned, allowed) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        random_device(),
        random_device(),
    );
    let mut conn = h.ctx.redis_conn.clone();
    // The key `trust_level` reads first; `set_banned` also needs a registered device row.
    let ban_key = format!("sentinel:ban:{banned}");
    let _: () = redis::cmd("SET")
        .arg(&ban_key)
        .arg("1")
        .arg("EX")
        .arg(120)
        .query_async(&mut conn)
        .await
        .unwrap();

    let (result, frame) = stream_send(
        &h,
        sender,
        Some(&banned),
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await;
    result.expect("a refusal is an answer, not a stream error");
    match frame {
        Some(proto::message_stream_response::Response::Error(e)) => {
            assert_eq!(e.error_code, proto::ErrorCode::Blocked as i32);
            assert!(!e.retryable);
        }
        other => panic!("expected a Blocked frame, got {other:?}"),
    }

    let unary = unary_send(
        &h,
        sender,
        &banned,
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await
    .expect("a refusal is an answer, not a status");
    assert!(!unary.success);
    assert_eq!(
        unary.error.expect("refusal").error_code,
        proto::ErrorCode::Blocked as i32
    );
    assert_eq!(stream_len(&mut conn, &recipient).await, 0);

    let unary = unary_send(
        &h,
        sender,
        &allowed,
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await
    .expect("send");
    assert!(unary.success, "only the banned device is refused");
    assert_eq!(stream_len(&mut conn, &recipient).await, 1);

    del(
        &mut conn,
        &[format!("delivery:offline:{recipient}"), ban_key],
    )
    .await;
    cleanup_sender(&mut conn, &sender).await;
}

/// `SendMessage` answers an exhausted hourly limit with `retry_after_ms` and writes nothing.
/// `trust.rs` holds the counter; this holds the wire. Mutation: ignore `limited` in `send_message`
/// — the entry is written.
#[tokio::test]
#[serial]
async fn u1_send_message_refuses_past_the_hourly_limit() {
    use construct_server_shared::shared::proto::services::v1 as proto;
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let mut conn = h.ctx.redis_conn.clone();
    let _: () = redis::cmd("SET")
        .arg(format!("rate:msg:{{{sender}}}:hour"))
        .arg(u32::MAX)
        .arg("EX")
        .arg(120)
        .query_async(&mut conn)
        .await
        .unwrap();

    let resp = unary_send(
        &h,
        sender,
        &device,
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await
    .expect("a refusal is an answer, not a status");
    assert!(!resp.success);
    let error = resp.error.expect("refusal");
    assert_eq!(error.error_code, proto::ErrorCode::RateLimit as i32);
    assert!(error.retryable);
    assert!(error.retry_after_ms.unwrap_or(0) > 0);
    assert_eq!(stream_len(&mut conn, &recipient).await, 0);

    cleanup_sender(&mut conn, &sender).await;
}

/// With the store holding the limits down, `SendMessage` still delivers, and says so on the
/// fail-open counter. Before this test the counter could not move: `redis_conn()` is always `Ok`
/// and the limit scripts swallowed their errors, so the outage alert never saw these skips.
///
/// The fault is aimed at the limit commands (`rate:msg:`), not at the connection: the blocklist
/// read that authenticates the send shares that connection, and refusing an unauthenticated send
/// is the right answer — what this test holds is that the *limits* failing never refuses a send
/// that was allowed. Mutations: drop both counts in `trust.rs`, or refuse on a script error.
#[tokio::test]
#[serial]
async fn f1_send_message_delivers_and_counts_when_the_limit_store_is_down() {
    let proxy = FaultyRedis::start().await;
    let Some(h) = build_harness_on(StealthTokenPolicy::Off, &redis_url(), &proxy.url).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let before = abuse_fail_open("rate_trust");

    proxy.fail_commands_naming("rate:msg:");
    let resp = unary_send(
        &h,
        sender,
        &device,
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await
    .expect("delivered without the limits");
    assert!(resp.success);

    assert!(abuse_fail_open("rate_trust") > before);
    let mut mailbox = h.ctx.queue.lock().await.clone_redis_connection();
    assert_eq!(stream_len(&mut mailbox, &recipient).await, 1);
    del(&mut mailbox, &[format!("delivery:offline:{recipient}")]).await;
}

/// A Sentinel that cannot read its store lets the send through: an abuse-control outage is not a
/// delivery outage. Mutation: refuse in the `Err` arm of `send_message` — the send is refused.
///
/// Aimed at Sentinel's block cache (`sentinel:blocks:`) for the same reason `f1` aims at the limit
/// keys: the connection it runs on is also the one the send authenticated on.
#[tokio::test]
#[serial]
async fn f2_send_message_delivers_when_sentinel_cannot_read_its_store() {
    let proxy = FaultyRedis::start().await;
    let Some(h) = build_harness_on(StealthTokenPolicy::Off, &redis_url(), &proxy.url).await else {
        return;
    };
    let h = with_sentinel(h);
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let before = abuse_fail_open("sentinel");

    proxy.fail_commands_naming("sentinel:blocks:");
    let resp = unary_send(
        &h,
        sender,
        &device,
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await
    .expect("delivered without Sentinel");
    assert!(resp.success);
    assert!(abuse_fail_open("sentinel") > before);

    let mut mailbox = h.ctx.queue.lock().await.clone_redis_connection();
    assert_eq!(stream_len(&mut mailbox, &recipient).await, 1);
    del(&mut mailbox, &[format!("delivery:offline:{recipient}")]).await;
}

/// Dispatch routes to the devices the caller hands over instead of asking the account again. The
/// `Known` arm belongs to the sealed path, which reads that list anyway to answer its sender.
///
/// Proven the hard way rather than by call counting: the pool below cannot answer anything, so a
/// second lookup would come back empty and the message would land in no device stream at all.
///
/// Mutation: make `DeviceTargets::resolve` always look up — the device stream stays empty.
#[tokio::test]
#[serial]
async fn d4_a_device_list_the_caller_read_is_not_asked_for_again() {
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());

    // A pool that points nowhere: every query against it fails, and a failed device lookup is an
    // empty list — the shape that would silently route this message to no mailbox.
    let dead_pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/none")
        .expect("lazy pool");
    let mut ctx = Arc::try_unwrap(h.ctx)
        .ok()
        .expect("sole owner of the context");
    ctx.db_pool = Arc::new(dead_pool);
    let ctx = Arc::new(ctx);

    let message_id = uuid::Uuid::new_v4().to_string();
    let mut envelope = construct_message::MessageEnvelope::new_direct_message(
        message_id.clone(),
        sender.to_string(),
        recipient.to_string(),
        vec![0; 32],
        0,
        vec![7; 16],
        String::new(),
    );
    envelope.recipient_device = Some(device.clone());

    crate::core::dispatch_envelope(
        &ctx,
        envelope,
        None,
        crate::core::DeviceTargets::Known(vec![device.clone()]),
    )
    .await
    .expect("dispatched to the devices the caller already had");

    let mut conn = ctx.queue.lock().await.clone_redis_connection();
    let device_stream = format!("delivery:offline:{recipient}:{device}");
    let landed: i64 = redis::cmd("XLEN")
        .arg(&device_stream)
        .query_async(&mut conn)
        .await
        .unwrap_or(0);
    assert_eq!(
        landed, 1,
        "the named device's mailbox got the copy without a second lookup"
    );
    del(
        &mut conn,
        &[
            device_stream,
            format!("delivery:offline:{recipient}"),
            // The dispatch marks the scoped dedup key after the write; leaving it would make a
            // later run of this test (same recipient? no — a fresh uuid) harmless but untidy.
            construct_queue::MessageDedupKey::new(
                &sender.to_string(),
                &recipient.to_string(),
                Some(&device),
                &message_id,
            )
            .as_str()
            .to_string(),
        ],
    )
    .await;
}

/// The device-revoked read fails while the blocklist read works: a device token is refused, a
/// device-less one is not affected. The arm `a1` could not isolate. Mutation: let the device-revoked
/// `Err` arm fall through — the device token is accepted.
#[tokio::test]
#[serial]
async fn a2_auth_fails_closed_when_only_the_device_revocation_cannot_be_read() {
    use crate::grpc::extract_authed_identity;
    let proxy = FaultyRedis::start().await;
    // Same wiring as `a1`: `FaultyRedis` refuses any command naming the armed fragment, so the
    // device marker's read fails while the mailbox and the token's own key stay readable.
    let Some(h) = build_harness_on(StealthTokenPolicy::Off, &redis_url(), &proxy.url).await else {
        return;
    };
    let bearer = |token: &str| {
        let mut md = tonic::metadata::MetadataMap::new();
        md.insert("authorization", format!("Bearer {token}").parse().unwrap());
        md
    };
    let user = uuid::Uuid::new_v4();
    let device = random_device();
    let (plain, _, _) = h.ctx.auth_manager.create_token(&user).expect("token");
    let (with_device, _, _) = h
        .ctx
        .auth_manager
        .create_token_for_device(&user, Some(&device))
        .expect("device token");
    assert_eq!(
        extract_authed_identity(&bearer(&with_device), &h.ctx).await,
        Some((user, Some(device.clone()))),
        "accepted before the fault, so the refusal below is the fault's"
    );

    proxy.fail_commands_naming("revoked_device:");
    assert_eq!(
        extract_authed_identity(&bearer(&with_device), &h.ctx).await,
        None
    );
    assert_eq!(
        extract_authed_identity(&bearer(&plain), &h.ctx).await,
        Some((user, None))
    );
}

/// The cheapest check every authenticated call makes does not queue behind the mailbox. An open
/// `MessageStream` already keeps its own queue clone for the same reason, and a send holds the mutex
/// across a whole per-device fan-out — so reading the blocklist under it made authentication wait
/// for somebody else's delivery.
///
/// Mutation: read the two markers through `context.queue.lock()` — this call then times out behind
/// the guard held below instead of answering.
#[tokio::test]
#[serial]
async fn a3_auth_does_not_wait_on_the_mailbox_mutex() {
    use crate::grpc::extract_authed_identity;
    let Some(h) = build_harness(StealthTokenPolicy::Off).await else {
        return;
    };
    let user = uuid::Uuid::new_v4();
    let device = random_device();
    let (token, _, _) = h
        .ctx
        .auth_manager
        .create_token_for_device(&user, Some(&device))
        .expect("device token");
    let mut md = tonic::metadata::MetadataMap::new();
    md.insert("authorization", format!("Bearer {token}").parse().unwrap());

    let held = h.ctx.queue.lock().await;
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        extract_authed_identity(&md, &h.ctx),
    )
    .await
    .expect("the blocklist read must not wait for the mailbox mutex");
    drop(held);

    assert_eq!(answer, Some((user, Some(device))));
}

/// The dedup reads fail while the mailbox works: the message is written and both fail-opens are
/// counted, on the fast path and in dispatch. An unreadable dedup key may double-deliver; it must
/// not lose the message. Mutation: return early from either `Err` arm — no entry, or no count.
#[tokio::test]
#[serial]
async fn f3_an_unreadable_dedup_key_does_not_stop_delivery() {
    let proxy = FaultyRedis::start().await;
    let Some(h) = build_harness_on(StealthTokenPolicy::Off, &redis_url(), &proxy.url).await else {
        return;
    };
    let (sender, recipient, device) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), random_device());
    let (send_before, dispatch_before) = (
        abuse_fail_open("send_dedup"),
        abuse_fail_open("dispatch_dedup"),
    );

    proxy.fail_commands_naming("msg:dedup:");
    let resp = unary_send(
        &h,
        sender,
        &device,
        direct_envelope(&sender, &recipient, vec![7; 8], None),
    )
    .await
    .expect("delivered without the dedup read");
    assert!(resp.success);
    assert!(abuse_fail_open("send_dedup") > send_before);
    assert!(abuse_fail_open("dispatch_dedup") > dispatch_before);

    let mut conn = h.ctx.redis_conn.clone();
    assert_eq!(stream_len(&mut conn, &recipient).await, 1);
    del(&mut conn, &[format!("delivery:offline:{recipient}")]).await;
    cleanup_sender(&mut conn, &sender).await;
}

async fn account_with_push_tokens(
    db: &sqlx::PgPool,
    environment: &str,
) -> (uuid::Uuid, Vec<u8>, uuid::Uuid) {
    let user: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO users (id) VALUES (gen_random_uuid()) RETURNING id")
            .fetch_one(db)
            .await
            .expect("account");
    let token = random_bytes32().to_vec();
    sqlx::query(
        "INSERT INTO device_tokens (user_id, device_token_hash, device_token_encrypted, push_environment) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user)
    .bind(random_bytes32().as_slice())
    .bind(&token)
    .bind(environment)
    .execute(db)
    .await
    .expect("device token");
    let voip: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO voip_tokens (user_id, device_id, voip_token_hash, voip_token_encrypted, push_environment) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user)
    .bind(random_device())
    .bind(random_bytes32().as_slice())
    .bind(random_bytes32().as_slice())
    .bind(environment)
    .fetch_one(db)
    .await
    .expect("voip token");
    (user, token, voip)
}

/// One declared environment rejecting widens the row and keeps the token, for both token tables.
/// This was the 2026-08-18 loop, reopened on 2026-10-29 by the wake and VoIP senders. Mutation:
/// `verdict_after_rejection` always deletes — the row is gone.
#[tokio::test]
#[serial]
async fn r1_a_rejection_by_the_only_declared_environment_widens() {
    use crate::notification_core::{settle_rejected_device_token, settle_rejected_voip_token};
    let Some(db) = try_db_pool().await else {
        return;
    };
    let (user, token, voip) = account_with_push_tokens(&db, "sandbox").await;

    let (_, outcome) = settle_rejected_device_token(&db, &token, 1).await;
    outcome.expect("sql");
    let environment: String = sqlx::query_scalar(
        "SELECT push_environment FROM device_tokens WHERE device_token_encrypted = $1",
    )
    .bind(&token)
    .fetch_one(&*db)
    .await
    .expect("the token survives");
    assert_eq!(
        environment,
        construct_config::ApnsEnvironments::both().to_string()
    );

    let (_, outcome) = settle_rejected_voip_token(&db, voip, 1).await;
    outcome.expect("sql");
    let (environment, enabled): (String, bool) =
        sqlx::query_as("SELECT push_environment, enabled FROM voip_tokens WHERE id = $1")
            .bind(voip)
            .fetch_one(&*db)
            .await
            .expect("the VoIP token survives");
    assert_eq!(
        environment,
        construct_config::ApnsEnvironments::both().to_string()
    );
    assert!(enabled);

    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&*db)
        .await;
}

/// Every declared environment rejecting ends the token: deleted, or disabled for VoIP. Mutation:
/// swap the arms in either `settle_rejected_*` — the row stays as it was.
#[tokio::test]
#[serial]
async fn r2_a_rejection_by_every_environment_ends_the_token() {
    use crate::notification_core::{settle_rejected_device_token, settle_rejected_voip_token};
    let Some(db) = try_db_pool().await else {
        return;
    };
    let both = construct_config::ApnsEnvironments::both().to_string();
    let (user, token, voip) = account_with_push_tokens(&db, &both).await;

    let (_, outcome) = settle_rejected_device_token(&db, &token, 2).await;
    outcome.expect("sql");
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_tokens WHERE device_token_encrypted = $1")
            .bind(&token)
            .fetch_one(&*db)
            .await
            .unwrap();
    assert_eq!(left, 0);

    let (_, outcome) = settle_rejected_voip_token(&db, voip, 2).await;
    outcome.expect("sql");
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM voip_tokens WHERE id = $1")
        .bind(voip)
        .fetch_one(&*db)
        .await
        .expect("disabled, not deleted");
    assert!(!enabled);

    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user)
        .execute(&*db)
        .await;
}
