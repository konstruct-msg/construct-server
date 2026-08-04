//! Sealed-sender server matrix — Phase 1 (unit + Redis/Postgres integration).
//!
//! Run against local data plane:
//! ```text
//! docker-compose -f ops/docker-compose.dev.yml up -d
//! cargo test -p messaging-service sealed_matrix -- --nocapture
//! ```
//!
//! Tests skip cleanly when Redis/Postgres are unavailable (no hard CI fail without infra).
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

async fn try_redis() -> Option<redis::aio::ConnectionManager> {
    let client = redis::Client::open(redis_url()).ok()?;
    redis::aio::ConnectionManager::new(client).await.ok()
}

async fn try_db_pool() -> Option<Arc<DbPool>> {
    match DbPool::connect(&database_url()).await {
        Ok(pool) => {
            // Best-effort migrations so device lookup / delivery_pending exist.
            // Failure is non-fatal: sealed path degrades device fan-out to user stream.
            let _ = sqlx::migrate!("../shared/migrations").run(&pool).await;
            Some(Arc::new(pool))
        }
        Err(e) => {
            eprintln!("sealed_matrix: postgres unavailable ({e}) — skipping");
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
        jwt_secret: String::new(),
        jwt_private_key: None,
        jwt_public_key: None,
        paseto_private_key: Some(paseto_priv.to_string()),
        paseto_public_key: Some(paseto_pub.to_string()),
        paseto_public_key_previous: Vec::new(),
        token_issue_format: "paseto".to_string(),
        port: 50053,
        bind_address: "127.0.0.1".to_string(),
        health_port: 8081,
        heartbeat_interval_secs: 60,
        server_registry_ttl_secs: 120,
        message_ttl_days: 7,
        dedup_safety_margin_hours: 2,
        access_token_ttl_hours: 24,
        session_ttl_days: 30,
        refresh_token_ttl_days: 7,
        jwt_issuer: "construct-test".to_string(),
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
    let redis_conn = match try_redis().await {
        Some(c) => c,
        None => {
            eprintln!(
                "sealed_matrix: redis unavailable at {} — skipping",
                redis_url()
            );
            return None;
        }
    };
    let db_pool = try_db_pool().await?;

    let (priv_pem, pub_pem) = make_ed25519_pems();
    let config = Arc::new(make_config(
        &redis_url(),
        &database_url(),
        &priv_pem,
        &pub_pem,
        policy,
    ));

    let message_queue = MessageQueue::new(&config)
        .await
        .expect("MessageQueue::new with live redis");
    let redis_from_queue = message_queue.clone_redis_connection();
    let _ = redis_conn; // queue has its own manager; keep both alive
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
        redis_conn: redis_from_queue,
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

fn seal_token_for_server(token: &[u8; 32], server_secret: &X25519StaticSecret) -> Vec<u8> {
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

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
    let nonce_bytes = random_bytes32();
    let aead_nonce = Nonce::from_slice(&nonce_bytes[..12]);
    let ciphertext = cipher.encrypt(aead_nonce, token.as_slice()).unwrap();

    let mut sealed = Vec::with_capacity(32 + 12 + ciphertext.len());
    sealed.extend_from_slice(ephemeral_pub.as_bytes());
    sealed.extend_from_slice(&nonce_bytes[..12]);
    sealed.extend_from_slice(&ciphertext);
    sealed
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

    // Queue API agrees
    {
        let mut q = h.ctx.queue.lock().await;
        let mapped = q
            .get_message_sender(&resp.message_id)
            .await
            .expect("get_message_sender");
        assert!(
            mapped.is_none(),
            "get_message_sender must be None for sealed (got {mapped:?})"
        );
    }

    // delivery_pending only written when sender non-empty; give spawn a tick then check
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    if let Ok(row) = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM delivery_pending WHERE sender_id <> '' AND message_hash IS NOT NULL",
    )
    .fetch_one(&*h.ctx.db_pool)
    .await
    {
        // We cannot easily compute message_hash without salt path; just ensure table is queryable.
        let _ = row;
    }
    // Targeted: no row for this message's routing hash
    let salt = &h.ctx.config.logging.hash_salt;
    let message_hash = {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(salt.as_bytes()).expect("hmac accepts any key length");
        mac.update(resp.message_id.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    match sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM delivery_pending WHERE message_hash = $1",
    )
    .bind(&message_hash)
    .fetch_one(&*h.ctx.db_pool)
    .await
    {
        Ok(count) => assert_eq!(
            count, 0,
            "I5: delivery_pending must not record sealed messages"
        ),
        Err(e) => {
            // Table missing if migrations failed — non-fatal for matrix when only Redis is up.
            eprintln!("sealed_matrix: delivery_pending check skipped ({e})");
        }
    }

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
    let result = redeem_token_checked(&mut conn, Some(&[1u8; 32]), None, &[], &[]).await;
    // server_secret None → NotConfigured takes precedence over empty token in redeem_token_checked
    assert!(
        matches!(
            result,
            TokenRedeemResult::NotConfigured | TokenRedeemResult::MissingToken
        ),
        "got {result:?}"
    );
}
