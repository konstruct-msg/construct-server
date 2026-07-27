#![allow(dead_code)]

use chrono::Utc;
use construct_auth::AuthManager;
use construct_config::{
    ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
    DeepLinksConfig, FederationConfig, LoggingConfig, MediaConfig, MicroservicesConfig, MtlsConfig,
    RedisChannels, RedisKeyPrefixes, SecurityConfig,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use uuid::Uuid;

use crate::service::GroupServiceImpl;

/// Shared PASETO AuthManager for group-service unit tests (ephemeral keypair).
pub(crate) static TEST_AUTH: LazyLock<Arc<AuthManager>> = LazyLock::new(|| {
    let kp = ed25519_compact::KeyPair::generate();
    let priv_pem = String::from_utf8(kp.sk.to_pem().as_bytes().to_vec()).expect("priv pem");
    let pub_pem = String::from_utf8(kp.pk.to_pem().as_bytes().to_vec()).expect("pub pem");
    let config = test_auth_config(priv_pem, pub_pem);
    Arc::new(AuthManager::new(&config).expect("test AuthManager"))
});

fn test_auth_config(paseto_priv: String, paseto_pub: String) -> Config {
    Config {
        database_url: String::new(),
        redis_url: String::new(),
        jwt_secret: "unused".to_string(),
        jwt_private_key: None,
        jwt_public_key: None,
        paseto_private_key: Some(paseto_priv),
        paseto_public_key: Some(paseto_pub),
        paseto_public_key_previous: Vec::new(),
        token_issue_format: "paseto".to_string(),
        port: 8080,
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
        delivery_queue_prefix: "delivery:".to_string(),
        delivery_poll_interval_ms: 100,
        grpc_keepalive_interval_secs: 45,
        grpc_keepalive_timeout_secs: 5,
        rust_log: "error".to_string(),
        logging: LoggingConfig {
            enable_message_metadata: false,
            enable_user_identifiers: false,
            hash_salt: "test-salt".to_string(),
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
            max_connections: 1,
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
        messaging: construct_config::MessagingConfig::default(),
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

/// Build a GroupServiceImpl for unit tests with the shared TEST_AUTH manager.
pub(crate) async fn make_test_service(db: Arc<sqlx::PgPool>) -> GroupServiceImpl {
    GroupServiceImpl {
        db,
        hub: crate::service::GroupHub::new(),
        notification_client: None,
        redis: get_test_redis().await,
        auth: TEST_AUTH.clone(),
    }
}

pub(crate) async fn get_test_redis() -> redis::aio::ConnectionManager {
    let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(url).expect("Invalid REDIS_URL");
    client
        .get_connection_manager()
        .await
        .expect("Failed to connect to Redis")
}

pub(crate) async fn get_test_db() -> Arc<sqlx::PgPool> {
    let mut db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    if (db_url.contains("localhost") || db_url.contains("127.0.0.1"))
        && !db_url.contains("sslmode=")
    {
        db_url.push_str(if db_url.contains('?') {
            "&sslmode=disable"
        } else {
            "?sslmode=disable"
        });
    }
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Failed to connect");
    sqlx::migrate!("../shared/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    Arc::new(pool)
}

pub(crate) async fn create_test_device(db: &sqlx::PgPool) -> (Uuid, String, SigningKey) {
    let user_id = Uuid::new_v4();
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    sqlx::query(
        "INSERT INTO users (id, primary_device_id) VALUES ($1, NULL) ON CONFLICT (id) DO NOTHING",
    )
    .bind(user_id)
    .execute(db)
    .await
    .expect("Failed to insert test user");

    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    let device_id = hex::encode(&hash[..16]);
    let identity_public = verifying_key.as_bytes().to_vec();

    sqlx::query(
        r#"
        INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                             identity_public, signed_prekey_public, registered_at)
        VALUES ($1, $2, 'test.local', $3, $4, $5, $6)
        ON CONFLICT (device_id) DO UPDATE SET user_id = EXCLUDED.user_id
        "#,
    )
    .bind(&device_id)
    .bind(user_id)
    .bind(verifying_key.as_bytes().to_vec())
    .bind(identity_public)
    .bind(vec![0u8; 32])
    .bind(Utc::now())
    .execute(db)
    .await
    .expect("Failed to insert test device");

    sqlx::query(
        "UPDATE users SET primary_device_id = COALESCE(primary_device_id, $2) WHERE id = $1",
    )
    .bind(user_id)
    .bind(&device_id)
    .execute(db)
    .await
    .expect("Failed to set primary device");

    (user_id, device_id, signing_key)
}

pub(crate) async fn create_test_group_in_db(db: &sqlx::PgPool, device_id: &str) -> Uuid {
    let group_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO mls_groups
            (group_id, epoch, ratchet_tree, encrypted_group_context,
             max_members, message_retention_days, threads_enabled, created_at, last_sequence)
        VALUES ($1, 0, $2, $3, 2048, 90, false, $4, 0)
        "#,
    )
    .bind(group_id)
    .bind(vec![0u8; 32])
    .bind(vec![0u8; 32])
    .bind(now)
    .execute(db)
    .await
    .expect("Failed to insert test group");

    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 0, $3)",
    )
    .bind(group_id)
    .bind(device_id)
    .bind(now)
    .execute(db)
    .await
    .expect("Failed to add creator to group");

    sqlx::query(
        "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, true, $3)",
    )
    .bind(group_id)
    .bind(device_id)
    .bind(now)
    .execute(db)
    .await
    .expect("Failed to add creator as admin");

    group_id
}

/// Authenticated metadata: Bearer token + matching x-user-id / x-device-id
/// (mirrors real client gRPC metadata).
pub(crate) fn create_metadata(user_id: &Uuid, device_id: &str) -> tonic::metadata::MetadataMap {
    let (token, _, _) = TEST_AUTH
        .create_token_for_device(user_id, Some(device_id))
        .expect("test token");
    let mut meta = tonic::metadata::MetadataMap::new();
    meta.insert(
        "authorization",
        format!("Bearer {token}").parse().expect("auth header"),
    );
    meta.insert("x-user-id", user_id.to_string().parse().unwrap());
    meta.insert("x-device-id", device_id.parse().unwrap());
    meta
}

/// Metadata with only spoofable headers (no Bearer) — must be rejected.
pub(crate) fn create_metadata_header_only(
    user_id: &Uuid,
    device_id: &str,
) -> tonic::metadata::MetadataMap {
    let mut meta = tonic::metadata::MetadataMap::new();
    meta.insert("x-user-id", user_id.to_string().parse().unwrap());
    meta.insert("x-device-id", device_id.parse().unwrap());
    meta
}

pub(crate) async fn publish_test_key_package(
    db: &sqlx::PgPool,
    user_id: Uuid,
    device_id: &str,
) -> Vec<u8> {
    let kp = format!("test-kp:{user_id}:{device_id}:{}", Uuid::new_v4()).into_bytes();
    let kp_ref = sha256_bytes(&kp);
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO group_key_packages
            (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(&kp)
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::days(30))
    .execute(db)
    .await
    .expect("Failed to publish test KeyPackage");

    kp_ref
}

pub(crate) fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
