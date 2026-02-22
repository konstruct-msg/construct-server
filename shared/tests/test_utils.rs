// ============================================================================
// Test Utilities for Microservices
// ============================================================================
//
// Provides test infrastructure for REST API integration tests.
// Spawns individual microservices (auth, user, messaging, notification)
// with isolated test databases.
//
// ============================================================================

#![allow(dead_code)]

use argon2::{
    Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString},
};
use axum::Router;
use axum::extract::State;
use axum::routing::{get, patch, post, put};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_config::Config;
use construct_server_shared::{
    apns::{ApnsClient, DeviceTokenEncryption},
    auth::AuthManager,
    auth_service::{AuthServiceContext, handlers as auth_handlers},
    kafka::MessageProducer,
    messaging_service::{MessagingServiceContext, handlers as messaging_handlers},
    notification_service::{NotificationServiceContext, handlers as notification_handlers},
    queue::MessageQueue,
    routes::health,
    user_service::{UserServiceContext, handlers as user_handlers},
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Test application with all microservices
pub struct TestApp {
    /// Legacy: points to auth service for backward compatibility
    pub address: String,
    pub auth_address: String,
    pub user_address: String,
    pub messaging_address: String,
    pub notification_address: String,
    pub db_pool: PgPool,
    pub config: Arc<Config>,
}

/// Single service test app (for focused tests)
pub struct SingleServiceApp {
    pub address: String,
    pub db_pool: PgPool,
    pub config: Arc<Config>,
}

/// Create test config from .env.test
async fn create_test_config(db_name: &str) -> Config {
    // CRITICAL: Remove Kafka SASL credentials BEFORE loading any .env file
    // dotenvy::dotenv() in Config::from_env() won't override existing env vars
    // SAFETY: Tests run single-threaded (--test-threads=1) so this is safe
    unsafe {
        std::env::remove_var("KAFKA_SASL_MECHANISM");
        std::env::remove_var("KAFKA_SASL_USERNAME");
        std::env::remove_var("KAFKA_SASL_PASSWORD");
    }

    // Load .env.test with override - this replaces any existing env vars
    // Try multiple paths since tests may run from different directories
    let _ = dotenvy::from_filename_override(".env.test")
        .or_else(|_| dotenvy::from_filename_override("../.env.test"))
        .or_else(|_| dotenvy::from_filename_override("../../.env.test"));

    // Read JWT keys directly from files - try multiple paths for workspace compatibility
    let private_key = try_read_key_file(&[
        "prkeys/jwt_private_key.pem",
        "../prkeys/jwt_private_key.pem",
    ])
    .expect("Failed to read JWT private key file");
    let public_key =
        try_read_key_file(&["prkeys/jwt_public_key.pem", "../prkeys/jwt_public_key.pem"])
            .expect("Failed to read JWT public key file");

    // Set env vars before Config::from_env() reads them
    // SAFETY: Tests run single-threaded (--test-threads=1) so this is safe
    unsafe {
        std::env::set_var("JWT_PRIVATE_KEY", &private_key);
        std::env::set_var("JWT_PUBLIC_KEY", &public_key);
        // Low PoW difficulty for fast tests (1 leading zero bit = instant)
        std::env::set_var("POW_DIFFICULTY", "1");
        // Disable rate limiting for tests (unless already set by specific test)
        if std::env::var("MAX_POW_CHALLENGES_PER_HOUR").is_err() {
            std::env::set_var("MAX_POW_CHALLENGES_PER_HOUR", "0");
        }
        if std::env::var("MAX_REGISTRATIONS_PER_HOUR").is_err() {
            std::env::set_var("MAX_REGISTRATIONS_PER_HOUR", "0");
        }
    }

    let mut config = Config::from_env().expect("Failed to read base config from .env.test");

    // Override database for test isolation (unique DB per test)
    // Use DATABASE_URL from env or fallback to local dev credentials
    let base_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://construct:construct_dev_password@localhost:5432/postgres".to_string()
    });

    config.database_url = if let Some(pos) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..pos], db_name)
    } else {
        format!("{}/{}", base_url, db_name)
    };

    config
}

/// Try to read a key file from multiple possible paths
fn try_read_key_file(paths: &[&str]) -> Result<String, std::io::Error> {
    for path in paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return Ok(content);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Key file not found in any of: {:?}", paths),
    ))
}

/// Create test database
async fn setup_test_database(db_name: &str) -> PgPool {
    // Load .env.test so DATABASE_URL is available before DB bootstrap
    let _ = dotenvy::from_filename_override(".env.test")
        .or_else(|_| dotenvy::from_filename_override("../.env.test"))
        .or_else(|_| dotenvy::from_filename_override("../../.env.test"));

    // Try DATABASE_URL first, then common local test defaults
    let mut candidates = vec![];
    if let Ok(url) = std::env::var("DATABASE_URL") {
        candidates.push(url);
    }
    candidates.push(
        "postgres://construct_test:construct_test_password@localhost:5433/postgres".to_string(),
    );
    candidates.push("postgres://postgres:postgres@localhost:5432/postgres".to_string());
    candidates
        .push("postgres://construct:construct_dev_password@localhost:5432/postgres".to_string());

    let mut connection = None;
    let mut base_url = None;
    let mut last_err = None;
    for candidate in candidates {
        let candidate_postgres = if let Some(pos) = candidate.rfind('/') {
            format!("{}/postgres", &candidate[..pos])
        } else {
            candidate.clone()
        };
        // Prefer IPv4 loopback; some local setups listen only on IPv4 and reject ::1
        let candidate_postgres = candidate_postgres.replace("@localhost:", "@127.0.0.1:");
        match PgConnection::connect(&candidate_postgres).await {
            Ok(conn) => {
                connection = Some(conn);
                base_url = Some(candidate_postgres);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let mut connection = connection.unwrap_or_else(|| {
        panic!(
            "Failed to connect to Postgres with all known test URLs: {:?}",
            last_err
        )
    });
    let base_url = base_url.expect("Base DB URL should be set when Postgres connection succeeds");

    // Keep config/database creation on the same working URL for this test process
    unsafe {
        std::env::set_var("DATABASE_URL", &base_url);
    }

    // Drop if exists and create fresh
    let _ = connection
        .execute(format!(r#"DROP DATABASE IF EXISTS "{}";"#, db_name).as_str())
        .await;

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database");

    // Build database URL using same credentials
    let db_url = if let Some(pos) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..pos], db_name)
    } else {
        format!("{}/{}", base_url, db_name)
    };

    let db_pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test database");

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Failed to run migrations");

    db_pool
}

/// Cleanup rate limiting keys from Redis
pub async fn cleanup_rate_limits(redis_url: &str) {
    use redis::AsyncCommands;

    let client = redis::Client::open(redis_url).ok();
    if let Some(client) = client
        && let Ok(mut conn) = client.get_multiplexed_async_connection().await
    {
        let patterns = vec![
            "rate:*",
            "rate:login:*",
            "rate:register:*",
            "rate:combined:*",
        ];

        for pattern in patterns {
            let keys: Vec<String> = conn.keys(pattern).await.unwrap_or_default();
            if !keys.is_empty() {
                let _: Result<(), _> = conn.del(&keys).await;
            }
        }
    }
}

/// Spawn auth service
async fn spawn_auth_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));

    let context = Arc::new(AuthServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
        key_management: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(|State(ctx): State<Arc<AuthServiceContext>>| async move {
                let app_ctx = Arc::new(ctx.to_app_context());
                health::readiness_check(State(app_ctx)).await
            }),
        )
        .route("/health/live", get(health::liveness_check))
        // Passwordless device-based authentication endpoints
        .route(
            "/api/v1/auth/challenge",
            get(auth_handlers::get_pow_challenge),
        )
        .route(
            "/api/v1/auth/register-device",
            post(auth_handlers::register_device),
        )
        .route(
            "/api/v1/auth/device",
            post(auth_handlers::authenticate_device),
        )
        .route("/api/v1/auth/refresh", post(auth_handlers::refresh_token))
        .route("/api/v1/auth/logout", post(auth_handlers::logout))
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn user service
async fn spawn_user_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));

    let context = Arc::new(UserServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(|State(ctx): State<Arc<UserServiceContext>>| async move {
                let app_ctx = Arc::new(ctx.to_app_context());
                health::readiness_check(State(app_ctx)).await
            }),
        )
        .route("/health/live", get(health::liveness_check))
        .route("/api/v1/account", get(user_handlers::get_account))
        .route("/api/v1/account", put(user_handlers::update_account))
        // Note: DELETE /api/v1/account removed - use device-signed deletion
        .route("/api/v1/keys/upload", post(user_handlers::upload_keys))
        .route(
            "/api/v1/users/:user_id/public-key",
            get(user_handlers::get_public_key_bundle),
        )
        .route(
            "/api/v1/users/me/public-key",
            patch(user_handlers::update_verifying_key),
        )
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn messaging service
async fn spawn_messaging_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));
    let kafka_producer =
        Arc::new(MessageProducer::new(&config.kafka).expect("Failed to create kafka producer"));
    let apns_client =
        Arc::new(ApnsClient::new(config.apns.clone()).expect("Failed to create APNs client"));
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .expect("Failed to create token encryption"),
    );

    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(
                |State(ctx): State<Arc<MessagingServiceContext>>| async move {
                    let app_ctx = Arc::new(ctx.to_app_context());
                    health::readiness_check(State(app_ctx)).await
                },
            ),
        )
        .route("/health/live", get(health::liveness_check))
        .route("/api/v1/messages", post(messaging_handlers::send_message))
        .route("/api/v1/messages", get(messaging_handlers::get_messages))
        .route(
            "/api/v1/messages/confirm",
            post(messaging_handlers::confirm_message),
        )
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn notification service
async fn spawn_notification_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("127.0.0.1:{}", port);

    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .expect("Failed to create queue"),
    ));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("Failed to create auth manager"));
    let apns_client =
        Arc::new(ApnsClient::new(config.apns.clone()).expect("Failed to create APNs client"));
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .expect("Failed to create token encryption"),
    );

    let context = Arc::new(NotificationServiceContext {
        db_pool,
        queue,
        auth_manager,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(
                |State(ctx): State<Arc<NotificationServiceContext>>| async move {
                    let app_ctx = Arc::new(ctx.to_app_context());
                    health::readiness_check(State(app_ctx)).await
                },
            ),
        )
        .route("/health/live", get(health::liveness_check))
        .route(
            "/api/v1/notifications/register-device",
            post(notification_handlers::register_device),
        )
        .route(
            "/api/v1/notifications/unregister-device",
            post(notification_handlers::unregister_device),
        )
        .route(
            "/api/v1/notifications/preferences",
            put(notification_handlers::update_preferences),
        )
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Spawn all microservices for full integration tests
pub async fn spawn_app() -> TestApp {
    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let auth_address = spawn_auth_service(config.clone(), db_pool_arc.clone()).await;
    let user_address = spawn_user_service(config.clone(), db_pool_arc.clone()).await;
    let messaging_address = spawn_messaging_service(config.clone(), db_pool_arc.clone()).await;
    let notification_address =
        spawn_notification_service(config.clone(), db_pool_arc.clone()).await;

    // Give services time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    TestApp {
        address: auth_address.clone(), // Legacy compatibility
        auth_address,
        user_address,
        messaging_address,
        notification_address,
        db_pool,
        config,
    }
}

/// Spawn all microservices with rate limiting enabled (for rate limit tests)
pub async fn spawn_app_with_rate_limiting() -> TestApp {
    // Temporarily enable rate limiting
    unsafe {
        std::env::set_var("MAX_POW_CHALLENGES_PER_HOUR", "10");
        std::env::set_var("MAX_REGISTRATIONS_PER_HOUR", "5");
    }

    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let auth_address = spawn_auth_service(config.clone(), db_pool_arc.clone()).await;
    let user_address = spawn_user_service(config.clone(), db_pool_arc.clone()).await;
    let messaging_address = spawn_messaging_service(config.clone(), db_pool_arc.clone()).await;
    let notification_address =
        spawn_notification_service(config.clone(), db_pool_arc.clone()).await;

    // Give services time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Restore default (disabled)
    unsafe {
        std::env::set_var("MAX_POW_CHALLENGES_PER_HOUR", "0");
        std::env::set_var("MAX_REGISTRATIONS_PER_HOUR", "0");
    }

    TestApp {
        address: auth_address.clone(), // Legacy compatibility
        auth_address,
        user_address,
        messaging_address,
        notification_address,
        db_pool,
        config,
    }
}

/// Spawn only auth service (for auth-focused tests)
pub async fn spawn_auth_app() -> SingleServiceApp {
    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let address = spawn_auth_service(config.clone(), db_pool_arc).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    SingleServiceApp {
        address,
        db_pool,
        config,
    }
}

/// Spawn only user service (for user-focused tests)
pub async fn spawn_user_app() -> SingleServiceApp {
    let db_name = format!(
        "construct_test_{}",
        Uuid::new_v4().to_string().replace("-", "_")
    );
    let db_pool = setup_test_database(&db_name).await;
    let config = Arc::new(create_test_config(&db_name).await);
    let db_pool_arc = Arc::new(db_pool.clone());

    let address = spawn_user_service(config.clone(), db_pool_arc).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    SingleServiceApp {
        address,
        db_pool,
        config,
    }
}

impl TestApp {
    /// Get base URL for auth service
    pub fn auth_url(&self) -> String {
        format!("http://{}", self.auth_address)
    }

    /// Get base URL for user service
    pub fn user_url(&self) -> String {
        format!("http://{}", self.user_address)
    }

    /// Get base URL for messaging service
    pub fn messaging_url(&self) -> String {
        format!("http://{}", self.messaging_address)
    }

    /// Get base URL for notification service
    pub fn notification_url(&self) -> String {
        format!("http://{}", self.notification_address)
    }
}

impl SingleServiceApp {
    /// Get base URL
    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

// ============================================================================
// Passwordless Registration Helper
// ============================================================================

/// PoW challenge response from server
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge: String,
    difficulty: u32,
    expires_at: i64,
}

/// Device registration response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceResponse {
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Salt prefix for PoW v2 (challenge-based salt)
const POW_SALT_PREFIX: &str = "kpow2:";

/// Argon2id parameters (MUST match server)
const MEMORY_COST_KIB: u32 = 32 * 1024; // 32 MB
const TIME_COST: u32 = 2; // 2 iterations
const PARALLELISM: u32 = 1; // 1 thread
const HASH_LENGTH: usize = 32; // 32 bytes

/// Derive a unique salt from the challenge string.
/// Format: "kpow2:" + first 16 characters of challenge
fn derive_pow_salt(challenge: &str) -> String {
    let challenge_prefix = &challenge[..std::cmp::min(16, challenge.len())];
    format!("{}{}", POW_SALT_PREFIX, challenge_prefix)
}

/// Solve PoW challenge (find nonce that produces hash with required leading zero bits)
fn solve_pow(challenge: &str, difficulty: u32) -> (u64, String) {
    let params = ParamsBuilder::new()
        .m_cost(MEMORY_COST_KIB)
        .t_cost(TIME_COST)
        .p_cost(PARALLELISM)
        .output_len(HASH_LENGTH)
        .build()
        .expect("Failed to build Argon2 params");

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let derived_salt = derive_pow_salt(challenge);
    let salt = SaltString::encode_b64(derived_salt.as_bytes()).expect("Failed to encode salt");

    for nonce in 0u64.. {
        let input = format!("{}{}", challenge, nonce);

        if let Ok(hash) = argon2.hash_password(input.as_bytes(), &salt)
            && let Some(h) = hash.hash
        {
            let hash_bytes = h.as_bytes();
            let leading_zeros = count_leading_zero_bits(hash_bytes);

            if leading_zeros >= difficulty {
                return (nonce, hex::encode(hash_bytes));
            }
        }
    }

    unreachable!("PoW should always find a solution")
}

/// Count leading zero bits in hash
fn count_leading_zero_bits(hash_bytes: &[u8]) -> u32 {
    let mut count = 0;
    for byte in hash_bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Register a new user using passwordless device-based authentication.
///
/// This function:
/// 1. Generates Ed25519 + X25519 key pairs
/// 2. Gets PoW challenge from server
/// 3. Solves PoW (fast with difficulty=1 in tests)
/// 4. Registers device with server
/// 5. Returns (user_id, access_token)
pub async fn register_user_passwordless(
    client: &reqwest::Client,
    auth_address: &str,
    username: Option<&str>,
) -> (String, String) {
    // 1. Generate Ed25519 signing key (for authentication)
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // 2. Generate X25519 key pair (for E2EE identity)
    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    // 3. Generate signed prekey (X25519 for Double Ratchet)
    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    // 3.5. Generate signedPrekeySignature for X3DH
    // Signature over: prologue || signed_prekey_public
    // Prologue = "KonstruktX3DH-v1" || suite_id (2 bytes BE, 0x0001 for Curve25519+Ed25519)
    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]); // suite_id = 1 (Curve25519+Ed25519)
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    // 4. Compute device_id = SHA256(identity_public)[0..16] as hex
    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    // 5. Get PoW challenge from server
    let challenge_url = format!("http://{}/api/v1/auth/challenge", auth_address);
    let challenge_response = client
        .get(&challenge_url)
        .send()
        .await
        .expect("Failed to get PoW challenge");

    assert_eq!(
        challenge_response.status(),
        reqwest::StatusCode::OK,
        "Challenge request failed: {:?}",
        challenge_response.text().await
    );

    let challenge: ChallengeResponse = client
        .get(&challenge_url)
        .send()
        .await
        .expect("Failed to get PoW challenge")
        .json()
        .await
        .expect("Failed to parse challenge response");

    // 6. Solve PoW (with difficulty=1 in tests, this is instant)
    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    // 7. Build registration request
    let register_request = serde_json::json!({
        "username": username,
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    // 8. Register device
    let register_url = format!("http://{}/api/v1/auth/register-device", auth_address);
    let register_response = client
        .post(&register_url)
        .json(&register_request)
        .send()
        .await
        .expect("Failed to send registration request");

    let status = register_response.status();
    if status != reqwest::StatusCode::CREATED {
        let error_text = register_response.text().await.unwrap();
        panic!("Registration failed (status {}): {}", status, error_text);
    }

    let auth_response: RegisterDeviceResponse = register_response
        .json()
        .await
        .expect("Failed to parse registration response");

    (auth_response.user_id, auth_response.access_token)
}

// ============================================================================
// Protocol Compliance Test Helpers
// ============================================================================

/// Simple test user structure for protocol compliance tests
pub struct TestUser {
    pub user_id: String,
    pub access_token: String,
}

/// Register a test user with default settings
/// Returns TestUser with user_id and access_token
pub async fn register_test_user(ctx: &TestApp, username: &str) -> TestUser {
    let client = reqwest::Client::new();
    let (user_id, access_token) =
        register_user_passwordless(&client, &ctx.auth_address, Some(username)).await;

    TestUser {
        user_id,
        access_token,
    }
}

/// Send a test message from sender to recipient
/// Returns the response JSON
pub async fn send_test_message(
    ctx: &TestApp,
    sender: &TestUser,
    recipient_id: &str,
    content: &str,
) -> serde_json::Value {
    let client = reqwest::Client::new();

    // Create a dummy encrypted message
    // In real tests, this would use actual E2EE
    use base64::{Engine as _, engine::general_purpose};
    let request_body = serde_json::json!({
        "recipientId": recipient_id,
        "ciphertext": general_purpose::STANDARD.encode(content.as_bytes()),
        "header": {
            "ratchetPublicKey": general_purpose::STANDARD.encode([0u8; 32]),
            "previousChainLength": 0,
            "messageNumber": 0,
        },
        "suiteId": 1,
        "timestamp": chrono::Utc::now().timestamp(),
    });

    let response = client
        .post(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", sender.access_token))
        .json(&request_body)
        .send()
        .await
        .expect("Failed to send message");

    response
        .json()
        .await
        .expect("Failed to parse send response")
}

/// Get all messages for a user
/// Returns array of message JSONs
pub async fn get_all_messages(ctx: &TestApp, user: &TestUser) -> Vec<serde_json::Value> {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .query(&[("limit", "100")])
        .send()
        .await
        .expect("Failed to get messages");

    let body: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse messages response");

    body["messages"].as_array().unwrap_or(&vec![]).clone()
}
