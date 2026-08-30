// ============================================================================
// Test Utilities for Microservices
// ============================================================================
//
// Spawns lightweight HTTP health stubs + messaging gRPC for integration tests.
// Client REST APIs were removed — product auth is gRPC AuthService.
//
// ============================================================================

#![allow(dead_code)]

use argon2::{
    Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString},
};
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use construct_config::{ApnsEnvironment, Config};
use construct_context::AppContext;
use construct_error::AppError;
use construct_server_shared::{
    apns::{ApnsClient, DeviceTokenEncryption},
    auth::AuthManager,
    auth_service::AuthServiceContext,
    health,
    message::types::{MessageEnvelope, ProtoEnvelopeContext},
    notification_service::NotificationServiceContext,
    queue::MessageQueue,
    shared::proto::services::v1::{
        self as proto_svc,
        auth_service_client::AuthServiceClient,
        auth_service_server::{AuthService as GrpcAuthService, AuthServiceServer},
        messaging_service_server::{
            MessagingService as GrpcMessagingService, MessagingServiceServer,
        },
    },
    user_service::UserServiceContext,
};
use construct_utils::log_safe_id;
use ed25519_dalek::{Signer, SigningKey};
use futures_core::Stream;
use hmac::{Hmac, Mac, digest::KeyInit};
use rand_core::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::pin::Pin;
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};
use tonic::{Request as GrpcRequest, Response as GrpcResponse, Status as GrpcStatus};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Test application with all microservices
pub struct TestApp {
    /// Legacy: points to auth HTTP for backward compatibility
    pub address: String,
    pub auth_address: String,
    /// gRPC AuthService (GetPowChallenge / RegisterDevice) for client registration
    pub grpc_auth_address: String,
    pub user_address: String,
    pub messaging_address: String,
    pub grpc_messaging_address: String,
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

    // Load .env.test as defaults — CI env vars take precedence (not overridden)
    // Try multiple paths since tests may run from different directories
    let _ = dotenvy::from_filename(".env.test")
        .or_else(|_| dotenvy::from_filename("../.env.test"))
        .or_else(|_| dotenvy::from_filename("../../.env.test"));

    // Generate a fresh Ed25519 keypair on the fly — no PEM files committed to repo
    // or required from disk. This is the canonical PASETO v4.public test setup.
    let kp = ed25519_compact::KeyPair::generate();
    let priv_pem_bytes = kp.sk.to_pem();
    let pub_pem_bytes = kp.pk.to_pem();
    let paseto_private_key =
        String::from_utf8(priv_pem_bytes.as_bytes().to_vec()).expect("Ed25519 private PEM");
    let paseto_public_key =
        String::from_utf8(pub_pem_bytes.as_bytes().to_vec()).expect("Ed25519 public PEM");

    // Set env vars before Config::from_env() reads them
    // SAFETY: Tests run single-threaded (--test-threads=1) so this is safe
    unsafe {
        // PASETO v4.public is the primary test path — generate inline.
        std::env::set_var("PASETO_PRIVATE_KEY", &paseto_private_key);
        std::env::set_var("PASETO_PUBLIC_KEY", &paseto_public_key);
        std::env::set_var("TOKEN_ISSUE_FORMAT", "paseto");
        // INSTANCE_DOMAIN is required by FederationConfig::from_env (no silent default);
        // set explicitly so the test doesn't depend on a local `.env` being present.
        std::env::set_var("INSTANCE_DOMAIN", "test.local");

        // Set valid throwaway values so the secret-hygiene fail-fast in Config::from_env
        // doesn't inherit a MALFORMED value from an ambient `.env`/CI (e.g. a hex-encoded
        // SERVER_SIGNING_KEY → 48 bytes). All-zeros is a valid Ed25519 seed / issuer
        // scalar; federation is disabled in tests, so these are never used cryptographically.
        std::env::set_var(
            "SERVER_SIGNING_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        std::env::set_var("TOKEN_ISSUER_KEY", "0".repeat(64));
        // APNS device-token encryption key: 64-hex (32 bytes). Overridden here so the
        // fail-fast doesn't inherit a malformed ambient value from `.env.test`; matches
        // the all-zeros value CI already sets in the workflow. Unused in these tests.
        std::env::set_var("APNS_DEVICE_TOKEN_ENCRYPTION_KEY", "0".repeat(64));

        // Override legacy JWT env vars inherited from `.env` (or `.env.test`).
        // Set to empty strings rather than `remove_var`, because `Config::from_env()`
        // below calls `dotenvy::dotenv()` which re-sets unset vars from `.env`.
        // `dotenvy` does not override existing vars, so setting them to "" here
        // prevents the stale `prkeys/jwt_public_key.pem` path from being restored.
        // Empty string is treated as "no key" by `load_jwt_*_key()` (via the
        // `is_valid_key` trim check), yielding `None` — which is what we want:
        // tests use PASETO only, legacy JWT verify-disabled.
        std::env::set_var("JWT_PRIVATE_KEY", "");
        std::env::set_var("JWT_PUBLIC_KEY", "");

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
    // Load .env.test as defaults — CI env vars take precedence (not overridden)
    let _ = dotenvy::from_filename(".env.test")
        .or_else(|_| dotenvy::from_filename("../.env.test"))
        .or_else(|_| dotenvy::from_filename("../../.env.test"));

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

/// Minimal gRPC AuthService for integration tests (PoW + device registration).
#[derive(Clone)]
struct TestAuthGrpcService {
    context: Arc<AuthServiceContext>,
}

fn app_error_to_status(e: AppError) -> GrpcStatus {
    // Keep mapping coarse — tests only need registration success/failure.
    match e {
        AppError::Validation(msg) | AppError::Auth(msg) => GrpcStatus::invalid_argument(msg),
        AppError::NotFound(msg) => GrpcStatus::not_found(msg),
        other => GrpcStatus::internal(other.to_string()),
    }
}

#[tonic::async_trait]
impl GrpcAuthService for TestAuthGrpcService {
    async fn get_pow_challenge(
        &self,
        _request: GrpcRequest<proto_svc::GetPowChallengeRequest>,
    ) -> Result<GrpcResponse<proto_svc::GetPowChallengeResponse>, GrpcStatus> {
        let app_context = Arc::new(self.context.to_app_context());
        let (_headers, axum::Json(challenge)) =
            construct_server_shared::auth_service::core::get_pow_challenge(
                app_context,
                axum::http::HeaderMap::new(),
            )
            .await
            .map_err(app_error_to_status)?;
        Ok(GrpcResponse::new(proto_svc::GetPowChallengeResponse {
            challenge: challenge.challenge,
            difficulty: challenge.difficulty,
            expires_at: challenge.expires_at,
        }))
    }

    async fn register_device(
        &self,
        request: GrpcRequest<proto_svc::RegisterDeviceRequest>,
    ) -> Result<GrpcResponse<proto_svc::RegisterDeviceResponse>, GrpcStatus> {
        let req = request.into_inner();
        let public_keys = req
            .public_keys
            .ok_or_else(|| GrpcStatus::invalid_argument("public_keys is required"))?;
        let pow_solution = req
            .pow_solution
            .ok_or_else(|| GrpcStatus::invalid_argument("pow_solution is required"))?;
        let app_context = Arc::new(self.context.to_app_context());
        let (_status, axum::Json(response)) =
            construct_server_shared::auth_service::core::register_device(
                app_context,
                axum::http::HeaderMap::new(),
                construct_server_shared::auth_service::core::RegisterDeviceInput {
                    username: req.username,
                    device_id: req.device_id,
                    public_keys:
                        construct_server_shared::auth_service::core::DevicePublicKeysInput {
                            verifying_key: public_keys.verifying_key,
                            identity_public: public_keys.identity_public,
                            signed_prekey_public: public_keys.signed_prekey_public,
                            signed_prekey_signature: public_keys.signed_prekey_signature,
                            crypto_suite: public_keys.crypto_suite,
                            supports_pq_ratchet: public_keys.supports_pq_ratchet,
                        },
                    pow_solution: construct_server_shared::auth_service::core::PowSolutionInput {
                        challenge: pow_solution.challenge,
                        nonce: pow_solution.nonce,
                        hash: pow_solution.hash,
                    },
                    identity_public_key: req.identity_public_key,
                    identity_key_type: req.identity_key_type,
                },
            )
            .await
            .map_err(app_error_to_status)?;

        Ok(GrpcResponse::new(proto_svc::RegisterDeviceResponse {
            tokens: Some(proto_svc::AuthTokensResponse {
                user_id: response.user_id,
                access_token: response.access_token,
                refresh_token: response.refresh_token,
                expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
                veil_bridge_cert: None,
            }),
        }))
    }

    async fn authenticate_device(
        &self,
        _: GrpcRequest<proto_svc::AuthenticateDeviceRequest>,
    ) -> Result<GrpcResponse<proto_svc::AuthenticateDeviceResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("authenticate_device"))
    }
    async fn refresh_token(
        &self,
        _: GrpcRequest<proto_svc::RefreshTokenRequest>,
    ) -> Result<GrpcResponse<proto_svc::RefreshTokenResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("refresh_token"))
    }
    async fn verify_token(
        &self,
        _: GrpcRequest<proto_svc::VerifyTokenRequest>,
    ) -> Result<GrpcResponse<proto_svc::VerifyTokenResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("verify_token"))
    }
    async fn logout(
        &self,
        _: GrpcRequest<proto_svc::LogoutRequest>,
    ) -> Result<GrpcResponse<proto_svc::LogoutResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("logout"))
    }
    async fn set_recovery_key(
        &self,
        _: GrpcRequest<proto_svc::SetRecoveryKeyRequest>,
    ) -> Result<GrpcResponse<proto_svc::SetRecoveryKeyResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("set_recovery_key"))
    }
    async fn get_recovery_status(
        &self,
        _: GrpcRequest<proto_svc::GetRecoveryStatusRequest>,
    ) -> Result<GrpcResponse<proto_svc::GetRecoveryStatusResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("get_recovery_status"))
    }
    async fn recover_account(
        &self,
        _: GrpcRequest<proto_svc::RecoverAccountRequest>,
    ) -> Result<GrpcResponse<proto_svc::RecoverAccountResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("recover_account"))
    }
    async fn store_recovery_bundle(
        &self,
        _: GrpcRequest<proto_svc::StoreRecoveryBundleRequest>,
    ) -> Result<GrpcResponse<proto_svc::StoreRecoveryBundleResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("store_recovery_bundle"))
    }
    async fn get_recovery_bundle(
        &self,
        _: GrpcRequest<proto_svc::GetRecoveryBundleRequest>,
    ) -> Result<GrpcResponse<proto_svc::GetRecoveryBundleResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("get_recovery_bundle"))
    }
    async fn get_sender_certificate(
        &self,
        _: GrpcRequest<proto_svc::GetSenderCertificateRequest>,
    ) -> Result<GrpcResponse<proto_svc::GetSenderCertificateResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("get_sender_certificate"))
    }
    async fn issue_tokens(
        &self,
        _: GrpcRequest<proto_svc::IssueTokensRequest>,
    ) -> Result<GrpcResponse<proto_svc::IssueTokensResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("issue_tokens"))
    }
    async fn approve_join_request(
        &self,
        _: GrpcRequest<proto_svc::ApproveJoinRequestRequest>,
    ) -> Result<GrpcResponse<proto_svc::ApproveJoinRequestResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("approve_join_request"))
    }
}

/// Spawn auth HTTP health + gRPC AuthService. Returns (http_address, grpc_address).
async fn spawn_auth_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> (String, String) {
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
        server_signer: None,
        token_enc_pub: None,
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(|State(ctx): State<Arc<AuthServiceContext>>| async move {
                let app_ctx = Arc::new(ctx.to_app_context());
                health::readiness_check_handler(axum::extract::State(app_ctx)).await
            }),
        )
        .route("/health/live", get(health::liveness_check_handler))
        .with_state(context.clone());

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_port = grpc_listener.local_addr().unwrap().port();
    let grpc_address = format!("127.0.0.1:{}", grpc_port);
    let grpc_service = TestAuthGrpcService { context };

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(AuthServiceServer::new(grpc_service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                grpc_listener,
            ))
            .await
            .unwrap();
    });

    (address, grpc_address)
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
                health::readiness_check_handler(axum::extract::State(app_ctx)).await
            }),
        )
        .route("/health/live", get(health::liveness_check_handler))
        .with_state(context);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    address
}

/// Minimal gRPC MessagingService for integration tests.
/// Only `send_message` is functional; all other RPCs return Unimplemented.
#[derive(Clone)]
struct TestMessagingGrpcService {
    context: Arc<AppContext>,
}

#[tonic::async_trait]
impl GrpcMessagingService for TestMessagingGrpcService {
    type MessageStreamStream = Pin<
        Box<
            dyn Stream<Item = Result<proto_svc::MessageStreamResponse, GrpcStatus>>
                + Send
                + 'static,
        >,
    >;

    async fn message_stream(
        &self,
        _request: GrpcRequest<tonic::Streaming<proto_svc::MessageStreamRequest>>,
    ) -> Result<GrpcResponse<Self::MessageStreamStream>, GrpcStatus> {
        Err(GrpcStatus::unimplemented(
            "message_stream not available in tests",
        ))
    }

    async fn send_message(
        &self,
        request: GrpcRequest<proto_svc::SendMessageRequest>,
    ) -> Result<GrpcResponse<proto_svc::SendMessageResponse>, GrpcStatus> {
        let req = request.into_inner();
        let envelope = req
            .message
            .ok_or_else(|| GrpcStatus::invalid_argument("message is required"))?;
        let sender = envelope
            .sender
            .ok_or_else(|| GrpcStatus::invalid_argument("sender is required"))?;
        let sender_id = uuid::Uuid::parse_str(&sender.user_id)
            .map_err(|_| GrpcStatus::invalid_argument("invalid sender.user_id"))?;
        let recipient = envelope
            .recipient
            .ok_or_else(|| GrpcStatus::invalid_argument("recipient is required"))?;
        if envelope.encrypted_payload.is_empty() {
            return Err(GrpcStatus::invalid_argument(
                "encrypted_payload is required",
            ));
        }
        let message_id = uuid::Uuid::new_v4().to_string();
        let msg_envelope = MessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: sender_id.to_string(),
            recipient_id: recipient.user_id.clone(),
            message_id: message_id.clone(),
            encrypted_payload: envelope.encrypted_payload.to_vec(),
            content_type: envelope.content_type,
            recipient_device: None,
        });
        let app_context = self.context.clone();
        dispatch_envelope_for_test(&app_context, msg_envelope)
            .await
            .map_err(|e| GrpcStatus::internal(e.to_string()))?;
        Ok(GrpcResponse::new(proto_svc::SendMessageResponse {
            message_id,
            message_number: 0,
            server_timestamp: chrono::Utc::now().timestamp_millis(),
            success: true,
            error: None,
            rate_limit_challenge: None,
            attempt_id: None,
        }))
    }

    async fn send_sealed_message(
        &self,
        _: GrpcRequest<proto_svc::SendSealedMessageRequest>,
    ) -> Result<GrpcResponse<proto_svc::SendMessageResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("send_sealed_message"))
    }

    async fn edit_message(
        &self,
        _: GrpcRequest<proto_svc::EditMessageRequest>,
    ) -> Result<GrpcResponse<proto_svc::EditMessageResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("edit_message"))
    }

    async fn add_reaction(
        &self,
        _: GrpcRequest<proto_svc::AddReactionRequest>,
    ) -> Result<GrpcResponse<proto_svc::AddReactionResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("add_reaction"))
    }

    async fn remove_reaction(
        &self,
        _: GrpcRequest<proto_svc::RemoveReactionRequest>,
    ) -> Result<GrpcResponse<proto_svc::RemoveReactionResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("remove_reaction"))
    }

    async fn get_pending_messages(
        &self,
        _: GrpcRequest<proto_svc::GetPendingMessagesRequest>,
    ) -> Result<GrpcResponse<proto_svc::GetPendingMessagesResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("get_pending_messages"))
    }

    async fn request_key_sync(
        &self,
        _: GrpcRequest<proto_svc::RequestKeySyncRequest>,
    ) -> Result<GrpcResponse<proto_svc::RequestKeySyncResponse>, GrpcStatus> {
        Err(GrpcStatus::unimplemented("request_key_sync"))
    }
}

/// Spawn messaging service — returns (http_address, grpc_address)
async fn spawn_messaging_service(config: Arc<Config>, db_pool: Arc<PgPool>) -> (String, String) {
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

    let context = Arc::new(
        AppContext::builder()
            .with_db_pool(db_pool)
            .with_queue(queue)
            .with_auth_manager(auth_manager)
            .with_config(config.clone())
            .with_apns_client(apns_client.clone())
            .with_apns_sandbox_client(apns_client)
            .with_token_encryption(token_encryption)
            .with_server_instance_id(uuid::Uuid::new_v4().to_string())
            .build()
            .expect("Failed to build test AppContext"),
    );

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(|State(ctx): State<Arc<AppContext>>| async move {
                health::readiness_check_handler(axum::extract::State(ctx)).await
            }),
        )
        .route("/health/live", get(health::liveness_check_handler))
        .with_state(context.clone());

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Spawn gRPC server for messaging
    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_port = grpc_listener.local_addr().unwrap().port();
    let grpc_address = format!("127.0.0.1:{}", grpc_port);
    let grpc_service = TestMessagingGrpcService { context };

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MessagingServiceServer::new(grpc_service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                grpc_listener,
            ))
            .await
            .unwrap();
    });

    (address, grpc_address)
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
    let mut sandbox_config = config.apns.clone();
    sandbox_config.environment = ApnsEnvironment::Development;
    let apns_sandbox_client =
        Arc::new(ApnsClient::new(sandbox_config).expect("Failed to create APNs sandbox client"));
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .expect("Failed to create token encryption"),
    );

    let context = Arc::new(NotificationServiceContext {
        db_pool,
        queue,
        auth_manager,
        apns_client,
        apns_sandbox_client,
        token_encryption,
        config: config.clone(),
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/health/ready",
            get(
                |State(ctx): State<Arc<NotificationServiceContext>>| async move {
                    let app_ctx = Arc::new(ctx.to_app_context());
                    health::readiness_check_handler(axum::extract::State(app_ctx)).await
                },
            ),
        )
        .route("/health/live", get(health::liveness_check_handler))
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

    let (auth_address, grpc_auth_address) =
        spawn_auth_service(config.clone(), db_pool_arc.clone()).await;
    let user_address = spawn_user_service(config.clone(), db_pool_arc.clone()).await;
    let (messaging_address, grpc_messaging_address) =
        spawn_messaging_service(config.clone(), db_pool_arc.clone()).await;
    let notification_address =
        spawn_notification_service(config.clone(), db_pool_arc.clone()).await;

    // Give services time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    TestApp {
        address: auth_address.clone(), // Legacy compatibility
        auth_address,
        grpc_auth_address,
        user_address,
        messaging_address,
        grpc_messaging_address,
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

    let (auth_address, grpc_auth_address) =
        spawn_auth_service(config.clone(), db_pool_arc.clone()).await;
    let user_address = spawn_user_service(config.clone(), db_pool_arc.clone()).await;
    let (messaging_address, grpc_messaging_address) =
        spawn_messaging_service(config.clone(), db_pool_arc.clone()).await;
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
        grpc_auth_address,
        user_address,
        messaging_address,
        grpc_messaging_address,
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

    let (address, _grpc) = spawn_auth_service(config.clone(), db_pool_arc).await;

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
pub struct ChallengeResponse {
    pub challenge: String,
    pub difficulty: u32,
    pub expires_at: i64,
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
pub fn solve_pow(challenge: &str, difficulty: u32) -> (u64, String) {
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

/// Register a new user via gRPC AuthService (passwordless device registration).
///
/// `auth_grpc_address` is host:port of the test AuthService (see `TestApp.grpc_auth_address`).
/// Returns (user_id, access_token).
pub async fn register_user_passwordless(
    _client: &reqwest::Client,
    auth_grpc_address: &str,
    username: Option<&str>,
) -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let channel = tonic::transport::Channel::from_shared(format!("http://{auth_grpc_address}"))
        .expect("auth grpc uri")
        .connect()
        .await
        .expect("connect auth grpc");
    let mut auth = AuthServiceClient::new(channel);

    let challenge = auth
        .get_pow_challenge(proto_svc::GetPowChallengeRequest {})
        .await
        .expect("GetPowChallenge")
        .into_inner();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    let reg = auth
        .register_device(proto_svc::RegisterDeviceRequest {
            username: username.map(|s| s.to_string()),
            device_id,
            public_keys: Some(proto_svc::DevicePublicKeys {
                verifying_key: verifying_key.as_bytes().to_vec(),
                identity_public: identity_public.as_bytes().to_vec(),
                signed_prekey_public: prekey_public.as_bytes().to_vec(),
                signed_prekey_signature: prekey_signature.to_bytes().to_vec(),
                crypto_suite: "Curve25519+Ed25519".to_string(),
                hybrid_identity_key: None,
                hybrid_identity_signature: None,
                signed_prekey_hybrid_signature: None,
                supports_pq_ratchet: false,
            }),
            pow_solution: Some(proto_svc::PowSolution {
                challenge: challenge.challenge,
                nonce,
                hash,
            }),
            identity_public_key: None,
            identity_key_type: None,
        })
        .await
        .expect("RegisterDevice")
        .into_inner();

    let tokens = reg.tokens.expect("tokens in RegisterDeviceResponse");
    (tokens.user_id, tokens.access_token)
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
        register_user_passwordless(&client, &ctx.grpc_auth_address, Some(username)).await;

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

// ── Dispatch helpers for integration tests (not a twin of messaging-service/src/core.rs) ──

async fn fetch_recipient_device_ids(
    app_context: &Arc<AppContext>,
    recipient_id: &str,
) -> Vec<String> {
    let Ok(uid) = Uuid::parse_str(recipient_id) else {
        return vec![];
    };
    match construct_db::get_devices_by_user_id(&app_context.db_pool, &uid).await {
        Ok(devices) => devices.into_iter().map(|d| d.device_id).collect(),
        Err(e) => {
            tracing::warn!(error = %e, recipient = %recipient_id, "Failed to fetch recipient devices for fan-out");
            vec![]
        }
    }
}

async fn dispatch_envelope_for_test(
    app_context: &Arc<AppContext>,
    envelope: MessageEnvelope,
) -> Result<(), AppError> {
    let t_start = std::time::Instant::now();
    let salt = &app_context.config.logging.hash_salt;
    let message_id = &envelope.message_id;
    let sender_id = &envelope.sender_id;
    let recipient_id = &envelope.recipient_id;

    use construct_server_shared::message::MessageType;
    let is_user_message = matches!(
        envelope.message_type,
        MessageType::DirectMessage | MessageType::MLSMessage | MessageType::SenderSync
    );

    let t_lock = std::time::Instant::now();
    let mut queue = app_context.queue.lock().await;
    tracing::debug!(
        wait_ms = t_lock.elapsed().as_millis(),
        "queue lock acquired (dispatch)"
    );

    if is_user_message {
        match queue.is_message_duplicate(message_id).await {
            Ok(true) => {
                tracing::debug!(message_id = %message_id, "Duplicate message_id — skipping (idempotent retry)");
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Failed to check dedup key — proceeding anyway");
            }
        }
    }

    drop(queue);

    if is_user_message
        && let (Ok(sender_uuid), Ok(recipient_uuid)) =
            (Uuid::parse_str(sender_id), Uuid::parse_str(recipient_id))
    {
        match construct_db::is_blocked_by(&app_context.db_pool, &recipient_uuid, &sender_uuid).await
        {
            Ok(true) => {
                tracing::debug!(
                    sender_hash = %log_safe_id(sender_id, salt),
                    recipient_hash = %log_safe_id(recipient_id, salt),
                    "Message silently dropped — sender is blocked by recipient"
                );
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, "Failed to check user_blocks — proceeding with delivery");
            }
        }
    }

    let device_ids = fetch_recipient_device_ids(app_context, recipient_id).await;
    let mut queue = app_context.queue.lock().await;
    queue
        .write_message_to_device_streams(recipient_id, &device_ids, &envelope)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to deliver message: {e}")))?;
    if is_user_message && let Err(e) = queue.mark_message_dispatched(message_id).await {
        tracing::warn!(
            error = %e,
            message_id = %message_id,
            "Failed to mark message dispatched after mailbox write — retry may duplicate"
        );
    }

    if !sender_id.is_empty()
        && let Err(e) = queue.store_message_sender(message_id, sender_id).await
    {
        tracing::warn!(error = %e, message_id = %message_id, "Failed to store receipt sender mapping in Redis (non-critical)");
    }
    drop(queue);

    let elapsed = t_start.elapsed();
    tracing::info!(
        elapsed_ms = elapsed.as_millis(),
        sender_hash = %log_safe_id(sender_id, salt),
        recipient_hash = %log_safe_id(recipient_id, salt),
        message_id = %message_id,
        "Message dispatched"
    );

    if !sender_id.is_empty() {
        let hash_salt = app_context.config.logging.hash_salt.clone();
        let msg_id = message_id.clone();
        let snd_id = sender_id.clone();
        let pool = app_context.db_pool.clone();
        tokio::spawn(async move {
            let message_hash = receipt_routing_hash(&msg_id, &hash_salt);
            let result = sqlx::query(
                "INSERT INTO delivery_pending (message_hash, sender_id, expires_at) \
                 VALUES ($1, $2, NOW() + INTERVAL '30 days') \
                 ON CONFLICT (message_hash) DO NOTHING",
            )
            .bind(&message_hash)
            .bind(&snd_id)
            .execute(&*pool)
            .await;
            if let Err(e) = result {
                tracing::warn!(error = %e, message_id = %msg_id, "Failed to persist receipt sender to DB (non-critical)");
            }
        });
    }

    Ok(())
}

async fn confirm_pending_message_for_test(
    app_context: Arc<AppContext>,
    sender_id: Uuid,
    temp_id: &str,
) -> Result<serde_json::Value, AppError> {
    let sender_id_str = sender_id.to_string();

    let Some(pending_storage) = &app_context.pending_message_storage else {
        return Ok(serde_json::json!({
            "status": "confirmed",
            "message": "2-phase commit not enabled"
        }));
    };

    match pending_storage.confirm_pending(temp_id).await {
        Ok(true) => {
            tracing::debug!(
                temp_id = %temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Message confirmed (Phase 2)"
            );
            Ok(serde_json::json!({
                "status": "confirmed",
                "tempId": temp_id
            }))
        }
        Ok(false) => {
            tracing::warn!(
                temp_id = %temp_id,
                sender_hash = %log_safe_id(&sender_id_str, &app_context.config.logging.hash_salt),
                "Attempted to confirm non-existent pending message"
            );
            Ok(serde_json::json!({
                "status": "confirmed",
                "tempId": temp_id,
                "message": "Already confirmed or expired"
            }))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                temp_id = %temp_id,
                "Failed to confirm pending message"
            );
            Ok(serde_json::json!({
                "status": "confirmed",
                "tempId": temp_id,
                "message": "Confirmation queued"
            }))
        }
    }
}

fn receipt_routing_hash(message_id: &str, salt: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    // Keep in sync with messaging-service `core::receipt_routing_hash`: never
    // substitute a fixed "fallback" HMAC key.
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(message_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
