// ============================================================================
// Auth Service - Phase 2.6.2
// ============================================================================
//
// Authentication and authorization service for microservices architecture.
// Handles:
// - User registration
// - User login
// - JWT token management (access tokens, refresh tokens)
// - Token refresh
// - Logout (token invalidation)
// - Account recovery via seed phrase
//
// Architecture:
// - Stateless (JWT tokens)
// - Horizontally scalable
// - No sticky sessions required
//
// ============================================================================

mod recovery;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use construct_config::Config;
use construct_server_shared::auth_service::AuthServiceContext;
use construct_server_shared::db::DbPool;
use construct_server_shared::queue::MessageQueue;
use serde_json::json;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    auth_service_server::{AuthService, AuthServiceServer},
};

#[derive(Clone)]
struct AuthGrpcService {
    context: Arc<AuthServiceContext>,
}

#[tonic::async_trait]
impl AuthService for AuthGrpcService {
    async fn get_pow_challenge(
        &self,
        _request: Request<proto::GetPowChallengeRequest>,
    ) -> Result<Response<proto::GetPowChallengeResponse>, Status> {
        let app_context = Arc::new(self.context.to_app_context());
        let axum::Json(challenge) =
            construct_server_shared::auth_service::core::get_pow_challenge(app_context)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(proto::GetPowChallengeResponse {
            challenge: challenge.challenge,
            difficulty: challenge.difficulty,
            expires_at: challenge.expires_at,
        }))
    }

    async fn register_device(
        &self,
        request: Request<proto::RegisterDeviceRequest>,
    ) -> Result<Response<proto::AuthTokensResponse>, Status> {
        let req = request.into_inner();
        let public_keys = req
            .public_keys
            .ok_or_else(|| Status::invalid_argument("public_keys is required"))?;
        let pow_solution = req
            .pow_solution
            .ok_or_else(|| Status::invalid_argument("pow_solution is required"))?;
        let app_context = Arc::new(self.context.to_app_context());
        let (_status, axum::Json(response)) =
            construct_server_shared::auth_service::core::register_device(
                app_context,
                construct_server_shared::auth_service::core::RegisterDeviceInput {
                    username: req.username,
                    device_id: req.device_id,
                    public_keys:
                        construct_server_shared::auth_service::core::DevicePublicKeysInput {
                            verifying_key: public_keys.verifying_key,
                            identity_public: public_keys.identity_public,
                            signed_prekey_public: public_keys.signed_prekey_public,
                            signed_prekey_signature: public_keys.signed_prekey_signature,
                            suite_id: public_keys.suite_id,
                        },
                    pow_solution: construct_server_shared::auth_service::core::PowSolutionInput {
                        challenge: pow_solution.challenge,
                        nonce: pow_solution.nonce,
                        hash: pow_solution.hash,
                    },
                },
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::AuthTokensResponse {
            user_id: response.user_id,
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
        }))
    }

    async fn refresh_token(
        &self,
        request: Request<proto::RefreshTokenRequest>,
    ) -> Result<Response<proto::RefreshTokenResponse>, Status> {
        let app_context = Arc::new(self.context.to_app_context());
        let response = construct_server_shared::auth_service::core::refresh_tokens_proto(
            app_context,
            request.into_inner(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(response))
    }

    async fn verify_token(
        &self,
        request: Request<proto::VerifyTokenRequest>,
    ) -> Result<Response<proto::VerifyTokenResponse>, Status> {
        let token = request.into_inner().access_token;
        match self.context.auth_manager.verify_token(&token) {
            Ok(claims) => Ok(Response::new(proto::VerifyTokenResponse {
                valid: true,
                user_id: Some(claims.sub),
                device_id: None,
                expires_at: Some(claims.exp),
            })),
            Err(_) => Ok(Response::new(proto::VerifyTokenResponse {
                valid: false,
                user_id: None,
                device_id: None,
                expires_at: None,
            })),
        }
    }

    async fn authenticate_device(
        &self,
        request: Request<proto::AuthenticateDeviceRequest>,
    ) -> Result<Response<proto::AuthTokensResponse>, Status> {
        let req = request.into_inner();
        let app_context = Arc::new(self.context.to_app_context());
        let (_status, axum::Json(response)) =
            construct_server_shared::auth_service::core::authenticate_device(
                app_context,
                construct_server_shared::auth_service::core::AuthenticateDeviceInput {
                    device_id: req.device_id,
                    timestamp: req.timestamp,
                    signature: req.signature,
                },
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::AuthTokensResponse {
            user_id: response.user_id,
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            expires_at: chrono::Utc::now().timestamp() + response.expires_in as i64,
        }))
    }

    async fn logout(
        &self,
        request: Request<proto::LogoutRequest>,
    ) -> Result<Response<proto::LogoutResponse>, Status> {
        let req = request.into_inner();
        if req.access_token.is_empty() {
            return Err(Status::invalid_argument("access_token is required"));
        }
        let claims = self
            .context
            .auth_manager
            .verify_token(&req.access_token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::auth_service::core::logout_user(
            app_context,
            user_id,
            req.all_devices,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::LogoutResponse { success: true }))
    }

    // =========================================================================
    // Account Recovery RPCs
    // =========================================================================

    async fn set_recovery_key(
        &self,
        request: Request<proto::SetRecoveryKeyRequest>,
    ) -> Result<Response<proto::SetRecoveryKeyResponse>, Status> {
        // Extract token before consuming request
        let token = request_token(request.metadata())?;
        let req = request.into_inner();

        // Validate inputs
        if req.recovery_public_key.is_empty() {
            return Err(Status::invalid_argument("recovery_public_key is required"));
        }
        if req.setup_signature.is_empty() {
            return Err(Status::invalid_argument("setup_signature is required"));
        }
        if req.timestamp == 0 {
            return Err(Status::invalid_argument("timestamp is required"));
        }

        // Verify auth token
        let claims = self.context.auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let db = self.context.db_pool.as_ref();
        let fingerprint = recovery::set_recovery_key(
            db,
            user_id,
            &req.recovery_public_key,
            &req.setup_signature,
            req.timestamp,
            req.encrypted_backup.as_deref(),
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("already set") {
                Status::already_exists(msg)
            } else if msg.contains("expired") || msg.contains("Invalid") {
                Status::invalid_argument(msg)
            } else {
                Status::internal(msg)
            }
        })?;

        Ok(Response::new(proto::SetRecoveryKeyResponse {
            success: true,
            fingerprint,
            setup_at: chrono::Utc::now().timestamp(),
            error: None,
        }))
    }

    async fn get_recovery_status(
        &self,
        request: Request<proto::GetRecoveryStatusRequest>,
    ) -> Result<Response<proto::GetRecoveryStatusResponse>, Status> {
        // Must be authenticated
        let token = request_token(request.metadata())?;
        let claims = self.context.auth_manager
            .verify_token(&token)
            .map_err(|_| Status::unauthenticated("invalid access token"))?;
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| Status::internal("invalid user id in token"))?;

        let db = self.context.db_pool.as_ref();
        let status = recovery::get_recovery_status(db, user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::GetRecoveryStatusResponse {
            is_setup: status.is_setup,
            fingerprint: status.fingerprint,
            setup_at: status.setup_at.map(|t| t.timestamp()),
            last_used_at: status.last_used_at.map(|t| t.timestamp()),
            has_backup: status.has_backup,
        }))
    }

    async fn recover_account(
        &self,
        request: Request<proto::RecoverAccountRequest>,
    ) -> Result<Response<proto::RecoverAccountResponse>, Status> {
        let req = request.into_inner();

        // Validate required fields
        if req.identifier.is_empty() {
            return Err(Status::invalid_argument("identifier is required"));
        }
        if req.challenge.is_empty() {
            return Err(Status::invalid_argument("challenge is required"));
        }
        if req.recovery_signature.is_empty() {
            return Err(Status::invalid_argument("recovery_signature is required"));
        }
        let new_device = req.new_device
            .ok_or_else(|| Status::invalid_argument("new_device is required"))?;
        let public_keys = new_device.public_keys
            .ok_or_else(|| Status::invalid_argument("new_device.public_keys is required"))?;

        let db = self.context.db_pool.as_ref();

        // 1. Verify recovery signature and get user_id
        let user_id = recovery::verify_recovery_signature(
            db,
            &req.identifier,
            &req.challenge,
            &req.recovery_signature,
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                Status::not_found(msg)
            } else if msg.contains("not set up") {
                Status::failed_precondition(msg)
            } else if msg.contains("cooldown") {
                Status::resource_exhausted(msg)
            } else if msg.contains("Invalid") {
                Status::permission_denied(msg)
            } else {
                Status::internal(msg)
            }
        })?;

        // 2. Revoke all existing devices
        let devices_revoked = recovery::revoke_all_devices(db, user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // 3. Revoke all tokens
        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::auth_service::core::logout_user(
            app_context.clone(),
            user_id,
            true,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        // 4. Register new device directly (bypass PoW for recovery flow)
        let hostname = env::var("SERVER_HOSTNAME").unwrap_or_else(|_| "construct.cc".to_string());

        let verifying_key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.verifying_key,
        )
        .unwrap_or(public_keys.verifying_key.as_bytes().to_vec());

        let identity_public = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.identity_public,
        )
        .unwrap_or(public_keys.identity_public.as_bytes().to_vec());

        let signed_prekey_public = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.signed_prekey_public,
        )
        .unwrap_or(public_keys.signed_prekey_public.as_bytes().to_vec());

        let signed_prekey_signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &public_keys.signed_prekey_signature,
        )
        .unwrap_or(public_keys.signed_prekey_signature.as_bytes().to_vec());

        construct_server_shared::db::create_device(
            self.context.db_pool.as_ref(),
            construct_server_shared::db::CreateDeviceData {
                device_id: new_device.device_id,
                server_hostname: hostname,
                verifying_key,
                identity_public,
                signed_prekey_public,
                signed_prekey_signature,
                crypto_suites: format!(r#"["{}"]"#, public_keys.suite_id),
            },
            Some(user_id),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        // 5. Generate tokens for new device
        let (access_token, _, exp_timestamp) = app_context
            .auth_manager
            .create_token(&user_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        let (refresh_token, refresh_jti, _) = app_context
            .auth_manager
            .create_refresh_token(&user_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        // Store refresh token
        {
            let mut queue = app_context.queue.lock().await;
            let ttl = app_context.config.refresh_token_ttl_days * construct_config::SECONDS_PER_DAY;
            if let Err(e) = queue
                .store_refresh_token(&refresh_jti, &user_id.to_string(), ttl)
                .await
            {
                tracing::warn!(error = %e, "Failed to store refresh token during recovery");
            }
        }

        // 6. Update last_recovery_at
        recovery::mark_recovery_used(db, user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let now = chrono::Utc::now().timestamp();
        Ok(Response::new(proto::RecoverAccountResponse {
            success: true,
            user_id: user_id.to_string(),
            tokens: Some(proto::AuthTokensResponse {
                user_id: user_id.to_string(),
                access_token,
                refresh_token,
                expires_at: exp_timestamp,
            }),
            devices_revoked,
            recovered_at: now,
            warnings: vec!["All existing sessions have been terminated".to_string()],
            error: None,
        }))
    }
}

/// Extract Bearer token from gRPC metadata
fn request_token(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
    let auth = metadata
        .get("authorization")
        .or_else(|| metadata.get("Authorization"))
        .ok_or_else(|| Status::unauthenticated("missing authorization header"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("invalid authorization header"))?;

    auth.strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("authorization must be Bearer token"))
}

/// GET /.well-known/jwks.json
/// Returns JSON Web Key Set (JWKS) for RS256 public key
/// This endpoint is public and doesn't require authentication
async fn get_jwks() -> impl IntoResponse {
    // Try to get JWT public key from environment
    match env::var("JWT_PUBLIC_KEY") {
        Ok(public_key) => {
            // Remove PEM headers/footers and newlines for JWKS format
            let key_content = public_key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\n", "")
                .replace("\r", "");

            let jwks = json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": key_content,
                    "kid": "construct-auth-service-key"
                }]
            });

            (StatusCode::OK, Json(jwks))
        }
        Err(_) => {
            // If no public key, return error
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "JWT public key not configured"
                })),
            )
        }
    }
}

/// GET /public-key
/// Returns the JWT public key in PEM format
/// This endpoint is public and doesn't require authentication
async fn get_public_key() -> impl IntoResponse {
    match env::var("JWT_PUBLIC_KEY") {
        Ok(public_key) => (StatusCode::OK, public_key),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "JWT public key not configured".to_string(),
        ),
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Service discovery endpoint (wrapper)
async fn well_known_construct_server(
    State(context): State<Arc<AuthServiceContext>>,
) -> impl IntoResponse {
    use construct_server_shared::routes::federation;

    // Convert AuthServiceContext to AppContext
    let app_context = Arc::new(context.to_app_context());

    // Call the actual handler
    federation::well_known_construct_server(axum::extract::State(app_context)).await
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::from_env()?;
    let config = Arc::new(config);

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(config.rust_log.clone()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("=== Auth Service Starting ===");
    info!("Port: {}", config.port);

    // Initialize database
    info!("Connecting to database...");
    let db_pool = Arc::new(
        DbPool::connect(&config.database_url)
            .await
            .context("Failed to connect to database")?,
    );
    info!("Connected to database");

    // Apply database migrations
    info!("Applying database migrations...");
    sqlx::migrate!("../shared/migrations")
        .run(&*db_pool)
        .await
        .context("Failed to apply database migrations")?;
    info!("Database migrations applied successfully");

    // Initialize Redis
    info!("Connecting to Redis...");
    let queue = Arc::new(Mutex::new(
        MessageQueue::new(&config)
            .await
            .context("Failed to create message queue")?,
    ));
    info!("Connected to Redis");

    // Initialize Auth Manager
    let auth_manager = Arc::new(
        construct_server_shared::auth::AuthManager::new(&config)
            .context("Failed to initialize auth manager")?,
    );

    // Initialize Key Management System (optional, requires VAULT_ADDR)
    let key_management =
        match construct_server_shared::key_management::KeyManagementConfig::from_env() {
            Ok(kms_config) => {
                info!("Initializing Key Management System...");
                match construct_server_shared::key_management::KeyManagementSystem::new(
                    db_pool.clone(),
                    kms_config,
                )
                .await
                {
                    Ok(kms) => {
                        // Start background tasks (key refresh, rotation)
                        if let Err(e) = kms.start().await {
                            tracing::error!(error = %e, "Failed to start key management background tasks");
                            return Err(e).context("Failed to start key management system");
                        }
                        info!("Key Management System initialized and started");
                        Some(Arc::new(kms))
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Failed to initialize Key Management System - continuing without automatic key rotation"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::info!(
                    error = %e,
                    "Key Management System disabled (VAULT_ADDR not configured or invalid config)"
                );
                None
            }
        };

    // Create service context
    let context = Arc::new(AuthServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
        key_management,
    });

    // Import auth service handlers
    use construct_server_shared::auth_service::handlers;

    // Start gRPC AuthService (hard-cut target transport)
    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("AUTH_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50051".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Invalid AUTH_GRPC_BIND_ADDRESS")?;
    tokio::spawn(async move {
        let service = AuthGrpcService {
            context: grpc_context,
        };
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(AuthServiceServer::new(service))
            .serve(grpc_addr)
            .await
        {
            tracing::error!(error = %e, "Auth gRPC server failed");
        }
    });
    info!("Auth gRPC listening on {}", grpc_bind_address);

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Service discovery (Hybrid Discovery Protocol v1.0)
        .route(
            "/.well-known/construct-server",
            get(well_known_construct_server),
        )
        // Public key endpoint (no auth required)
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/public-key", get(get_public_key))
        // Passwordless authentication endpoints
        .route("/api/v1/auth/challenge", get(handlers::get_pow_challenge))
        .route(
            "/api/v1/auth/register-device",
            post(handlers::register_device),
        )
        .route("/api/v1/auth/device", post(handlers::authenticate_device))
        // Token management endpoints
        .route("/api/v1/auth/refresh", post(handlers::refresh_token))
        .route("/api/v1/auth/logout", post(handlers::logout))
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("Auth Service listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
