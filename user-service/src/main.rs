// User management service for microservices architecture.
// Handles:
// - User profiles management
// - Public keys (key bundles)
// - Account management (get, update, delete)
//
// Architecture:
// - Stateless
// - Horizontally scalable
// - Redis caching for key bundles
//
// ============================================================================

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use construct_config::Config;
use construct_db as db_agility;
use construct_server_shared::auth::AuthManager;
use construct_server_shared::db::DbPool;
use construct_server_shared::queue::MessageQueue;
use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    user_service_server::{UserService, UserServiceServer},
};
use construct_server_shared::user_service::UserServiceContext;
use serde_json::json;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct UserGrpcService {
    context: Arc<UserServiceContext>,
}

#[tonic::async_trait]
impl UserService for UserGrpcService {
    async fn get_user_profile(
        &self,
        request: Request<proto::GetUserProfileRequest>,
    ) -> Result<Response<proto::UserProfile>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let user = construct_server_shared::db::get_user_by_id(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        Ok(Response::new(proto::UserProfile {
            user_id: user.id.to_string(),
            username: user.username,
            display_name: None,
            bio: None,
            profile_picture_url: None,
            email: None,
            phone: None,
            created_at: 0,
            last_seen: None,
            public_key_fingerprint: None,
            privacy: None,
            verified: false,
        }))
    }

    async fn update_user_profile(
        &self,
        request: Request<proto::UpdateUserProfileRequest>,
    ) -> Result<Response<proto::UserProfile>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let normalized_username = req.username.and_then(|u| {
            let trimmed = u.trim().to_lowercase();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        if let Some(ref username) = normalized_username {
            if username.len() < 3 || username.len() > 20 {
                return Err(Status::invalid_argument("username must be 3-20 characters"));
            }
            if !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(Status::invalid_argument(
                    "username can only contain letters, numbers, and underscores",
                ));
            }

            if let Some(existing) =
                construct_server_shared::db::get_user_by_username(&self.context.db_pool, username)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?
                && existing.id != user_id
            {
                return Err(Status::already_exists("username is already taken"));
            }
        }

        let updated = construct_server_shared::db::update_user_username(
            &self.context.db_pool,
            &user_id,
            normalized_username.as_deref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::UserProfile {
            user_id: updated.id.to_string(),
            username: updated.username,
            display_name: None,
            bio: None,
            profile_picture_url: None,
            email: None,
            phone: None,
            created_at: 0,
            last_seen: None,
            public_key_fingerprint: None,
            privacy: None,
            verified: false,
        }))
    }

    async fn update_profile_picture(
        &self,
        _request: Request<proto::UpdateProfilePictureRequest>,
    ) -> Result<Response<proto::UpdateProfilePictureResponse>, Status> {
        Err(Status::unimplemented(
            "update_profile_picture is not implemented yet",
        ))
    }

    async fn get_user_capabilities(
        &self,
        request: Request<proto::GetUserCapabilitiesRequest>,
    ) -> Result<Response<proto::GetUserCapabilitiesResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let caps = db_agility::get_user_capabilities(&self.context.db_pool, &user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("user not found"))?;

        let crypto_suites: Vec<String> = caps
            .crypto_suites
            .iter()
            .map(|suite| format!("{:?}", suite))
            .collect();
        let supports_pq = crypto_suites
            .iter()
            .any(|suite| suite.contains("Hybrid") || suite.contains("Kyber"));

        Ok(Response::new(proto::GetUserCapabilitiesResponse {
            user_id: caps.user_id.to_string(),
            crypto_suites,
            supports_webrtc: false,
            supports_mls: false,
            supports_pq,
            device_capabilities: vec![],
        }))
    }

    async fn block_user(
        &self,
        request: Request<proto::BlockUserRequest>,
    ) -> Result<Response<proto::BlockUserResponse>, Status> {
        let req = request.into_inner();
        let blocker_user_id = uuid::Uuid::parse_str(&req.blocker_user_id)
            .map_err(|_| Status::invalid_argument("invalid blocker_user_id"))?;
        let blocked_user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        if blocker_user_id == blocked_user_id {
            return Err(Status::invalid_argument("cannot block self"));
        }

        if construct_server_shared::db::get_user_by_id(&self.context.db_pool, &blocked_user_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .is_none()
        {
            return Err(Status::not_found("user not found"));
        }

        let blocked_at = construct_server_shared::db::block_user(
            &self.context.db_pool,
            &blocker_user_id,
            &blocked_user_id,
            req.reason.as_deref(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::BlockUserResponse {
            success: true,
            blocked_at: blocked_at.timestamp_millis(),
        }))
    }

    async fn unblock_user(
        &self,
        request: Request<proto::UnblockUserRequest>,
    ) -> Result<Response<proto::UnblockUserResponse>, Status> {
        let req = request.into_inner();
        let blocker_user_id = uuid::Uuid::parse_str(&req.blocker_user_id)
            .map_err(|_| Status::invalid_argument("invalid blocker_user_id"))?;
        let blocked_user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let success = construct_server_shared::db::unblock_user(
            &self.context.db_pool,
            &blocker_user_id,
            &blocked_user_id,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::UnblockUserResponse { success }))
    }

    async fn get_blocked_users(
        &self,
        request: Request<proto::GetBlockedUsersRequest>,
    ) -> Result<Response<proto::GetBlockedUsersResponse>, Status> {
        let req = request.into_inner();
        let user_id = uuid::Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("invalid user_id"))?;

        let blocked_users =
            construct_server_shared::db::get_blocked_users(&self.context.db_pool, &user_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        let total_count = blocked_users.len() as u32;
        let blocked_users = blocked_users
            .into_iter()
            .map(|u| proto::BlockedUser {
                user_id: u.user_id.to_string(),
                username: u.username.unwrap_or_default(),
                blocked_at: u.blocked_at.timestamp_millis(),
                reason: u.reason,
            })
            .collect();

        Ok(Response::new(proto::GetBlockedUsersResponse {
            blocked_users,
            total_count,
            next_cursor: None,
            has_more: false,
        }))
    }

    async fn delete_account(
        &self,
        _request: Request<proto::DeleteAccountRequest>,
    ) -> Result<Response<proto::DeleteAccountResponse>, Status> {
        // TODO: Implement account deletion (GDPR right to be forgotten)
        // - Verify confirmation token
        // - Mark account as deleted (soft delete)
        // - Schedule data cleanup job
        // - Revoke all sessions/tokens
        Err(Status::unimplemented("DeleteAccount not implemented yet"))
    }

    async fn export_user_data(
        &self,
        _request: Request<proto::ExportUserDataRequest>,
    ) -> Result<Response<proto::ExportUserDataResponse>, Status> {
        // TODO: Implement data export (GDPR data portability)
        // - Collect user profile, devices, keys
        // - Optionally include message metadata (if stored)
        // - Format as JSON/CSV based on request
        // - Return download URL or inline data
        Err(Status::unimplemented("ExportUserData not implemented yet"))
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
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

    info!("=== User Service Starting ===");
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
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // Create service context
    let context = Arc::new(UserServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
    });

    // Import user service handlers
    use construct_server_shared::user_service::handlers;

    // Start gRPC UserService (SVC-2 scaffold)
    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("USER_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50052".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Invalid USER_GRPC_BIND_ADDRESS")?;
    tokio::spawn(async move {
        let service = UserGrpcService {
            context: grpc_context,
        };
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(UserServiceServer::new(service))
            .serve(grpc_addr)
            .await
        {
            tracing::error!(error = %e, "User gRPC server failed");
        }
    });
    info!("User gRPC listening on {}", grpc_bind_address);

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // User profile endpoints
        .route(
            "/api/v1/users/:device_id/profile",
            get(handlers::get_device_profile),
        )
        // Account management endpoints
        .route("/api/v1/account", get(handlers::get_account))
        .route("/api/v1/account", put(handlers::update_account))
        // Note: DELETE /api/v1/account removed - use device-signed deletion instead
        // Keys management endpoints
        .route(
            "/api/v1/users/:id/public-key",
            get(handlers::get_public_key_bundle),
        )
        .route("/api/v1/keys/upload", post(handlers::upload_keys))
        // Username availability check (no auth required)
        .route(
            "/api/v1/users/username/availability",
            get(handlers::check_username_availability),
        )
        // Invite endpoints (Phase 5: Dynamic invite tokens)
        .route("/api/v1/invites/generate", post(handlers::generate_invite))
        .route("/api/v1/invites/accept", post(handlers::accept_invite))
        // Device-signed account deletion (Phase 5.0.1)
        .route(
            "/api/v1/users/me/delete-challenge",
            get(handlers::get_delete_challenge),
        )
        .route(
            "/api/v1/users/me/delete-confirm",
            post(handlers::confirm_delete),
        )
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("User Service listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("Failed to start server")?;

    Ok(())
}
