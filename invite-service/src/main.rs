use anyhow::{Context, Result};
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use construct_config::Config;
use construct_server_shared::{auth::AuthManager, db::DbPool, queue::MessageQueue};
use serde_json::json;
use std::{env, sync::Arc};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status, metadata::MetadataMap};
use tracing::info;
use uuid::Uuid;

// Import proto types
use construct_server_shared::shared::proto::services::v1 as proto;
use proto::invite_service_server::{InviteService, InviteServiceServer};

mod core;

/// Shared service context
pub struct InviteServiceContext {
    pub db_pool: Arc<DbPool>,
    pub queue: Arc<Mutex<MessageQueue>>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
}

/// Extract user_id from gRPC metadata (set by auth interceptor)
fn extract_user_id(metadata: &MetadataMap) -> Result<Uuid, Status> {
    let user_id_str = metadata
        .get("x-user-id")
        .ok_or_else(|| Status::unauthenticated("Missing x-user-id metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("Invalid x-user-id format"))?;

    Uuid::parse_str(user_id_str).map_err(|_| Status::unauthenticated("Invalid x-user-id UUID"))
}

/// Extract device_id from gRPC metadata (optional)
fn extract_device_id(metadata: &MetadataMap) -> Option<String> {
    metadata
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// gRPC InviteService implementation
#[derive(Clone)]
struct InviteGrpcService {
    context: Arc<InviteServiceContext>,
}

#[tonic::async_trait]
impl InviteService for InviteGrpcService {
    async fn generate_invite(
        &self,
        request: Request<proto::GenerateInviteRequest>,
    ) -> Result<Response<proto::GenerateInviteResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id(metadata)?;
        let device_id = extract_device_id(metadata);
        let req = request.into_inner();

        // Call core business logic
        let input = core::GenerateInviteInput {
            user_id,
            device_id,
            ttl_seconds: req.ttl_seconds,
        };

        let output = core::generate_invite(&self.context, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to generate invite: {}", e)))?;

        Ok(Response::new(proto::GenerateInviteResponse {
            jti: output.jti,
            server: output.server,
            expires_at: output.expires_at,
            user_id: output.user_id,
            device_id: output.device_id,
            ttl_seconds: output.ttl_seconds,
        }))
    }

    async fn accept_invite(
        &self,
        request: Request<proto::AcceptInviteRequest>,
    ) -> Result<Response<proto::AcceptInviteResponse>, Status> {
        let metadata = request.metadata();
        let accepter_user_id = extract_user_id(metadata)?;
        let req = request.into_inner();

        // Parse InviteToken from proto
        let invite_token = req
            .invite
            .ok_or_else(|| Status::invalid_argument("Missing invite token"))?;

        // Convert proto InviteToken to crypto_agility::InviteToken
        let invite = crypto_agility::InviteToken {
            v: invite_token.v as u32,
            jti: Uuid::parse_str(&invite_token.jti)
                .map_err(|_| Status::invalid_argument("Invalid jti UUID"))?,
            uuid: Uuid::parse_str(&invite_token.uuid)
                .map_err(|_| Status::invalid_argument("Invalid user UUID"))?,
            device_id: invite_token.device_id,
            server: invite_token.server,
            eph_key: invite_token.eph_pub,
            ts: invite_token.ts,
            sig: invite_token.sig,
        };

        // Call core business logic
        let input = core::AcceptInviteInput {
            accepter_user_id,
            invite,
        };

        let output = core::accept_invite(&self.context, input)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to accept invite");
                Status::invalid_argument(format!("Failed to accept invite: {}", e))
            })?;

        Ok(Response::new(proto::AcceptInviteResponse {
            user_id: output.user_id,
            device_id: output.device_id,
            server: output.server,
            message: output.message,
        }))
    }

    async fn revoke_invite(
        &self,
        request: Request<proto::RevokeInviteRequest>,
    ) -> Result<Response<proto::RevokeInviteResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id(metadata)?;
        let req = request.into_inner();

        // Call core business logic
        let input = core::RevokeInviteInput {
            user_id,
            jti: req.jti,
        };

        let output = core::revoke_invite(&self.context, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke invite: {}", e)))?;

        Ok(Response::new(proto::RevokeInviteResponse {
            success: output.success,
            message: output.message,
        }))
    }

    async fn list_invites(
        &self,
        request: Request<proto::ListInvitesRequest>,
    ) -> Result<Response<proto::ListInvitesResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id(metadata)?;
        let req = request.into_inner();

        // Call core business logic
        let input = core::ListInvitesInput {
            user_id,
            limit: req.limit,
            include_expired: req.include_expired.unwrap_or(false),
        };

        let output = core::list_invites(&self.context, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to list invites: {}", e)))?;

        // Convert to proto
        let invites = output
            .invites
            .into_iter()
            .map(|inv| proto::InviteInfo {
                jti: inv.jti,
                user_id: inv.user_id,
                device_id: inv.device_id,
                created_at: inv.created_at,
                expires_at: inv.expires_at,
                used: inv.used,
                used_by: inv.used_by,
                used_at: inv.used_at,
            })
            .collect();

        Ok(Response::new(proto::ListInvitesResponse { invites }))
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&config.rust_log))
        .init();

    info!("=== Invite Service Starting ===");
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
    let context = Arc::new(InviteServiceContext {
        db_pool,
        queue,
        auth_manager,
        config: config.clone(),
    });

    // Start gRPC InviteService
    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("INVITE_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50055".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Invalid INVITE_GRPC_BIND_ADDRESS")?;
    tokio::spawn(async move {
        let service = InviteGrpcService {
            context: grpc_context,
        };
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(InviteServiceServer::new(service))
            .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal())
            .await
        {
            tracing::error!(error = %e, "Invite gRPC server failed");
        }
    });
    info!("Invite gRPC listening on {}", grpc_bind_address);

    // Create REST API router (minimal - mostly for health checks)
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check));

    // Start REST server
    info!("Invite Service REST listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start axum server")?;

    Ok(())
}
