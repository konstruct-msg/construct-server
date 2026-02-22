// ============================================================================
// Notification Service - Phase 2.6.5
// ============================================================================
//
// Notification service for microservices architecture.
// Handles:
// - Device token registration (POST /api/v1/notifications/register-device)
// - Device token unregistration (POST /api/v1/notifications/unregister-device)
// - Notification preferences (PUT /api/v1/notifications/preferences)
// - Push notifications (APNs for iOS, FCM for Android - future)
//
// Architecture:
// - Stateless sending
// - Can scale independently
// - Rate limiting for APNs/FCM
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
use construct_server_shared::apns::{ApnsClient, DeviceTokenEncryption};
use construct_server_shared::auth::AuthManager;
use construct_server_shared::db::DbPool;
use construct_server_shared::notification_service::NotificationServiceContext;
use construct_server_shared::queue::MessageQueue;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status, metadata::MetadataMap, transport::Server};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

// Import generated proto types
use construct_server_shared::shared::proto::services::v1 as proto;
use proto::notification_service_server::{NotificationService, NotificationServiceServer};

mod core;

/// Extract user_id from gRPC metadata (set by auth interceptor)
fn extract_user_id(metadata: &MetadataMap) -> Result<Uuid, Status> {
    let user_id_str = metadata
        .get("x-user-id")
        .ok_or_else(|| Status::unauthenticated("Missing x-user-id metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("Invalid x-user-id format"))?;

    Uuid::parse_str(user_id_str).map_err(|_| Status::unauthenticated("Invalid x-user-id UUID"))
}

/// gRPC implementation of NotificationService
struct NotificationGrpcService {
    context: Arc<NotificationServiceContext>,
}

#[tonic::async_trait]
impl NotificationService for NotificationGrpcService {
    async fn send_blind_notification(
        &self,
        request: Request<proto::SendBlindNotificationRequest>,
    ) -> Result<Response<proto::SendBlindNotificationResponse>, Status> {
        let _metadata = request.metadata();

        // Note: SendBlindNotification typically called by internal services, not clients
        // For now, we'll require auth but allow it to be called without x-user-id
        // by using the user_id from the request payload
        let req = request.into_inner();

        let user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user_id"))?;

        let input = core::SendBlindNotificationInput {
            user_id,
            badge_count: req.badge_count,
            activity_type: req.activity_type,
        };

        let output = core::send_blind_notification(&self.context, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to send notification: {}", e)))?;

        Ok(Response::new(proto::SendBlindNotificationResponse {
            success: output.success,
        }))
    }

    async fn register_device_token(
        &self,
        request: Request<proto::RegisterDeviceTokenRequest>,
    ) -> Result<Response<proto::RegisterDeviceTokenResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id(metadata)?;
        let req = request.into_inner();

        let input = core::RegisterDeviceTokenInput {
            user_id,
            device_token: req.device_token,
            device_name: req.device_name,
            notification_filter: req.notification_filter,
        };

        let output = core::register_device_token(&self.context, input)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to register device token");
                Status::internal(format!("Failed to register device token: {}", e))
            })?;

        Ok(Response::new(proto::RegisterDeviceTokenResponse {
            success: output.success,
            token_id: output.token_id,
        }))
    }

    async fn unregister_device_token(
        &self,
        request: Request<proto::UnregisterDeviceTokenRequest>,
    ) -> Result<Response<proto::UnregisterDeviceTokenResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id(metadata)?;
        let req = request.into_inner();

        let input = core::UnregisterDeviceTokenInput {
            user_id,
            device_token: req.device_token,
        };

        let output = core::unregister_device_token(&self.context, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to unregister device token: {}", e)))?;

        Ok(Response::new(proto::UnregisterDeviceTokenResponse {
            success: output.success,
        }))
    }

    async fn update_notification_preferences(
        &self,
        request: Request<proto::UpdateNotificationPreferencesRequest>,
    ) -> Result<Response<proto::UpdateNotificationPreferencesResponse>, Status> {
        let metadata = request.metadata();
        let user_id = extract_user_id(metadata)?;
        let req = request.into_inner();

        let input = core::UpdateNotificationPreferencesInput {
            user_id,
            device_token: req.device_token,
            notification_filter: req.notification_filter,
            enabled: req.enabled,
        };

        let output = core::update_notification_preferences(&self.context, input)
            .await
            .map_err(|e| Status::internal(format!("Failed to update preferences: {}", e)))?;

        Ok(Response::new(
            proto::UpdateNotificationPreferencesResponse {
                success: output.success,
            },
        ))
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

    info!("=== Notification Service Starting ===");
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

    // Initialize APNs Client
    info!("Initializing APNs client...");
    let apns_client =
        Arc::new(ApnsClient::new(config.apns.clone()).context("Failed to initialize APNs client")?);
    info!("APNs client initialized");

    // Initialize Device Token Encryption
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .context("Failed to initialize device token encryption")?,
    );

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

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
    let context = Arc::new(NotificationServiceContext {
        db_pool,
        queue,
        auth_manager,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management,
    });

    // Import notification service handlers
    use construct_server_shared::notification_service::handlers;

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        // Notification endpoints
        .route(
            "/api/v1/notifications/register-device",
            post(handlers::register_device),
        )
        .route(
            "/api/v1/notifications/unregister-device",
            post(handlers::unregister_device),
        )
        .route(
            "/api/v1/notifications/preferences",
            put(handlers::update_preferences),
        )
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context.clone());

    // Prepare gRPC server
    let grpc_bind_address = std::env::var("NOTIFICATION_GRPC_BIND_ADDRESS")
        .unwrap_or_else(|_| "[::]:50054".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Failed to parse NOTIFICATION_GRPC_BIND_ADDRESS")?;

    let grpc_service = NotificationGrpcService {
        context: context.clone(),
    };

    info!("Starting Notification Service...");
    info!("REST API listening on {}", config.bind_address);
    info!("gRPC API listening on {}", grpc_bind_address);

    // Start both servers concurrently
    let rest_server = async move {
        let listener = tokio::net::TcpListener::bind(&config.bind_address)
            .await
            .context("Failed to bind REST server")?;

        axum::serve(listener, app)
            .await
            .context("Failed to start REST server")
    };

    let grpc_server = async move {
        Server::builder()
            .add_service(NotificationServiceServer::new(grpc_service))
            .serve(grpc_addr)
            .await
            .context("Failed to start gRPC server")
    };

    // Run both servers, exit if either fails
    tokio::select! {
        result = rest_server => {
            result?;
        }
        result = grpc_server => {
            result?;
        }
    }

    Ok(())
}
