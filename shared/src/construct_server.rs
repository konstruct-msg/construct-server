use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Re-export types from modular crates (Phase 4)
pub use construct_crypto::{
    BundleData, EncryptedMessage, MessageType, ServerCryptoValidator, StoredEncryptedMessage,
    UploadableKeyBundle, compute_message_hash,
};
pub use construct_error::AppError;
pub use construct_types::{ChatMessage, ClientMessage, ServerMessage, UserId};

pub mod apns;
pub mod audit;
pub mod auth;
pub mod auth_service;
pub mod context;
pub mod db;
pub mod delivery_ack;
pub mod federation;
pub mod gateway;
pub mod handlers {
    pub mod federation; // Used in routes/federation.rs
}
pub mod health;
pub mod kafka;
pub mod key_management;
// pub mod message_gateway; // TODO PROTO-1: Replace with new gRPC MessagingService
pub mod messaging_service;
pub mod metrics;
pub mod models; // Invite objects and other data models
pub mod notification_service;
pub mod pending_messages; // 2-Phase commit protocol for message delivery
pub mod pow; // Proof of Work for device registration
pub mod queue;
pub mod rate_limit; // ← NEW: Rate limiting & warmup sandbox
pub mod routes;
pub mod server_registry;
pub mod user_service;
pub mod utils;

// Re-export delivery_worker modules for use in bin/delivery_worker.rs
pub mod delivery_worker;

use auth::AuthManager;
use construct_config::Config;
use context::AppContext;
use kafka::MessageProducer;
use queue::MessageQueue;

// Monolithic server - simplified to HTTP-only (WebSocket removed)
// NOTE: This is kept for development/testing only. Production uses microservices.
pub async fn run_http_server(app_context: AppContext, listener: TcpListener) {
    use tower::ServiceBuilder;
    use tower_http::trace::TraceLayer;

    // Create Axum router for HTTP routes
    let app_context_arc = Arc::new(app_context);
    let app = routes::create_router(app_context_arc)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    tracing::info!("Starting HTTP server (WebSocket support removed)");
    axum::serve(listener, app)
        .await
        .expect("HTTP server failed");
}

// WebSocket delivery listener removed - all clients use REST API now
// Delivery worker writes to Redis Streams, clients poll via GET /api/v1/messages

// Legacy code removed - kept for reference only
#[allow(dead_code)]
fn _spawn_delivery_listener_removed(
    _queue: Arc<Mutex<MessageQueue>>,
    _clients: (),
    _server_instance_id: String,
    _config: Arc<Config>,
) {
    // WebSocket delivery removed - clients use REST API long polling instead
    // Delivery worker writes to Redis Streams, clients poll via GET /api/v1/messages
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration first (needed for logging)
    let config = Config::from_env()?;
    let app_config = Arc::new(config);

    // Initialize tracing using config
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            app_config.rust_log.clone(),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let bind_address = format!("[::]:{}", app_config.port);

    // Connect to database
    let db_pool = Arc::new(db::create_pool(&app_config.database_url, &app_config.db).await?);
    tracing::info!("Connected to database");

    // Apply database migrations
    tracing::info!("Applying database migrations...");
    sqlx::migrate!().run(&*db_pool).await?;
    tracing::info!("Database migrations applied successfully.");

    // Connect to Redis
    let redis_url_safe = if let Some(at_pos) = app_config.redis_url.find('@') {
        let protocol_end = app_config.redis_url.find("://").map(|p| p + 3).unwrap_or(0);
        format!(
            "{}***{}",
            &app_config.redis_url[..protocol_end],
            &app_config.redis_url[at_pos..]
        )
    } else {
        app_config.redis_url.clone()
    };
    tracing::info!("Connecting to Redis at: {}", redis_url_safe);

    let message_queue = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        MessageQueue::new(&app_config),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Redis connection timed out after 10 seconds"))??;

    tracing::info!("Connected to Redis");

    let queue = Arc::new(Mutex::new(message_queue));

    // Initialize Kafka producer (Phase 1: Foundation)
    tracing::info!("Initializing Kafka producer...");
    let kafka_producer = MessageProducer::new(&app_config.kafka)?;
    tracing::info!(
        enabled = app_config.kafka.enabled,
        brokers = %app_config.kafka.brokers,
        topic = %app_config.kafka.topic,
        "Kafka producer initialized"
    );
    let kafka_producer = Arc::new(kafka_producer);

    // Initialize APNs client
    tracing::info!("Initializing APNs client...");
    let apns_client = apns::ApnsClient::new(app_config.apns.clone())?;
    if app_config.apns.enabled {
        apns_client.initialize().await?;
        tracing::info!(
            environment = ?app_config.apns.environment,
            key_id = %app_config.apns.key_id,
            "APNs client initialized successfully"
        );
    } else {
        tracing::info!("APNs is disabled");
    }
    let apns_client = Arc::new(apns_client);

    // Initialize device token encryption with key versioning support
    tracing::info!("Initializing device token encryption...");
    let token_encryption = {
        use std::collections::HashMap;

        // Start with primary key (version 1) - backward compatibility
        let mut keys = HashMap::new();
        keys.insert(1, app_config.apns.device_token_encryption_key.clone());

        // Load additional key versions from environment variables
        // Format: APNS_DEVICE_TOKEN_ENCRYPTION_KEY_V2, APNS_DEVICE_TOKEN_ENCRYPTION_KEY_V3, etc.
        let mut current_version = 1u8;

        for version in 2..=10 {
            let env_var = format!("APNS_DEVICE_TOKEN_ENCRYPTION_KEY_V{}", version);
            if let Ok(key) = std::env::var(&env_var) {
                if key.len() != 64 {
                    tracing::warn!(
                        version = version,
                        env_var = %env_var,
                        "APNS_DEVICE_TOKEN_ENCRYPTION_KEY_V{} must be 64 hex characters (32 bytes) - skipping",
                        version
                    );
                    continue;
                }

                if key == "0000000000000000000000000000000000000000000000000000000000000000" {
                    tracing::warn!(
                        version = version,
                        env_var = %env_var,
                        "APNS_DEVICE_TOKEN_ENCRYPTION_KEY_V{} must be changed from default value - skipping",
                        version
                    );
                    continue;
                }

                keys.insert(version, key);
                current_version = version; // Use highest version as current
                tracing::info!(
                    version = version,
                    "Loaded device token encryption key version {}",
                    version
                );
            }
        }

        if keys.len() > 1 {
            tracing::info!(
                active_versions = ?keys.keys().collect::<Vec<_>>(),
                current_version = current_version,
                "Device token encryption initialized with key versioning ({} active keys)",
                keys.len()
            );
            apns::DeviceTokenEncryption::from_keys(keys, current_version)?
        } else {
            tracing::info!("Device token encryption initialized with single key (no versioning)");
            apns::DeviceTokenEncryption::from_hex(&app_config.apns.device_token_encryption_key)?
        }
    };
    let token_encryption = Arc::new(token_encryption);
    tracing::info!(
        current_version = token_encryption.current_version(),
        active_versions = ?token_encryption.active_versions(),
        "Device token encryption initialized"
    );

    // Initialize Delivery ACK system (optional, based on env vars)
    let delivery_ack_manager = match delivery_ack::DeliveryAckConfig::from_env() {
        Ok(ack_config) => {
            tracing::info!("Initializing Delivery ACK system...");
            let storage = Arc::new(delivery_ack::PostgresDeliveryStorage::new(
                (*db_pool).clone(),
            ));
            let manager = Arc::new(delivery_ack::DeliveryAckManager::new(
                storage.clone(),
                ack_config.clone(),
            ));

            // Spawn cleanup task
            let cleanup_task = delivery_ack::DeliveryCleanupTask::new(
                storage,
                std::time::Duration::from_secs(ack_config.cleanup_interval_secs),
            );
            tokio::spawn(async move {
                cleanup_task.run().await;
            });

            tracing::info!(
                expiry_days = ack_config.expiry_days,
                cleanup_interval_secs = ack_config.cleanup_interval_secs,
                "Delivery ACK system initialized"
            );
            Some(manager)
        }
        Err(e) => {
            tracing::info!(
                error = %e,
                "Delivery ACK system disabled (DELIVERY_SECRET_KEY not set)"
            );
            None
        }
    };

    // Create auth manager
    let auth_manager = Arc::new(
        AuthManager::new(&app_config)
            .context("Failed to initialize AuthManager - check JWT configuration (JWT_SECRET or JWT_PRIVATE_KEY/JWT_PUBLIC_KEY)")?
    );

    // Initialize Key Management System (optional, requires VAULT_ADDR)
    let key_management = match key_management::KeyManagementConfig::from_env() {
        Ok(kms_config) => {
            tracing::info!("Initializing Key Management System...");
            match key_management::KeyManagementSystem::new(db_pool.clone(), kms_config).await {
                Ok(kms) => {
                    // Start background tasks (key refresh, rotation)
                    if let Err(e) = kms.start().await {
                        tracing::error!(error = %e, "Failed to start key management background tasks");
                        return Err(format!("Failed to start key management system: {}", e).into());
                    }
                    tracing::info!("Key Management System initialized and started");
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

    // HTTP listener (WebSocket removed - all clients use REST API)
    let listener = TcpListener::bind(&bind_address).await?;
    tracing::info!("Construct server listening on {} (HTTP only)", bind_address);

    // WebSocket clients removed - no longer needed
    // Create a dummy Clients type for compatibility
    let server_instance_id = uuid::Uuid::new_v4().to_string();

    // Create application context using builder pattern
    let mut app_context = AppContext::builder()
        .with_db_pool(db_pool.clone())
        .with_queue(queue.clone())
        .with_auth_manager(auth_manager.clone())
        .with_config(app_config.clone())
        .with_kafka_producer(kafka_producer.clone())
        .with_apns_client(apns_client.clone())
        .with_token_encryption(token_encryption.clone())
        .with_server_instance_id(server_instance_id)
        .build()
        .expect("Failed to build AppContext");

    // Add delivery ACK manager if initialized
    if let Some(manager) = delivery_ack_manager {
        app_context = app_context.with_delivery_ack_manager(manager);
    }

    // Add key management system if initialized
    if let Some(kms) = key_management {
        app_context = app_context.with_key_management(kms);
    }

    // NOTE: WebSocket delivery listener and server registry removed
    // - Clients use REST API long polling (GET /api/v1/messages)
    // - Delivery worker writes to Redis Streams
    // - No need for server instance registration or WebSocket delivery

    let http_server = run_http_server(app_context, listener);

    tokio::select! {
        _ = http_server => {
            tracing::info!("Server shut down.");
        },
        _ = shutdown_signal() => {
            tracing::info!("Shutdown signal received. Shutting down...");
        }
    }

    Ok(())
}

/// Wait for SIGTERM or Ctrl-C — used for graceful shutdown across all services.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.ok();
    }
}

/// Create a pre-configured tonic gRPC server with HTTP/2 keepalive.
///
/// Keepalive pings the client every 20s and closes unresponsive connections after 10s.
/// This prevents silent H2 connection hangs and reduces stream reset noise in logs.
pub fn grpc_server() -> tonic::transport::Server {
    tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(20)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
}
