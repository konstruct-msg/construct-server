mod context;
mod core;
mod envelope;
mod grpc;
mod handlers;
mod media_routes;
mod receipts;
mod stream;
mod trust;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use construct_config::Config;
use construct_server_shared::apns::DeviceTokenEncryption;
use construct_server_shared::auth::AuthManager;
use construct_server_shared::clients::notification::NotificationClient;
use construct_server_shared::clients::sentinel::SentinelClient;
use construct_server_shared::db::DbPool;
use construct_server_shared::kafka::MessageProducer;
use construct_server_shared::queue::MessageQueue;
use construct_server_shared::shared::proto::services::v1::messaging_service_server::MessagingServiceServer;
use context::MessagingServiceContext;
use grpc::MessagingGrpcService;
use serde_json::json;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    info!("=== Messaging Service Starting ===");
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

    // Initialize Kafka Producer (or no-op stub when KAFKA_ENABLED=false)
    if config.kafka.enabled {
        info!("Connecting to Kafka/Redpanda...");
    } else {
        info!("KAFKA_ENABLED=false — using Redis Streams for direct delivery");
    }
    let kafka_producer =
        Arc::new(MessageProducer::new(&config.kafka).context("Failed to create message producer")?);
    if config.kafka.enabled {
        info!("Connected to Kafka");
    }

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // Initialize APNs clients — kept for to_app_context() adapter; push is delegated to notification-service
    let apns_client = Arc::new(
        construct_server_shared::apns::ApnsClient::new(config.apns.clone())
            .context("Failed to initialize APNs client (adapter compat)")?,
    );
    let mut sandbox_config = config.apns.clone();
    sandbox_config.environment = construct_config::ApnsEnvironment::Development;
    let apns_sandbox_client = Arc::new(
        construct_server_shared::apns::ApnsClient::new(sandbox_config)
            .context("Failed to initialize APNs sandbox client (adapter compat)")?,
    );
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .context("Failed to initialize device token encryption")?,
    );

    // Initialize notification-service gRPC client for outgoing silent push
    let notification_client = match env::var("NOTIFICATION_SERVICE_URL")
        .or_else(|_| Ok::<_, std::env::VarError>("http://notification:50054".to_string()))
    {
        Ok(url) => match NotificationClient::new(&url) {
            Ok(client) => {
                info!(url = %url, "Notification service gRPC client initialized");
                Some(client)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create notification service gRPC client — push notifications disabled");
                None
            }
        },
        Err(_) => None,
    };

    // Initialize sentinel-service gRPC client for send-path spam/rate protection
    let sentinel_client = match env::var("SENTINEL_SERVICE_URL")
        .unwrap_or_else(|_| "http://sentinel:50059".to_string())
    {
        url if url.is_empty() => None,
        url => match SentinelClient::new(&url) {
            Ok(client) => {
                info!(url = %url, "Sentinel service gRPC client initialized");
                Some(client)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create sentinel service gRPC client — send-path protection disabled");
                None
            }
        },
    };

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

    // Initialize server signer for federation (sealed sender cross-server forwarding)
    let server_signer =
        construct_server_shared::context::AppContext::init_server_signer_pub(&config);

    // Create service context
    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        apns_client,
        apns_sandbox_client,
        token_encryption,
        notification_client,
        sentinel_client,
        config: config.clone(),
        key_management,
        server_signer,
        server_instance_id: uuid::Uuid::new_v4().to_string(),
    });

    // handlers module is local (messaging-service/src/handlers.rs)

    // Start gRPC MessagingService (SVC-3 scaffold)
    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("MESSAGING_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50053".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Invalid MESSAGING_GRPC_BIND_ADDRESS")?;
    // Replace bare .serve() with graceful shutdown for gRPC
    let grpc_keepalive_secs = config.grpc_keepalive_interval_secs;
    tokio::spawn(async move {
        let service = MessagingGrpcService {
            context: grpc_context,
        };
        if let Err(e) = construct_server_shared::grpc_server(grpc_keepalive_secs)
            .add_service(
                MessagingServiceServer::new(service).max_decoding_message_size(512 * 1024), // 512 KB — ~100× real message
            )
            .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal())
            .await
        {
            tracing::error!(error = %e, "Messaging gRPC server failed");
        }
    });
    info!("Messaging gRPC listening on {}", grpc_bind_address);

    // Periodic queue TTL: trim offline streams older than 30 days.
    // Runs every 1 hour. Non-critical — errors are logged but don't stop the service.
    {
        let queue_clone = Arc::clone(&context.queue);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let mut queue = queue_clone.lock().await;
                match queue.trim_streams_by_age(30 * 24 * 3600).await {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!(trimmed = n, "Queue TTL: trimmed old messages");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Queue TTL trim failed (non-critical)");
                    }
                }
            }
        });
    }

    // Create router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        .route("/health/ready", get(health_check))
        .route("/health/live", get(health_check))
        .route(
            "/metrics",
            get(construct_server_shared::metrics::metrics_handler),
        )
        // Phase 4.5: Control messages endpoint
        .route("/api/v1/control", post(handlers::send_control_message))
        // Media upload token endpoint
        .route(
            "/api/v1/media/token",
            post(media_routes::generate_media_token),
        )
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(context);

    // Start server
    info!("Messaging Service listening on {}", config.bind_address);

    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .context("Failed to bind to address")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(construct_server_shared::shutdown_signal())
        .await
        .context("Failed to start server")?;

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================
//
// Pure-function tests that require no external services (no Redis, no DB).
// Run with: cargo test --package messaging-service
//
// Integration tests that need running infrastructure are marked #[ignore]
// and can be run with: cargo test --package messaging-service -- --ignored
// ============================================================================

#[cfg(test)]
mod tests {
    use crate::envelope::convert_kafka_envelope_to_proto;
    use crate::receipts::build_receipt_response;
    use base64::Engine as _;
    use construct_server_shared::kafka::types::{KafkaMessageEnvelope, MessageType};
    use construct_server_shared::shared::proto::services::v1 as proto;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_direct_envelope(
        sender: &str,
        recipient: &str,
        payload_b64: &str,
    ) -> KafkaMessageEnvelope {
        KafkaMessageEnvelope {
            message_id: "msg-001".to_string(),
            sender_id: sender.to_string(),
            recipient_id: recipient.to_string(),
            timestamp: 1_700_000_000,
            message_type: MessageType::DirectMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: payload_b64.to_string(),
            content_hash: "abc123".to_string(),
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
            max_queue_len: None,
        }
    }

    fn make_control_envelope(msg_type_str: &str) -> KafkaMessageEnvelope {
        KafkaMessageEnvelope {
            message_id: "ctrl-001".to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            timestamp: 1_700_000_000,
            message_type: MessageType::ControlMessage,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: msg_type_str.to_string(),
            content_hash: "ctrl-hash".to_string(),
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: false,
            sealed_inner_b64: None,
            edits_message_id: None,
            max_queue_len: None,
        }
    }

    fn make_sealed_envelope(recipient: &str, sealed_b64: &str) -> KafkaMessageEnvelope {
        KafkaMessageEnvelope {
            message_id: "sealed-001".to_string(),
            sender_id: String::new(), // intentionally empty
            recipient_id: recipient.to_string(),
            timestamp: 1_700_000_000,
            message_type: MessageType::SealedSender,
            ephemeral_public_key: None,
            message_number: None,
            mls_payload: None,
            group_id: None,
            encrypted_payload: sealed_b64.to_string(),
            content_hash: "sealed-hash".to_string(),
            crypto_suite_id: 0,
            origin_server: None,
            federated: false,
            server_signature: None,
            is_sealed_sender: true,
            sealed_inner_b64: Some(sealed_b64.to_string()),
            edits_message_id: None,
            max_queue_len: None,
        }
    }

    // ── convert_kafka_envelope_to_proto ──────────────────────────────────────

    #[test]
    fn test_convert_direct_message_sets_sender_recipient() {
        use construct_server_shared::shared::proto::core::v1 as core;
        let env = make_direct_envelope("alice", "bob", "dGVzdA=="); // "test" in base64
        let proto = convert_kafka_envelope_to_proto(env).unwrap();

        assert_eq!(proto.sender.as_ref().unwrap().user_id, "alice");
        assert_eq!(proto.recipient.as_ref().unwrap().user_id, "bob");
        assert_eq!(proto.content_type, i32::from(core::ContentType::E2eeSignal));
        assert!(
            !proto.encrypted_payload.is_empty(),
            "payload should be decoded"
        );
    }

    #[test]
    fn test_convert_end_session_maps_session_reset_content_type() {
        use construct_server_shared::shared::proto::core::v1 as core;
        let env = make_control_envelope("END_SESSION");
        let proto = convert_kafka_envelope_to_proto(env).unwrap();

        assert_eq!(
            proto.content_type,
            i32::from(core::ContentType::SessionReset)
        );
        // Control message payloads must NOT be passed to the decryption layer
        assert!(
            proto.encrypted_payload.is_empty(),
            "END_SESSION must have empty payload"
        );
    }

    #[test]
    fn test_convert_session_reset_maps_session_reset_content_type() {
        use construct_server_shared::shared::proto::core::v1 as core;
        let env = make_control_envelope("SESSION_RESET");
        let proto = convert_kafka_envelope_to_proto(env).unwrap();

        assert_eq!(
            proto.content_type,
            i32::from(core::ContentType::SessionReset)
        );
        assert!(proto.encrypted_payload.is_empty());
    }

    #[test]
    fn test_convert_key_sync_maps_key_sync_content_type() {
        use construct_server_shared::shared::proto::core::v1 as core;
        let env = make_control_envelope("KEY_SYNC");
        let proto = convert_kafka_envelope_to_proto(env).unwrap();

        assert_eq!(proto.content_type, i32::from(core::ContentType::KeySync));
        assert!(proto.encrypted_payload.is_empty());
    }

    #[test]
    fn test_convert_sealed_sender_hides_sender_identity() {
        let sealed_bytes = b"fake-sealed-inner-bytes";
        let b64 = base64::engine::general_purpose::STANDARD.encode(sealed_bytes);
        let env = make_sealed_envelope("bob", &b64);
        let proto = convert_kafka_envelope_to_proto(env).unwrap();

        assert!(proto.sender.is_none(), "sealed sender must hide sender");
        assert_eq!(proto.recipient.as_ref().unwrap().user_id, "bob");

        let sealed = proto.sealed_sender.expect("sealed_sender must be set");
        assert_eq!(
            sealed.sealed_inner, sealed_bytes,
            "sealed_inner bytes must round-trip"
        );
    }

    #[test]
    fn test_convert_direct_message_propagates_edits_message_id() {
        let mut env = make_direct_envelope("alice", "bob", "dGVzdA==");
        env.edits_message_id = Some("original-msg-123".to_string());

        let proto = convert_kafka_envelope_to_proto(env).unwrap();
        assert_eq!(
            proto.edits_message_id,
            Some("original-msg-123".to_string()),
            "edits_message_id must be propagated to proto"
        );
    }

    #[test]
    fn test_convert_direct_message_edits_none_by_default() {
        let env = make_direct_envelope("alice", "bob", "dGVzdA==");
        let proto = convert_kafka_envelope_to_proto(env).unwrap();
        assert!(
            proto.edits_message_id.is_none(),
            "non-edit message must not set edits_message_id"
        );
    }

    // ── build_receipt_response ───────────────────────────────────────────────

    #[test]
    fn test_build_receipt_response_delivered_status() {
        use construct_server_shared::shared::proto::signaling::v1 as signaling;

        let env = KafkaMessageEnvelope::from_receipt(
            "alice".to_string(),
            "bob".to_string(),
            vec!["msg-1".to_string(), "msg-2".to_string()],
            "delivered",
        );

        let response = build_receipt_response(&env).unwrap();
        let receipt = match response.response {
            Some(proto::message_stream_response::Response::Receipt(r)) => r,
            _ => panic!("expected Receipt response"),
        };
        let direct = match receipt.receipt_type {
            Some(signaling::delivery_receipt::ReceiptType::Direct(d)) => d,
            _ => panic!("expected Direct receipt type"),
        };

        assert_eq!(direct.message_ids, vec!["msg-1", "msg-2"]);
        assert_eq!(direct.status, 1, "delivered = status 1");
    }

    #[test]
    fn test_build_receipt_response_read_status() {
        use construct_server_shared::shared::proto::signaling::v1 as signaling;

        let env = KafkaMessageEnvelope::from_receipt(
            "alice".to_string(),
            "bob".to_string(),
            vec!["msg-42".to_string()],
            "read",
        );

        let response = build_receipt_response(&env).unwrap();
        let receipt = match response.response {
            Some(proto::message_stream_response::Response::Receipt(r)) => r,
            _ => panic!("expected Receipt response"),
        };
        let direct = match receipt.receipt_type {
            Some(signaling::delivery_receipt::ReceiptType::Direct(d)) => d,
            _ => panic!("expected Direct receipt type"),
        };

        assert_eq!(direct.status, 2, "read = status 2");
        assert_eq!(direct.message_ids, vec!["msg-42"]);
    }

    #[test]
    fn test_build_receipt_response_invalid_json_returns_error() {
        let mut env = make_direct_envelope("alice", "bob", "");
        env.message_type = MessageType::Receipt;
        env.encrypted_payload = "not-valid-json".to_string();

        let result = build_receipt_response(&env);
        assert!(result.is_err(), "invalid JSON must return error");
    }

    #[test]
    fn test_build_receipt_response_unknown_status_defaults_to_delivered() {
        use construct_server_shared::shared::proto::signaling::v1 as signaling;

        let env = KafkaMessageEnvelope::from_receipt(
            "alice".to_string(),
            "bob".to_string(),
            vec!["msg-99".to_string()],
            "unknown_status",
        );

        let response = build_receipt_response(&env).unwrap();
        let receipt = match response.response {
            Some(proto::message_stream_response::Response::Receipt(r)) => r,
            _ => panic!("expected Receipt response"),
        };
        let direct = match receipt.receipt_type {
            Some(signaling::delivery_receipt::ReceiptType::Direct(d)) => d,
            _ => panic!("expected Direct receipt type"),
        };

        assert_eq!(
            direct.status, 1,
            "unknown status must default to delivered (1)"
        );
    }
}
