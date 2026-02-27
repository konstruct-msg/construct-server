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
use construct_server_shared::db::DbPool;
use construct_server_shared::kafka::MessageProducer;
use construct_server_shared::messaging_service::MessagingServiceContext;
use construct_server_shared::queue::MessageQueue;
use futures_core::Stream;
use serde_json::json;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use construct_server_shared::shared::proto::services::v1::{
    self as proto,
    messaging_service_server::{MessagingService, MessagingServiceServer},
};
use std::env;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tonic::{Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct MessagingGrpcService {
    context: Arc<MessagingServiceContext>,
}

#[tonic::async_trait]
impl MessagingService for MessagingGrpcService {
    type MessageStreamStream =
        Pin<Box<dyn Stream<Item = Result<proto::MessageStreamResponse, Status>> + Send + 'static>>;

    async fn message_stream(
        &self,
        request: Request<tonic::Streaming<proto::MessageStreamRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        let mut in_stream = request.into_inner();
        let context = self.context.clone();

        // Extract user_id from metadata (set by auth interceptor)
        // For now, we'll require it to be set externally or extract from first message
        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            // Track last seen stream_id for pagination
            let mut last_stream_id: Option<String> = None;
            let mut user_id: Option<uuid::Uuid> = None;

            // Poll interval for checking new messages (5 seconds)
            let mut poll_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    // Handle incoming requests from client
                    Some(result) = in_stream.next() => {
                        match result {
                            Ok(req) => {
                                if let Err(e) = handle_stream_request(
                                    req,
                                    &context,
                                    &tx,
                                    &mut user_id,
                                ).await {
                                    tracing::warn!("Error handling stream request: {}", e);
                                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                                    break;
                                }
                            }
                            Err(e) => {
                                // h2 protocol resets are normal client disconnects, not server errors
                                if e.message().contains("h2 protocol") {
                                    tracing::debug!("MessageStream closed by client: {}", e);
                                } else {
                                    tracing::warn!("Stream error: {}", e);
                                }
                                break;
                            }
                        }
                    }

                    // Poll for new messages periodically
                    _ = poll_interval.tick() => {
                        if let Some(uid) = user_id && let Err(e) = poll_messages(
                                &context,
                                uid,
                                &mut last_stream_id,
                                &tx,
                            ).await {
                                tracing::warn!("Error polling messages: {}", e);
                            }
                        }

                    else => break,
                }
            }

            tracing::info!("MessageStream closed");
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::MessageStreamStream
        ))
    }

    async fn send_message(
        &self,
        request: Request<proto::SendMessageRequest>,
    ) -> Result<Response<proto::SendMessageResponse>, Status> {
        let req = request.into_inner();
        let envelope = req
            .message
            .ok_or_else(|| Status::invalid_argument("message is required"))?;

        let sender = envelope
            .sender
            .ok_or_else(|| Status::invalid_argument("sender is required"))?;
        let sender_id = uuid::Uuid::parse_str(&sender.user_id)
            .map_err(|_| Status::invalid_argument("invalid sender.user_id"))?;

        let recipient = envelope
            .recipient
            .ok_or_else(|| Status::invalid_argument("recipient is required"))?;

        if envelope.encrypted_payload.is_empty() {
            return Err(Status::invalid_argument("encrypted_payload is required"));
        }

        let message_id = uuid::Uuid::new_v4().to_string();

        use construct_server_shared::kafka::types::{KafkaMessageEnvelope, ProtoEnvelopeContext};
        let kafka_envelope = KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
            sender_id: sender_id.to_string(),
            recipient_id: recipient.user_id.clone(),
            message_id: message_id.clone(),
            encrypted_payload: envelope.encrypted_payload.to_vec(),
        });

        let app_context = Arc::new(self.context.to_app_context());
        construct_server_shared::messaging_service::core::dispatch_envelope(
            &app_context,
            kafka_envelope,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(proto::SendMessageResponse {
            message_id,
            message_number: 0,
            server_timestamp: chrono::Utc::now().timestamp_millis(),
            success: true,
            error: None,
        }))
    }

    async fn edit_message(
        &self,
        _request: Request<proto::EditMessageRequest>,
    ) -> Result<Response<proto::EditMessageResponse>, Status> {
        Err(Status::unimplemented("edit_message is not implemented yet"))
    }

    // =========================================================================
    // Reactions RPCs (Stubs)
    // =========================================================================

    async fn add_reaction(
        &self,
        request: Request<proto::AddReactionRequest>,
    ) -> Result<Response<proto::AddReactionResponse>, Status> {
        let req = request.into_inner();

        if req.message_id.is_empty() {
            return Err(Status::invalid_argument("message_id is required"));
        }
        if req.encrypted_reaction.is_empty() {
            return Err(Status::invalid_argument("encrypted_reaction is required"));
        }

        // TODO: Implement add reaction
        // 1. Get authenticated user
        // 2. Validate message exists and user has access
        // 3. Store reaction (encrypted: sender + emoji)
        // 4. Notify message owner via streaming

        Err(Status::unimplemented("AddReaction not implemented yet"))
    }

    async fn remove_reaction(
        &self,
        request: Request<proto::RemoveReactionRequest>,
    ) -> Result<Response<proto::RemoveReactionResponse>, Status> {
        let req = request.into_inner();

        if req.message_id.is_empty() {
            return Err(Status::invalid_argument("message_id is required"));
        }
        if req.reaction_id.is_empty() {
            return Err(Status::invalid_argument("reaction_id is required"));
        }

        // TODO: Implement remove reaction
        // 1. Get authenticated user
        // 2. Validate user owns this reaction
        // 3. Remove reaction from storage
        // 4. Notify message owner via streaming

        Err(Status::unimplemented("RemoveReaction not implemented yet"))
    }

    async fn get_pending_messages(
        &self,
        request: Request<proto::GetPendingMessagesRequest>,
    ) -> Result<Response<proto::GetPendingMessagesResponse>, Status> {
        let user_id = request
            .metadata()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("Missing x-user-id"))?
            .to_string();

        let req = request.into_inner();
        let limit = req.limit.unwrap_or(50).min(100) as usize;
        let since = req.since_cursor.as_deref();

        let mut queue = self.context.queue.lock().await;
        let stream_messages = queue
            .read_user_messages_from_stream(&user_id, None, since, limit)
            .await
            .map_err(|e| Status::internal(format!("Failed to read messages: {}", e)))?;

        // encrypted_payload is opaque — server never reads crypto params from it.
        // Sort is by server timestamp (already chronological from Redis stream).
        let messages: Vec<proto::PendingMessage> = stream_messages
            .into_iter()
            .map(|(_stream_id, env)| {
                use base64::Engine;
                let payload_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&env.encrypted_payload)
                    .unwrap_or_else(|_| env.encrypted_payload.into_bytes());
                proto::PendingMessage {
                    message_id: env.message_id,
                    sender_id: env.sender_id,
                    encrypted_payload: payload_bytes,
                    timestamp: env.timestamp,
                }
            })
            .collect();

        let next_cursor = messages
            .last()
            .map(|m| format!("{}", m.timestamp))
            .unwrap_or_else(|| since.unwrap_or("0-0").to_string());

        let has_more = messages.len() == limit;

        Ok(Response::new(proto::GetPendingMessagesResponse {
            messages,
            next_cursor,
            has_more,
        }))
    }
}

/// Handle incoming MessageStreamRequest from client
async fn handle_stream_request(
    req: proto::MessageStreamRequest,
    context: &Arc<MessagingServiceContext>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
    user_id: &mut Option<uuid::Uuid>,
) -> anyhow::Result<()> {
    use proto::message_stream_request::Request as StreamReq;

    match req.request {
        Some(StreamReq::Send(envelope)) => {
            // Extract user_id from envelope if not set yet
            if user_id.is_none()
                && let Some(sender) = &envelope.sender
            {
                *user_id = Some(uuid::Uuid::parse_str(&sender.user_id)?);
            }

            if let Some(uid) = user_id {
                let recipient_id = envelope
                    .recipient
                    .as_ref()
                    .map(|r| r.user_id.clone())
                    .unwrap_or_default();
                if recipient_id.is_empty() {
                    return Err(anyhow::anyhow!("recipient is required"));
                }
                if envelope.encrypted_payload.is_empty() {
                    return Err(anyhow::anyhow!("encrypted_payload is required"));
                }
                let message_id = uuid::Uuid::new_v4().to_string();

                use construct_server_shared::kafka::types::{
                    KafkaMessageEnvelope, ProtoEnvelopeContext,
                };
                let kafka_envelope =
                    KafkaMessageEnvelope::from_proto_envelope(&ProtoEnvelopeContext {
                        sender_id: uid.to_string(),
                        recipient_id,
                        message_id: message_id.clone(),
                        encrypted_payload: envelope.encrypted_payload.to_vec(),
                    });

                let app_context = Arc::new(context.to_app_context());
                match construct_server_shared::messaging_service::core::dispatch_envelope(
                    &app_context,
                    kafka_envelope,
                )
                .await
                {
                    Ok(()) => {
                        let ack = proto::MessageAck {
                            message_id,
                            message_number: 0,
                            server_timestamp: chrono::Utc::now().timestamp_millis(),
                            delivery_count: 1,
                        };

                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Ack(ack)),
                            response_id: Some(req.request_id.clone()),
                        };

                        tx.send(Ok(response)).await?;
                    }
                    Err(e) => {
                        use construct_server_shared::shared::proto::core::v1 as core;
                        let message_id_str = if let Some(id_type) = &envelope.message_id_type {
                            match id_type {
                                core::envelope::MessageIdType::MessageId(id) => id.clone(),
                                _ => String::new(),
                            }
                        } else {
                            String::new()
                        };

                        let error = proto::MessageError {
                            message_id: message_id_str,
                            error_code: proto::ErrorCode::Unspecified.into(),
                            error_message: e.to_string(),
                            retryable: false,
                        };

                        let response = proto::MessageStreamResponse {
                            response: Some(proto::message_stream_response::Response::Error(error)),
                            response_id: Some(req.request_id.clone()),
                        };

                        tx.send(Ok(response)).await?;
                    }
                }
            }
        }

        Some(StreamReq::Heartbeat(hb)) => {
            let ack = proto::HeartbeatAck {
                timestamp: hb.timestamp,
                server_timestamp: chrono::Utc::now().timestamp_millis(),
            };

            let response = proto::MessageStreamResponse {
                response: Some(proto::message_stream_response::Response::HeartbeatAck(ack)),
                response_id: Some(req.request_id),
            };

            tx.send(Ok(response)).await?;
        }

        // Subscribe/Unsubscribe: conversation_ids are intentionally not logged or stored
        // to avoid leaking the client's contact graph to the server.
        // All messages for this user are already routed to their Redis stream regardless.
        Some(StreamReq::Receipt(_))
        | Some(StreamReq::Typing(_))
        | Some(StreamReq::Subscribe(_))
        | Some(StreamReq::Unsubscribe(_)) => {
            // Not implemented yet
            tracing::debug!("Received unimplemented request type");
        }

        None => {
            tracing::warn!("Received empty stream request");
        }
    }

    Ok(())
}

/// Poll for new messages from Redis Streams
async fn poll_messages(
    context: &Arc<MessagingServiceContext>,
    user_id: uuid::Uuid,
    last_stream_id: &mut Option<String>,
    tx: &mpsc::Sender<Result<proto::MessageStreamResponse, Status>>,
) -> anyhow::Result<()> {
    let user_id_str = user_id.to_string();
    let limit = 50;

    let mut queue = context.queue.lock().await;
    let messages = queue
        .read_user_messages_from_stream(&user_id_str, None, last_stream_id.as_deref(), limit)
        .await?;

    drop(queue);

    for (stream_id, envelope) in messages {
        // Convert KafkaMessageEnvelope to proto::Envelope
        let proto_envelope = convert_kafka_envelope_to_proto(envelope)?;

        let response = proto::MessageStreamResponse {
            response: Some(proto::message_stream_response::Response::Message(
                proto_envelope,
            )),
            response_id: None,
        };

        tx.send(Ok(response)).await?;
        *last_stream_id = Some(stream_id);
    }

    Ok(())
}

/// Convert KafkaMessageEnvelope to proto Envelope
fn convert_kafka_envelope_to_proto(
    envelope: construct_server_shared::kafka::types::KafkaMessageEnvelope,
) -> anyhow::Result<construct_server_shared::shared::proto::core::v1::Envelope> {
    use base64::Engine;
    use construct_server_shared::shared::proto::core::v1 as core;

    // Decode base64 ciphertext back to raw bytes — forwarded verbatim, never read.
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.encrypted_payload)
        .unwrap_or_else(|_| envelope.encrypted_payload.into_bytes());

    Ok(core::Envelope {
        sender: Some(core::UserId {
            user_id: envelope.sender_id,
            domain: None,
            display_name: None,
        }),
        sender_device: None,
        recipient: Some(core::UserId {
            user_id: envelope.recipient_id,
            domain: None,
            display_name: None,
        }),
        recipient_device: None,
        content_type: core::ContentType::E2eeSignal.into(),
        message_id_type: Some(core::envelope::MessageIdType::MessageId(
            envelope.message_id,
        )),
        timestamp: envelope.timestamp,
        ttl: 0,
        priority: core::MessagePriority::Normal.into(),
        encrypted_payload: payload_bytes,
        conversation_id: String::new(),
        server_metadata: None,
        client_metadata: None,
        forwarding_path: vec![],
        ephemeral_seconds: None,
        reply_to_message_id: None,
        edits_message_id: None,
        reactions: vec![],
        mentions: vec![],
    })
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

    // Initialize Kafka Producer
    info!("Connecting to Kafka...");
    let kafka_producer =
        Arc::new(MessageProducer::new(&config.kafka).context("Failed to create Kafka producer")?);
    info!("Connected to Kafka");

    // Initialize Auth Manager
    let auth_manager =
        Arc::new(AuthManager::new(&config).context("Failed to initialize auth manager")?);

    // ✅ NEW: Initialize APNs Client for push notifications
    info!("Initializing APNs client...");
    let apns_client = Arc::new(
        construct_server_shared::apns::ApnsClient::new(config.apns.clone())
            .context("Failed to initialize APNs client")?,
    );
    let token_encryption = Arc::new(
        DeviceTokenEncryption::from_hex(&config.apns.device_token_encryption_key)
            .context("Failed to initialize device token encryption")?,
    );
    if config.apns.enabled {
        info!("APNs client initialized and ENABLED");
    } else {
        info!("APNs client initialized but DISABLED (APNS_ENABLED=false)");
    }

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
    let context = Arc::new(MessagingServiceContext {
        db_pool,
        queue,
        auth_manager,
        kafka_producer,
        apns_client,
        token_encryption,
        config: config.clone(),
        key_management,
    });

    // Import messaging service handlers
    use construct_server_shared::messaging_service::handlers;

    // Start gRPC MessagingService (SVC-3 scaffold)
    let grpc_context = context.clone();
    let grpc_bind_address =
        env::var("MESSAGING_GRPC_BIND_ADDRESS").unwrap_or_else(|_| "[::]:50053".to_string());
    let grpc_addr = grpc_bind_address
        .parse()
        .context("Invalid MESSAGING_GRPC_BIND_ADDRESS")?;
    // Replace bare .serve() with graceful shutdown for gRPC
    tokio::spawn(async move {
        let service = MessagingGrpcService {
            context: grpc_context,
        };
        if let Err(e) = construct_server_shared::grpc_server()
            .add_service(MessagingServiceServer::new(service))
            .serve_with_shutdown(grpc_addr, construct_server_shared::shutdown_signal())
            .await
        {
            tracing::error!(error = %e, "Messaging gRPC server failed");
        }
    });
    info!("Messaging gRPC listening on {}", grpc_bind_address);

    // Import media routes
    use construct_server_shared::routes::media;

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
        // Messaging endpoints
        .route("/api/v1/messages", post(handlers::send_message))
        .route("/api/v1/messages", get(handlers::get_messages))
        // Phase 4.5: Control messages endpoint
        .route("/api/v1/control", post(handlers::send_control_message))
        // Media upload token endpoint
        .route("/api/v1/media/token", post(media::generate_media_token))
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
