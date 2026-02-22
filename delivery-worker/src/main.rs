// Delivery Worker - Kafka as Single Source of Truth
// ============================================================================
//
// This worker consumes messages from Kafka and delivers them to users.
//
// ARCHITECTURE: Hybrid Approach (Kafka + Redis)
// ============================================================================
//
// Key Principle: Kafka is the SINGLE SOURCE OF TRUTH.
// - Offset is committed ONLY when message is delivered to an ONLINE user
// - For OFFLINE users, offset is NOT committed → Kafka redelivers
// - Redis is used only as a cache/optimization, NOT as source of truth
//
// Flow:
// 1. Kafka Consumer reads message from topic
// 2. Check deduplication (Redis: processed_msg:{message_id})
// 3. Check if recipient is online (Redis: user:{user_id}:server_instance_id)
// 4. If ONLINE:
//    - Push to delivery_stream:{server_instance_id} (Redis Stream)
//    - Mark as processed
//    - COMMIT Kafka offset ✅
// 5. If OFFLINE:
//    - Optionally cache in Redis (optimization only)
//    - DO NOT commit Kafka offset ❌
//    - Message stays in Kafka, will be redelivered
//
// When user comes online:
// 1. Kafka consumer automatically retries (offset not committed)
// 2. User is now online → message delivered → offset committed
//
// Guarantees:
// - Kafka contains ALL messages (source of truth)
// - Messages are NEVER lost (even if Redis fails)
// - At-least-once delivery with deduplication
// - Ordering per user (Kafka partitioning)
//
// ============================================================================

use anyhow::{Context, Result};
use construct_config::Config;
use construct_server_shared::delivery_worker::{ProcessResult, WorkerState, process_kafka_message};
use construct_server_shared::kafka::MessageConsumer;
use construct_server_shared::utils::log_safe_id;
use futures_util::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Notification that a user has come online
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserOnlineNotification {
    /// User ID that came online
    user_id: String,

    /// Unique ID of the server instance handling this user's connection
    server_instance_id: String,
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

    info!("=== Delivery Worker Starting (Kafka as Source of Truth) ===");
    info!("Kafka Enabled: {}", config.kafka.enabled);
    info!("Kafka Brokers: {}", config.kafka.brokers);
    info!("Kafka Topic: {}", config.kafka.topic);
    info!("Kafka Consumer Group: {}", config.kafka.consumer_group);

    // Mask credentials in Redis URL for logging
    let redis_url_safe = if let Some(at_pos) = config.redis_url.find('@') {
        let protocol_end = config.redis_url.find("://").map(|p| p + 3).unwrap_or(0);
        format!(
            "{}***{}",
            &config.redis_url[..protocol_end],
            &config.redis_url[at_pos..]
        )
    } else {
        config.redis_url.clone()
    };
    info!("Connecting to Redis at: {}", redis_url_safe);

    // Connect to Redis
    let client =
        redis::Client::open(config.redis_url.as_str()).context("Failed to create Redis client")?;

    let redis_conn = client
        .get_multiplexed_async_connection()
        .await
        .context("Failed to create Redis data connection")?;

    info!("Connected to Redis");

    // Create worker state using the module
    let state = Arc::new(WorkerState::new(config.clone(), client.clone(), redis_conn));

    // Choose delivery mode based on KAFKA_ENABLED
    if config.kafka.enabled {
        info!("Starting Kafka consumer mode (Hybrid Approach)");
        run_kafka_consumer_mode(state, client).await
    } else {
        error!("Redis-only mode is not supported. Please enable KAFKA_ENABLED=true");
        Err(anyhow::anyhow!(
            "Redis-only mode is deprecated. Use Kafka mode instead."
        ))
    }
}

/// Kafka-based delivery worker with proper offset management
///
/// CRITICAL: Offset is committed ONLY for Success and Skipped results.
/// UserOffline results do NOT commit offset - Kafka will redeliver.
async fn run_kafka_consumer_mode(
    state: Arc<WorkerState>,
    redis_client: redis::Client,
) -> Result<()> {
    // Initialize message consumer
    let consumer =
        MessageConsumer::new(&state.config.kafka).context("Failed to initialize Kafka consumer")?;

    info!("Kafka consumer initialized successfully");
    info!(
        "Polling messages from Kafka topic: {}",
        state.config.kafka.topic
    );

    // Spawn user online notification listener
    let state_clone = state.clone();
    let redis_client_clone = redis_client.clone();
    let _online_notification_handle = tokio::spawn(async move {
        if let Err(e) = run_user_online_notification_listener(state_clone, redis_client_clone).await
        {
            error!(error = %e, "User online notification listener failed");
        }
    });
    info!("Started user online notification listener");
    info!("Subscribed to channel: {}", state.config.online_channel);

    // Metrics for logging
    let mut messages_delivered: u64 = 0;
    let mut messages_offline: u64 = 0;
    let mut messages_skipped: u64 = 0;
    let mut last_metrics_log = std::time::Instant::now();

    // Main Kafka consumer loop
    loop {
        match consumer.poll(std::time::Duration::from_secs(1)).await {
            Ok(Some(envelope)) => {
                let message_id = envelope.message_id.clone();
                let recipient_id = envelope.recipient_id.clone();
                let salt = &state.config.logging.hash_salt;

                // Process message using the module
                match process_kafka_message(&state, &envelope).await {
                    Ok(ProcessResult::Success) => {
                        // Message delivered to online user - COMMIT offset
                        messages_delivered += 1;

                        if let Err(e) = consumer.commit() {
                            error!(
                                error = %e,
                                message_id = %message_id,
                                "Failed to commit Kafka offset after successful delivery"
                            );
                        } else {
                            debug!(
                                message_id = %message_id,
                                recipient_hash = %log_safe_id(&recipient_id, salt),
                                "Message delivered, Kafka offset committed"
                            );
                        }
                    }
                    Ok(ProcessResult::Skipped) => {
                        // Message was already processed - COMMIT offset
                        messages_skipped += 1;

                        if let Err(e) = consumer.commit() {
                            error!(
                                error = %e,
                                message_id = %message_id,
                                "Failed to commit Kafka offset for skipped message"
                            );
                        } else {
                            debug!(
                                message_id = %message_id,
                                "Message skipped (deduplication), Kafka offset committed"
                            );
                        }
                    }
                    Ok(ProcessResult::UserOffline) => {
                        // User is offline - DO NOT COMMIT offset!
                        // Kafka will redeliver this message when we poll again
                        messages_offline += 1;

                        debug!(
                            message_id = %message_id,
                            recipient_hash = %log_safe_id(&recipient_id, salt),
                            "User offline - offset NOT committed, message will be redelivered from Kafka"
                        );

                        // Continue without committing - message stays in Kafka
                        // Small delay to prevent tight loop on offline messages
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        // Processing error - DO NOT COMMIT offset
                        error!(
                            error = %e,
                            message_id = %message_id,
                            recipient_hash = %log_safe_id(&recipient_id, salt),
                            "Failed to process Kafka message - offset NOT committed"
                        );

                        // Continue without committing - message will be redelivered
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }

                // Log metrics periodically (every 30 seconds)
                let now = std::time::Instant::now();
                if now.duration_since(last_metrics_log).as_secs() >= 30 {
                    info!(
                        delivered = messages_delivered,
                        offline = messages_offline,
                        skipped = messages_skipped,
                        "Delivery worker metrics (last 30s)"
                    );
                    messages_delivered = 0;
                    messages_offline = 0;
                    messages_skipped = 0;
                    last_metrics_log = now;
                }
            }
            Ok(None) => {
                // No messages available, continue polling
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                error!(error = %e, "Kafka consumer error");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Listen for user online notifications via Redis Pub/Sub
///
/// When a user comes online, Kafka consumer will automatically retry their messages
/// because offsets were not committed (messages remained in Kafka).
/// This listener is primarily for monitoring and logging.
async fn run_user_online_notification_listener(
    state: Arc<WorkerState>,
    redis_client: redis::Client,
) -> Result<()> {
    loop {
        let mut pubsub_conn = match redis_client.get_async_pubsub().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "Failed to create Redis Pub/Sub connection, retrying in 5s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Subscribe to user online notifications
        if let Err(e) = pubsub_conn
            .subscribe(state.config.online_channel.as_str())
            .await
        {
            error!(
                error = %e,
                channel = %state.config.online_channel,
                "Failed to subscribe to user online notifications, retrying in 5s..."
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }

        info!(
            channel = %state.config.online_channel,
            "Subscribed to user online notifications"
        );

        // Listen for notifications
        let mut stream = pubsub_conn.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "Failed to get Pub/Sub message payload");
                    continue;
                }
            };

            // Parse notification
            let notification: UserOnlineNotification = match serde_json::from_str(&payload) {
                Ok(n) => n,
                Err(e) => {
                    error!(
                        error = %e,
                        payload = %payload,
                        "Failed to parse user online notification JSON"
                    );
                    continue;
                }
            };

            // SECURITY: Hash user_id for privacy
            let salt = &state.config.logging.hash_salt;
            info!(
                user_hash = %log_safe_id(&notification.user_id, salt),
                "User came online - Kafka will redeliver any pending messages (offsets were not committed)"
            );

            // Note: We don't need to explicitly trigger Kafka consumer here.
            // Kafka will automatically redeliver messages because offsets were not committed
            // when user was offline. The consumer will process them on next poll().
        }

        // Stream ended - reconnect
        warn!("Pub/Sub stream ended, reconnecting...");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
