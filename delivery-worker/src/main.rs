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

mod deduplication;
mod dlq;
mod processor;
mod redis_streams;
mod retry;
mod state;

use anyhow::{Context, Result};
use construct_broker::{MessageConsumer, MessageProducer};
use construct_config::Config;
use construct_server_shared::utils::log_safe_id;
use dlq::{check_and_increment_retry, send_to_dlq};
use processor::{ProcessResult, process_kafka_message};
use state::WorkerState;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    // Small HTTP server for /health and /metrics
    {
        let http_port: u16 = std::env::var("METRICS_PORT")
            .unwrap_or_else(|_| "8085".into())
            .parse()
            .unwrap_or(8085);
        let http_addr: std::net::SocketAddr = format!("0.0.0.0:{}", http_port).parse().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new()
                .route("/health", axum::routing::get(|| async { "ok" }))
                .route(
                    "/metrics",
                    axum::routing::get(construct_server_shared::metrics::metrics_handler),
                );
            let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
            info!("Delivery Worker HTTP/metrics listening on {}", http_addr);
            axum::serve(listener, app).await.unwrap();
        });
    }

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
    let redis_conn = redis::aio::ConnectionManager::new(
        redis::Client::open(config.redis_url.as_str()).context("Failed to create Redis client")?,
    )
    .await
    .context("Failed to create Redis ConnectionManager")?;

    info!("Connected to Redis");

    // Create worker state using the module
    let state = Arc::new(WorkerState::new(config.clone(), redis_conn));

    // Choose delivery mode based on KAFKA_ENABLED
    if config.kafka.enabled {
        info!("Starting Kafka consumer mode (Hybrid Approach)");

        // Shutdown flag — set to true on SIGTERM/Ctrl-C
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_signal = shutdown.clone();

        // Spawn signal handler
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("SIGTERM received, initiating graceful shutdown...");
                    }
                    _ = tokio::signal::ctrl_c() => {
                        info!("SIGINT received, initiating graceful shutdown...");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                info!("Ctrl-C received, initiating graceful shutdown...");
            }
            shutdown_signal.store(true, Ordering::SeqCst);
        });

        run_kafka_consumer_mode(state, shutdown).await
    } else {
        // KAFKA_ENABLED=false → Redis-only mode.
        // In this mode messaging-service writes directly to Redis Streams and
        // uses pub/sub wakeup for real-time delivery. delivery-worker is not
        // needed and exits cleanly so operators don't have to exclude it from
        // their compose file.
        info!("KAFKA_ENABLED=false — running in Redis-only mode.");
        info!("Messages are delivered directly via Redis Streams by messaging-service.");
        info!("delivery-worker is not needed in this mode — exiting cleanly.");
        Ok(())
    }
}

/// Kafka-based delivery worker with proper offset management
///
/// CRITICAL: Offset is committed ONLY for Success and Skipped results.
/// UserOffline results do NOT commit offset - Kafka will redeliver.
/// Processing errors use DLQ after MAX_RETRIES to avoid infinite loops.
async fn run_kafka_consumer_mode(state: Arc<WorkerState>, shutdown: Arc<AtomicBool>) -> Result<()> {
    // Initialize message consumer
    let consumer =
        MessageConsumer::new(&state.config.kafka).context("Failed to initialize Kafka consumer")?;

    // Initialize producer for DLQ
    let dlq_producer = MessageProducer::new(&state.config.kafka)
        .context("Failed to initialize Kafka DLQ producer")?;

    info!("Kafka consumer initialized successfully");
    info!(
        "Polling messages from Kafka topic: {}",
        state.config.kafka.topic
    );

    // Metrics for logging
    let mut messages_delivered: u64 = 0;
    let mut messages_offline: u64 = 0;
    let mut messages_skipped: u64 = 0;
    let mut last_metrics_log = std::time::Instant::now();

    // Main Kafka consumer loop
    while !shutdown.load(Ordering::SeqCst) {
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
                        // Processing error - check retry count before deciding
                        error!(
                            error = %e,
                            message_id = %message_id,
                            recipient_hash = %log_safe_id(&recipient_id, salt),
                            "Failed to process Kafka message"
                        );

                        match check_and_increment_retry(&state, &message_id).await {
                            Ok((true, retry_count)) => {
                                // Exceeded max retries → send to DLQ and commit offset
                                if let Err(dlq_err) = send_to_dlq(
                                    &dlq_producer,
                                    &envelope,
                                    retry_count,
                                    &e.to_string(),
                                )
                                .await
                                {
                                    error!(error = %dlq_err, "Failed to send message to DLQ");
                                }

                                // Commit offset so we don't loop forever
                                if let Err(commit_err) = consumer.commit() {
                                    error!(error = %commit_err, "Failed to commit offset after DLQ");
                                } else {
                                    warn!(
                                        message_id = %message_id,
                                        retry_count = retry_count,
                                        "Message dead-lettered, offset committed"
                                    );
                                }
                            }
                            Ok((false, retry_count)) => {
                                // Still within retry limit - don't commit offset
                                warn!(
                                    message_id = %message_id,
                                    retry_count = retry_count,
                                    "Will retry message (offset NOT committed)"
                                );
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            }
                            Err(redis_err) => {
                                // Can't track retries (Redis down) - don't commit offset
                                error!(error = %redis_err, "Failed to check retry count, not committing offset");
                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            }
                        }
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

    // Graceful shutdown: flush pending Kafka messages before exit
    info!("Shutdown flag set — flushing Kafka producer...");
    if let Err(e) = dlq_producer.flush(std::time::Duration::from_secs(10)).await {
        error!(error = %e, "Failed to flush Kafka producer on shutdown");
    } else {
        info!("Kafka producer flushed successfully");
    }
    info!("Delivery worker stopped gracefully");
    Ok(())
}
