use crate::db::DbPool;
use crate::kafka::MessageProducer;
use crate::queue::MessageQueue;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Health check result with component status
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatus {
    pub status: String, // "healthy" or "unhealthy"
    pub database: ComponentStatus,
    pub redis: ComponentStatus,
    pub kafka: ComponentStatus,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentStatus {
    pub status: String, // "healthy" or "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Full health check (for /health endpoint)
/// Checks all components: database, Redis, Kafka
pub async fn health_check(
    pool: &DbPool,
    queue: Arc<Mutex<MessageQueue>>,
    kafka_producer: Option<Arc<MessageProducer>>,
) -> Result<()> {
    // Check database
    sqlx::query("SELECT 1").execute(pool).await?;

    // Check Redis
    queue.lock().await.ping().await?;

    // Check Kafka (if available and enabled)
    if let Some(kafka_producer) = kafka_producer {
        if kafka_producer.is_enabled() {
            // Kafka producer is initialized and connected
            // The producer will fail on first send if broker is unreachable
            tracing::debug!("Kafka producer is enabled and initialized");
        }
    } else {
        tracing::debug!("Kafka producer not available");
    }

    Ok(())
}

/// Readiness probe for Kubernetes
/// Checks if the service is ready to accept traffic
/// Verifies: database, Redis, Kafka (if enabled)
pub async fn readiness_check(
    pool: &DbPool,
    queue: Arc<Mutex<MessageQueue>>,
    kafka_producer: Option<Arc<MessageProducer>>,
) -> Result<HealthStatus> {
    let mut health = HealthStatus {
        status: "healthy".to_string(),
        database: ComponentStatus {
            status: "healthy".to_string(),
            error: None,
        },
        redis: ComponentStatus {
            status: "healthy".to_string(),
            error: None,
        },
        kafka: ComponentStatus {
            status: "healthy".to_string(),
            error: None,
        },
    };

    // Check database
    match sqlx::query("SELECT 1").execute(pool).await {
        Ok(_) => {
            health.database.status = "healthy".to_string();
        }
        Err(e) => {
            health.status = "unhealthy".to_string();
            health.database.status = "error".to_string();
            health.database.error = Some(format!("Database connection failed: {}", e));
        }
    }

    // Check Redis
    match queue.lock().await.ping().await {
        Ok(_) => {
            health.redis.status = "healthy".to_string();
        }
        Err(e) => {
            health.status = "unhealthy".to_string();
            health.redis.status = "error".to_string();
            health.redis.error = Some(format!("Redis connection failed: {}", e));
        }
    }

    // Check Kafka (if available and enabled)
    if let Some(kafka_producer) = kafka_producer {
        if kafka_producer.is_enabled() {
            // Kafka producer is initialized and connected
            // The producer will fail on first send if broker is unreachable
            // For readiness, we just check if it's enabled and initialized
            health.kafka.status = "healthy".to_string();
            tracing::debug!("Kafka producer is enabled and initialized");
        } else {
            // Kafka is not enabled, mark as ok (not required)
            health.kafka.status = "healthy".to_string();
        }
    } else {
        // Kafka producer not available, mark as ok (not required)
        health.kafka.status = "healthy".to_string();
        tracing::debug!("Kafka producer not available");
    }

    if health.status == "unhealthy" {
        return Err(anyhow::anyhow!(
            "Readiness check failed: one or more components are unhealthy"
        ));
    }

    Ok(health)
}

/// Liveness probe for Kubernetes
/// Checks if the process is alive
/// Minimal check - just returns OK if process is running
pub async fn liveness_check() -> Result<HealthStatus> {
    // Liveness check is minimal - just verify the process is running
    // No external dependencies checked
    Ok(HealthStatus {
        status: "alive".to_string(),
        database: ComponentStatus {
            status: "healthy".to_string(),
            error: None,
        },
        redis: ComponentStatus {
            status: "healthy".to_string(),
            error: None,
        },
        kafka: ComponentStatus {
            status: "healthy".to_string(),
            error: None,
        },
    })
}
