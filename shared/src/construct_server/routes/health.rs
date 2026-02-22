// ============================================================================
// Health and Metrics Routes
// ============================================================================
//
// Endpoints:
// - GET /health - Health check (database, Redis, Kafka) - legacy endpoint
// - GET /health/ready - Readiness probe for Kubernetes (checks all dependencies)
// - GET /health/live - Liveness probe for Kubernetes (minimal check)
// - GET /metrics - Prometheus metrics
//
// ============================================================================

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::context::AppContext;
use crate::health;
use crate::metrics;
use construct_error::AppError;

/// GET /health
/// Health check endpoint
pub async fn health_check(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    match health::health_check(
        &app_context.db_pool,
        app_context.queue.clone(),
        app_context.kafka_producer.clone(),
    )
    .await
    {
        Ok(_) => Ok((StatusCode::OK, "OK")),
        Err(e) => {
            tracing::error!("Health check failed: {}", e);
            Ok((StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"))
        }
    }
}

/// GET /health/ready
/// Readiness probe for Kubernetes
///
/// Checks if the service is ready to accept traffic:
/// - Database connection
/// - Redis connection
/// - Kafka producer (if enabled)
///
/// Returns 200 OK if all dependencies are healthy, 503 Service Unavailable otherwise
pub async fn readiness_check(
    State(app_context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, AppError> {
    match health::readiness_check(
        &app_context.db_pool,
        app_context.queue.clone(),
        app_context.kafka_producer.clone(),
    )
    .await
    {
        Ok(health_status) => Ok((
            StatusCode::OK,
            Json(json!({
                "status": health_status.status,
                "database": {
                    "status": health_status.database.status,
                    "error": health_status.database.error
                },
                "redis": {
                    "status": health_status.redis.status,
                    "error": health_status.redis.error
                },
                "kafka": {
                    "status": health_status.kafka.status,
                    "error": health_status.kafka.error
                }
            })),
        )),
        Err(e) => {
            tracing::warn!("Readiness check failed: {}", e);
            // Return 503 with error details
            Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "unhealthy",
                    "error": format!("Readiness check failed: {}", e)
                })),
            ))
        }
    }
}

/// GET /health/live
/// Liveness probe for Kubernetes
///
/// Minimal check - just verifies the process is running.
/// Does not check external dependencies (database, Redis, Kafka).
///
/// Always returns 200 OK if the process is alive.
pub async fn liveness_check() -> Result<impl IntoResponse, AppError> {
    match health::liveness_check().await {
        Ok(health_status) => Ok((
            StatusCode::OK,
            Json(json!({
                "status": health_status.status
            })),
        )),
        Err(e) => {
            // This should never happen for liveness check, but handle it anyway
            tracing::error!("Liveness check failed (unexpected): {}", e);
            Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "error": format!("Liveness check failed: {}", e)
                })),
            ))
        }
    }
}

/// GET /metrics
/// Prometheus metrics endpoint
pub async fn metrics() -> Result<impl IntoResponse, AppError> {
    match metrics::gather_metrics() {
        Ok(metrics_data) => Ok((
            StatusCode::OK,
            [("Content-Type", "text/plain; version=0.0.4")],
            metrics_data,
        )),
        Err(e) => {
            tracing::error!("Failed to gather metrics: {}", e);
            Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                [("Content-Type", "text/plain")],
                "Internal Server Error".to_string(),
            ))
        }
    }
}
