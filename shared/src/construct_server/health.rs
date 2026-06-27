use crate::db::DbPool;
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentStatus {
    pub status: String, // "healthy" or "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Full health check (for /health endpoint)
/// Checks all components: database, Redis
pub async fn health_check(pool: &DbPool, queue: Arc<Mutex<MessageQueue>>) -> Result<()> {
    sqlx::query("SELECT 1").execute(pool).await?;
    queue.lock().await.ping().await?;
    Ok(())
}

/// Readiness probe for Kubernetes
/// Checks if the service is ready to accept traffic
pub async fn readiness_check(
    pool: &DbPool,
    queue: Arc<Mutex<MessageQueue>>,
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
    };

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

    if health.status == "unhealthy" {
        return Err(anyhow::anyhow!(
            "Readiness check failed: one or more components are unhealthy"
        ));
    }

    Ok(health)
}

/// Liveness probe for Kubernetes
pub async fn liveness_check() -> Result<HealthStatus> {
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
    })
}

/// Axum handler: GET /health/ready — wraps `readiness_check` for use with `State<Arc<AppContext>>`.
pub async fn readiness_check_handler(
    axum::extract::State(app_context): axum::extract::State<
        Arc<crate::construct_server::context::AppContext>,
    >,
) -> Result<impl axum::response::IntoResponse, construct_error::AppError> {
    match readiness_check(&app_context.db_pool, app_context.queue.clone()).await {
        Ok(s) => Ok((
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({
                "status": s.status,
                "database": { "status": s.database.status, "error": s.database.error },
                "redis": { "status": s.redis.status, "error": s.redis.error }
            })),
        )),
        Err(e) => Ok((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "status": "unhealthy", "error": format!("{}", e) })),
        )),
    }
}

/// Axum handler: GET /health/live — minimal liveness probe.
pub async fn liveness_check_handler()
-> Result<impl axum::response::IntoResponse, construct_error::AppError> {
    match liveness_check().await {
        Ok(s) => Ok((
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({ "status": s.status })),
        )),
        Err(e) => Ok((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "status": "error", "error": format!("{}", e) })),
        )),
    }
}
