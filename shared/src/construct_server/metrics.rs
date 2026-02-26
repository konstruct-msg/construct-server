//! Re-export metrics from construct-metrics crate
//!
//! This module exists for backwards compatibility during Phase 5 migration.
//! New code should import directly from `construct_metrics`.

pub use construct_metrics::*;

/// Axum handler that serves Prometheus metrics in text format.
///
/// Add to any HTTP router:
/// ```ignore
/// .route("/metrics", get(construct_server_shared::metrics::metrics_handler))
/// ```
pub async fn metrics_handler() -> axum::response::Response<String> {
    match gather_metrics() {
        Ok(body) => axum::response::Response::builder()
            .status(200)
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .body(body)
            .unwrap(),
        Err(e) => axum::response::Response::builder()
            .status(500)
            .body(format!("Failed to gather metrics: {}", e))
            .unwrap(),
    }
}
