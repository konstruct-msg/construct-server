//! Re-export metrics from construct-metrics crate
//!
//! This module exists for backwards compatibility during Phase 5 migration.
//! New code should import directly from `construct_metrics`.

pub use construct_metrics::*;

/// Axum handler that serves Prometheus metrics in text format.
///
/// On the first scrape automatically marks the service as healthy via
/// `gateway_service_health{service=SERVICE_NAME}` = 1.0.
/// Set `SERVICE_NAME` env var in each service's docker-compose definition.
///
/// Add to any HTTP router:
/// ```ignore
/// .route("/metrics", get(construct_server_shared::metrics::metrics_handler))
/// ```
pub async fn metrics_handler() -> axum::response::Response<String> {
    // Auto-register health on first scrape using SERVICE_NAME env var.
    static HEALTH_REGISTERED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    HEALTH_REGISTERED.get_or_init(|| {
        if let Ok(name) = std::env::var("SERVICE_NAME") {
            let label: &'static str = Box::leak(name.into_boxed_str());
            GATEWAY_SERVICE_HEALTH.with_label_values(&[label]).set(1.0);
        }
    });
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

/// Call this once at service startup to mark the service as healthy in Prometheus.
///
/// Sets `gateway_service_health{service="<name>"}` = 1.0 so the INFRA dashboard
/// panel shows a green UP tile immediately after boot. The value stays 1 for the
/// lifetime of the process — it drops out of Prometheus scrape results (and the
/// panel turns grey) if the service crashes and stops responding to `/metrics`.
///
/// ```ignore
/// construct_server_shared::metrics::register_service_health("messaging");
/// ```
pub fn register_service_health(service: &'static str) {
    GATEWAY_SERVICE_HEALTH
        .with_label_values(&[service])
        .set(1.0);
}
