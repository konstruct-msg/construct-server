// ============================================================================
// Service Client - Phase 2.6.1
// ============================================================================
//
// HTTP client for communicating with microservices.
// Handles:
// - Request forwarding
// - Response proxying
// - Error handling
// - Circuit breaker (Phase 2.6.6)
// - Retry logic (future)
//
// ============================================================================

use crate::gateway::circuit_breaker::{CircuitBreaker, CircuitState};
use crate::metrics::{
    GATEWAY_CIRCUIT_BREAKER_STATE, GATEWAY_REQUEST_DURATION_SECONDS, GATEWAY_REQUESTS_TOTAL,
};
use anyhow::Result;
use axum::body::Body;
use axum::http::{Request, Response};
use construct_config::CircuitBreakerConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, warn};

/// HTTP client for forwarding requests to microservices
pub struct ServiceClient {
    client: reqwest::Client,
    #[allow(dead_code)]
    timeout: Duration,
    /// Circuit breakers per service
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    circuit_breaker_config: Arc<CircuitBreakerConfig>,
}

impl ServiceClient {
    pub fn new(timeout_secs: u64) -> Self {
        Self::new_with_circuit_breaker(
            timeout_secs,
            Arc::new(CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 2,
                timeout_secs: 60,
            }),
        )
    }

    pub fn new_with_circuit_breaker(
        timeout_secs: u64,
        circuit_breaker_config: Arc<CircuitBreakerConfig>,
    ) -> Self {
        // Configure connection pooling and keep-alive
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            timeout: Duration::from_secs(timeout_secs),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            circuit_breaker_config,
        }
    }

    /// Get or create circuit breaker for a service
    async fn get_circuit_breaker(&self, service_name: &str) -> CircuitBreaker {
        // Check if circuit breaker already exists
        {
            let breakers = self.circuit_breakers.read().await;
            if let Some(breaker) = breakers.get(service_name) {
                return breaker.clone();
            }
        }

        // Create new circuit breaker
        let breaker = CircuitBreaker::new(self.circuit_breaker_config.clone());
        {
            let mut breakers = self.circuit_breakers.write().await;
            breakers.insert(service_name.to_string(), breaker.clone());
        }
        breaker
    }

    /// Forward HTTP request to a service
    pub async fn forward_request(
        &self,
        service_url: &str,
        service_name: &str,
        request: Request<Body>,
    ) -> Result<Response<Body>> {
        let start_time = Instant::now();

        // Check circuit breaker
        let breaker = self.get_circuit_breaker(service_name).await;

        // Update circuit breaker state metric
        self.update_circuit_breaker_metric(service_name, &breaker)
            .await;

        // Check if request is allowed
        if let Err(e) = breaker.allow_request().await {
            error!(
                service = service_name,
                service_url = %service_url,
                error = %e,
                "Circuit breaker is open, rejecting request"
            );
            // Record metric for rejected request
            GATEWAY_REQUESTS_TOTAL
                .with_label_values(&[service_name, "503"])
                .inc();
            return Err(anyhow::anyhow!("Circuit breaker is open: {}", e));
        }
        // Build target URL
        let path = request.uri().path();
        let query = request.uri().query();
        let target_url = if let Some(query) = query {
            format!("{}{}?{}", service_url, path, query)
        } else {
            format!("{}{}", service_url, path)
        };

        // Convert Axum request to reqwest request
        let method = request.method().clone();
        let headers = request.headers().clone();

        // Read body
        let (_parts, body) = request.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;

        // Build reqwest request
        let mut reqwest_request = self.client.request(method, &target_url);

        // Copy headers (except Host, which will be set by reqwest)
        for (key, value) in headers.iter() {
            if key != "host" {
                reqwest_request = reqwest_request.header(key, value);
            }
        }

        // Add body if present
        if !body_bytes.is_empty() {
            reqwest_request = reqwest_request.body(body_bytes.to_vec());
        }

        // Execute request
        let result = reqwest_request.send().await;

        // Handle response and update circuit breaker
        let duration = start_time.elapsed();
        match result {
            Ok(response) => {
                let status = response.status();
                let status_code = status.as_u16();
                let status_code_str = status_code.to_string();

                // Record success or failure based on status code
                if status.is_success() || status.is_redirection() {
                    breaker.record_success().await;
                } else if status.is_server_error() {
                    // 5xx errors are considered failures
                    breaker.record_failure().await;
                } else {
                    // 4xx errors are client errors, not service failures
                    // Don't count them as circuit breaker failures
                    breaker.record_success().await;
                }

                // Update metrics
                GATEWAY_REQUESTS_TOTAL
                    .with_label_values(&[service_name, &status_code_str])
                    .inc();
                GATEWAY_REQUEST_DURATION_SECONDS
                    .with_label_values(&[service_name])
                    .observe(duration.as_secs_f64());

                // Update circuit breaker state metric
                self.update_circuit_breaker_metric(service_name, &breaker)
                    .await;

                // Convert reqwest response to Axum response
                let mut axum_response = Response::builder().status(status);

                // Copy headers
                for (key, value) in response.headers().iter() {
                    axum_response = axum_response.header(key, value);
                }

                // Read response body
                let body_bytes = response.bytes().await?;

                Ok(axum_response
                    .body(Body::from(body_bytes.to_vec()))
                    .map_err(|e| anyhow::anyhow!("Failed to build response: {}", e))?)
            }
            Err(e) => {
                // Network errors are failures
                breaker.record_failure().await;

                // Update metrics
                GATEWAY_REQUESTS_TOTAL
                    .with_label_values(&[service_name, "502"])
                    .inc();
                GATEWAY_REQUEST_DURATION_SECONDS
                    .with_label_values(&[service_name])
                    .observe(duration.as_secs_f64());

                // Update circuit breaker state metric
                self.update_circuit_breaker_metric(service_name, &breaker)
                    .await;

                // Log error with context
                let error_msg = e.to_string();
                // Check if this is a connection error (common with proxy issues)
                if error_msg.contains("invalid authority")
                    || error_msg.contains("client error")
                    || error_msg.contains("SendRequest")
                    || error_msg.contains("connection")
                {
                    // These are often proxy/infrastructure issues, log at warn level
                    warn!(
                        service = service_name,
                        service_url = %service_url,
                        error = %e,
                        "Service request failed (possible proxy/infrastructure issue)"
                    );
                } else {
                    error!(
                        service = service_name,
                        service_url = %service_url,
                        error = %e,
                        "Service request failed"
                    );
                }

                Err(anyhow::anyhow!("Request failed: {}", e))
            }
        }
    }

    /// Update circuit breaker state metric
    async fn update_circuit_breaker_metric(&self, service_name: &str, breaker: &CircuitBreaker) {
        let state = breaker.state().await;
        let state_value = match state {
            CircuitState::Closed => 0.0,
            CircuitState::Open => 1.0,
            CircuitState::HalfOpen => 2.0,
        };
        GATEWAY_CIRCUIT_BREAKER_STATE
            .with_label_values(&[service_name])
            .set(state_value);
    }

    /// Check if a service is healthy
    pub async fn check_health(&self, service_url: &str, service_name: &str) -> bool {
        let health_url = format!("{}/health", service_url);
        let is_healthy = match self
            .client
            .get(&health_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(e) => {
                warn!(service_url = %service_url, error = %e, "Service health check failed");
                false
            }
        };

        // Update health metric
        use crate::metrics::GATEWAY_SERVICE_HEALTH;
        GATEWAY_SERVICE_HEALTH
            .with_label_values(&[service_name])
            .set(if is_healthy { 1.0 } else { 0.0 });

        is_healthy
    }
}
