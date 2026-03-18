// ============================================================================
// Axum Middleware
// ============================================================================
//
// Middleware for request processing:
// - request_logging: Log all incoming requests
// - add_security_headers: Add security headers to responses
// - metrics_auth: Protect /metrics endpoint
//
// Note: CSRF protection removed — all core functionality is gRPC only.
// Remaining REST endpoints (health, metrics, federation) are read-only or
// use server-side signatures.
//
// ============================================================================

use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::time::Instant;

use crate::routes::extractors::TrustedUser;
use construct_error::AppError;
use construct_server_shared::context::AppContext;
use construct_server_shared::utils::{
    add_security_headers as utils_add_security_headers, extract_client_ip,
};
use subtle::ConstantTimeEq;

/// Request logging middleware
pub async fn request_logging(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    tracing::debug!(
        method = %method,
        path = %path,
        "Incoming request"
    );

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status();

    tracing::info!(
        method = %method,
        path = %path,
        status = %status.as_u16(),
        duration_ms = duration.as_millis(),
        "Request completed"
    );

    response
}

/// Add security headers to responses
pub async fn add_security_headers(req: Request, next: Next) -> Response {
    // Extract HTTPS status before moving req
    let is_https = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false);

    let mut response = next.run(req).await;

    // Convert axum headers to hyper headers for the utility function
    let mut hyper_headers = hyper::HeaderMap::new();
    for (key, value) in response.headers() {
        if let Ok(header_name) = hyper::header::HeaderName::from_bytes(key.as_str().as_bytes())
            && let Ok(header_value) = hyper::header::HeaderValue::from_bytes(value.as_bytes())
        {
            hyper_headers.insert(header_name, header_value);
        }
    }

    // Add security headers
    utils_add_security_headers(&mut hyper_headers, is_https);

    // Copy back to axum response
    response.headers_mut().clear();
    for (key, value) in hyper_headers {
        if let (Some(name), Ok(val)) = (key, axum::http::HeaderValue::from_bytes(value.as_bytes()))
        {
            response.headers_mut().insert(name, val);
        }
    }

    response
}

/// IP-based Rate Limiting Middleware
///
/// Implements rate limiting based on client IP address for anonymous operations
/// (login, registration, password reset, etc.).
///
/// Strategy:
/// - For anonymous operations: Only IP-based rate limiting
/// - For authenticated operations: Combined (user_id + IP) rate limiting (applied separately)
///
/// This middleware should be applied to endpoints that don't require authentication.
/// For authenticated endpoints, use the combined rate limiting in the handler.
#[allow(dead_code)]
pub async fn ip_rate_limiting(
    State(ctx): State<Arc<AppContext>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Skip rate limiting if disabled
    if !ctx.config.security.ip_rate_limiting_enabled {
        return Ok(next.run(req).await);
    }

    // Skip for safe methods (GET, HEAD, OPTIONS)
    if matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    ) {
        return Ok(next.run(req).await);
    }

    // Skip for health/metrics endpoints
    let path = req.uri().path();
    if path == "/health" || path == "/metrics" || path.starts_with("/federation/health") {
        return Ok(next.run(req).await);
    }

    // Extract client IP from headers
    // Note: In production, ensure your reverse proxy (Caddy, nginx) sets X-Forwarded-For
    // and strips any existing X-Forwarded-For from untrusted sources
    let headers = req.headers();
    let client_ip = extract_client_ip(headers, None);

    // Check IP-based rate limit
    {
        let mut queue = ctx.queue.lock().await;
        match queue.increment_ip_message_count(&client_ip).await {
            Ok(count) => {
                let max_ip_requests = ctx.config.security.max_requests_per_ip_per_hour;
                if count > max_ip_requests {
                    drop(queue);
                    tracing::warn!(
                        ip = %client_ip,
                        count = count,
                        limit = max_ip_requests,
                        path = %path,
                        "IP rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} requests per hour from this IP",
                        max_ip_requests
                    )));
                }
            }
            Err(e) => {
                tracing::error!(error = %e, ip = %client_ip, "Failed to check IP rate limit");
                // Fail open - continue but log error
            }
        }
    }

    Ok(next.run(req).await)
}

/// Combined Rate Limiting Middleware (user_id + IP)
///
/// Implements rate limiting based on both user_id and IP address for authenticated operations.
/// This provides more precise rate limiting:
/// - Same user from different IPs: separate limits per IP
/// - Different users from same IP: separate limits per user
///
/// This middleware should be applied to authenticated endpoints.
/// It requires TrustedUser extractor to be applied first (Gateway verifies JWT).
#[allow(dead_code)]
pub async fn combined_rate_limiting(
    State(ctx): State<Arc<AppContext>>,
    TrustedUser(user_id): TrustedUser,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Skip rate limiting if disabled
    if !ctx.config.security.combined_rate_limiting_enabled {
        return Ok(next.run(req).await);
    }

    // Skip for safe methods
    if matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    ) {
        return Ok(next.run(req).await);
    }

    let path = req.uri().path();
    let user_id_str = user_id.to_string();

    // Extract client IP from headers
    // Note: In production, ensure your reverse proxy sets X-Forwarded-For correctly
    let headers = req.headers();
    let client_ip = extract_client_ip(headers, None);

    // Check combined rate limit (user_id + IP)
    {
        let mut queue = ctx.queue.lock().await;
        match queue
            .increment_combined_rate_limit(&user_id_str, &client_ip, 3600)
            .await
        {
            Ok(count) => {
                // Use stricter limit for combined rate limiting (lower than IP-only)
                let max_combined_requests = ctx.config.security.max_requests_per_user_ip_per_hour;
                if count > max_combined_requests {
                    drop(queue);
                    let user_id_for_log = user_id.to_string();
                    tracing::warn!(
                        user_hash = %construct_server_shared::utils::log_safe_id(&user_id_for_log, &ctx.config.logging.hash_salt),
                        ip = %client_ip,
                        count = count,
                        limit = max_combined_requests,
                        path = %path,
                        "Combined rate limit exceeded"
                    );
                    return Err(AppError::Validation(format!(
                        "Rate limit exceeded: maximum {} requests per hour",
                        max_combined_requests
                    )));
                }
            }
            Err(e) => {
                drop(queue);
                let user_id_for_log = user_id.to_string();
                tracing::error!(
                    error = %e,
                    user_hash = %construct_server_shared::utils::log_safe_id(&user_id_for_log, &ctx.config.logging.hash_salt),
                    ip = %client_ip,
                    "Failed to check combined rate limit"
                );
                // Fail open - continue but log error
            }
        }
    }

    Ok(next.run(req).await)
}

/// Error handler middleware
/// Converts AppError responses to proper HTTP responses
/// Note: This is a placeholder - actual error handling is done via IntoResponse for AppError
#[allow(dead_code)]
pub async fn error_handler(req: Request, next: Next) -> Response {
    // Error handling is done via AppError::into_response() implementation
    next.run(req).await
}

/// Metrics Authentication Middleware
///
/// Protects /metrics endpoint from unauthorized access.
/// Supports two authentication methods:
/// 1. IP whitelist (if configured)
/// 2. Bearer token authentication (if configured)
///
/// If both are configured, either method can grant access.
/// If neither is configured and metrics_auth_enabled=false, access is allowed.
pub async fn metrics_auth(
    State(ctx): State<Arc<AppContext>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Skip if metrics auth is disabled
    if !ctx.config.security.metrics_auth_enabled {
        return Ok(next.run(req).await);
    }

    // Only apply to /metrics endpoint
    if req.uri().path() != "/metrics" {
        return Ok(next.run(req).await);
    }

    let headers = req.headers();
    let client_ip = extract_client_ip(headers, None);

    // Check 1: IP whitelist
    if !ctx.config.security.metrics_ip_whitelist.is_empty() {
        let ip_allowed = ctx
            .config
            .security
            .metrics_ip_whitelist
            .iter()
            .any(|allowed_ip| {
                // Support exact match and CIDR notation (basic)
                if allowed_ip.contains('/') {
                    // CIDR notation - for now, just check if IP starts with prefix
                    // TODO: Implement proper CIDR matching if needed
                    client_ip.starts_with(allowed_ip.split('/').next().unwrap_or(""))
                } else {
                    // Exact match
                    client_ip == *allowed_ip
                        || normalize_ip_for_comparison(&client_ip)
                            == normalize_ip_for_comparison(allowed_ip)
                }
            });

        if ip_allowed {
            tracing::debug!(ip = %client_ip, "Metrics access granted via IP whitelist");
            return Ok(next.run(req).await);
        }
    }

    // Check 2: Bearer token authentication
    if let Some(expected_token) = &ctx.config.security.metrics_bearer_token
        && let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
    {
        // Constant-time comparison to prevent timing attacks
        if bool::from(token.as_bytes().ct_eq(expected_token.as_bytes())) {
            tracing::debug!("Metrics access granted via Bearer token");
            return Ok(next.run(req).await);
        }
    }

    // Access denied
    tracing::warn!(
        ip = %client_ip,
        path = %req.uri().path(),
        "Unauthorized metrics access attempt"
    );

    Err(AppError::Auth(
        "Unauthorized: Metrics endpoint requires authentication".to_string(),
    ))
}

/// Normalize IP for comparison (handles IPv6 brackets)
fn normalize_ip_for_comparison(ip: &str) -> String {
    ip.trim_start_matches('[').trim_end_matches(']').to_string()
}
