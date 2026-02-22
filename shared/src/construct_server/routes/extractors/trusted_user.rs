// ============================================================================
// TrustedUser Extractor - Gateway Auth Pattern
// ============================================================================
//
// Extracts user identity from X-User-Id header set by Gateway.
//
// SECURITY: This extractor trusts the X-User-Id header unconditionally.
// It MUST only be used for services behind the API Gateway.
// Direct internet access to services would bypass authentication!
//
// Usage:
// ```rust
// async fn handler(user: TrustedUser, ...) -> Result<...> {
//     let user_id = user.0;
//     // ...
// }
// ```
//
// For endpoints that work both authenticated and anonymous:
// ```rust
// async fn handler(user: OptionalTrustedUser, ...) -> Result<...> {
//     if let Some(user_id) = user.0 {
//         // Authenticated user
//     } else {
//         // Anonymous user
//     }
// }
// ```
//
// ============================================================================

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::convert::Infallible;
use uuid::Uuid;

/// User identity propagated from Gateway via trusted X-User-Id header.
///
/// This extractor is used in the Trust Boundary pattern where:
/// - Gateway is the ONLY entry point from the internet
/// - Gateway verifies JWT and sets X-User-Id header
/// - Services trust this header (they are not directly accessible)
///
/// SECURITY WARNING:
/// Services using this extractor MUST NOT be accessible from the internet.
/// They should only be accessible via internal network (e.g., Fly.io private networking).
#[derive(Debug, Clone)]
pub struct TrustedUser(pub Uuid);

/// Header name for user ID propagation
const USER_ID_HEADER: &str = "x-user-id";

/// Generic implementation that doesn't require specific state type
#[async_trait]
impl<S> FromRequestParts<S> for TrustedUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract X-User-Id header set by Gateway
        let user_id = parts
            .headers
            .get(USER_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                // This should never happen if Gateway is working correctly
                // and if the service is not directly accessible from internet
                tracing::error!(
                    "Missing or invalid X-User-Id header. \
                     Is this request coming through Gateway? \
                     Is this service directly accessible from internet (security issue)?"
                );

                let body = json!({
                    "error": "Authentication required",
                    "code": "AUTH_REQUIRED",
                });
                (axum::http::StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
            })?;

        tracing::trace!(user_id = %user_id, "TrustedUser extracted from header");

        Ok(TrustedUser(user_id))
    }
}

/// Optional trusted user for endpoints that work both authenticated and anonymous.
///
/// Unlike TrustedUser, this extractor does not fail if X-User-Id header is missing.
/// It returns None for anonymous requests and Some(user_id) for authenticated ones.
///
/// Usage:
/// ```rust
/// async fn handler(user: OptionalTrustedUser, ...) -> Result<...> {
///     match user.0 {
///         Some(user_id) => { /* authenticated */ }
///         None => { /* anonymous */ }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalTrustedUser(pub Option<Uuid>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalTrustedUser
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user_id = parts
            .headers
            .get(USER_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Uuid::parse_str(s).ok());

        if let Some(ref id) = user_id {
            tracing::trace!(user_id = %id, "OptionalTrustedUser extracted from header");
        }

        Ok(OptionalTrustedUser(user_id))
    }
}

/// Trusted device ID propagated from Gateway via X-Device-Id header.
///
/// Optional - only set if JWT contains device_id claim.
#[derive(Debug, Clone)]
pub struct TrustedDeviceId(pub Option<String>);

/// Header name for device ID propagation
const DEVICE_ID_HEADER: &str = "x-device-id";

#[async_trait]
impl<S> FromRequestParts<S> for TrustedDeviceId
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let device_id = parts
            .headers
            .get(DEVICE_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Ok(TrustedDeviceId(device_id))
    }
}

/// Request trace ID propagated from Gateway via X-Request-Id header.
///
/// Used for distributed tracing and debugging.
#[derive(Debug, Clone)]
pub struct RequestTraceId(pub String);

/// Header name for request trace ID
const REQUEST_ID_HEADER: &str = "x-request-id";

#[async_trait]
impl<S> FromRequestParts<S> for RequestTraceId
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .headers
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Generate a fallback ID if not present (shouldn't happen with Gateway)
                Uuid::new_v4().to_string()
            });

        Ok(RequestTraceId(request_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Request};

    #[tokio::test]
    async fn test_trusted_user_valid_header() {
        let user_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_ID_HEADER,
            HeaderValue::from_str(&user_id.to_string()).unwrap(),
        );

        let mut parts = Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;

        let result = TrustedUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, user_id);
    }

    #[tokio::test]
    async fn test_trusted_user_missing_header() {
        let mut parts = Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        let result = TrustedUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_optional_trusted_user_with_header() {
        let user_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_ID_HEADER,
            HeaderValue::from_str(&user_id.to_string()).unwrap(),
        );

        let mut parts = Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        parts.headers = headers;

        let result = OptionalTrustedUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, Some(user_id));
    }

    #[tokio::test]
    async fn test_optional_trusted_user_without_header() {
        let mut parts = Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts()
            .0;

        let result = OptionalTrustedUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, None);
    }
}
