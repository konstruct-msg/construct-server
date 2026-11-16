use axum::{http::StatusCode, response::IntoResponse};
use serde_json::json;
use thiserror::Error;

/// Application error type with comprehensive error handling
///
/// This enum covers all error types that can occur in the application,
/// providing structured error information for logging and user-facing responses.
#[derive(Error, Debug)]
pub enum AppError {
    // ===== HTTP & Network Errors =====
    #[error("HTTP header error: {0}")]
    HttpHeader(#[from] hyper::header::InvalidHeaderValue),

    #[error("Hyper HTTP error: {0}")]
    Hyper(String),

    #[cfg(feature = "http")]
    #[error("HTTP client error: {0}")]
    Reqwest(#[from] reqwest::Error),

    // ===== Serialization Errors =====
    #[cfg(feature = "serialization")]
    #[error("Serialization error: {0}")]
    Serialization(#[from] rmp_serde::encode::Error),

    #[cfg(feature = "serialization")]
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] rmp_serde::decode::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // ===== Database & Storage Errors =====
    #[cfg(feature = "database")]
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[cfg(feature = "redis")]
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // ===== Authentication & Authorization Errors =====
    #[error("Authentication error: {0}")]
    Auth(String),

    /// The server refuses this device. Its own variant, not `Auth` with a message, because a
    /// client erases its data on one of the reasons and must read it as a number — see
    /// [`DeviceRefusal`].
    #[error("Authentication error: {}", .0.message())]
    DeviceRefused(DeviceRefusal),

    #[error("CSRF validation failed: {0}")]
    Csrf(String),

    // ===== Validation Errors =====
    #[error("Validation error: {0}")]
    Validation(String),

    // ===== Invite Errors (per INVITE_LINKS_QR_API_SPEC.md Section 10) =====
    #[error("Invite expired")]
    InviteExpired,

    #[error("Invalid invite signature")]
    InviteInvalidSignature,

    #[error("Invite already used")]
    InviteAlreadyUsed,

    #[error("Public key not found")]
    PublicKeyNotFound,

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Access forbidden: {0}")]
    Forbidden(String),

    #[error("Resource gone: {0}")]
    Gone(String),

    #[error("Resource conflict: {0}")]
    Conflict(String),

    #[error("Rate limit exceeded: {0}")]
    TooManyRequests(String),

    #[cfg(feature = "serialization")]
    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),

    // ===== Federation Errors =====
    #[error("Federation error: {0}")]
    Federation(String),

    // ===== Message Processing Errors =====
    #[error("Message processing error: {0}")]
    Message(String),

    // ===== Configuration Errors =====
    #[error("Configuration error: {0}")]
    Config(String),

    // ===== Internal Server Errors =====
    #[error("Internal server error: {0}")]
    Internal(String),

    // ===== Unknown/Generic Errors =====
    #[error("Unknown error: {0}")]
    Unknown(#[from] anyhow::Error),
}

/// Why the server refuses a device: `DeviceRefusal` in construct-protos
/// `services/auth_service.proto`, whose numbers these are (`construct-server-shared` asserts they
/// agree). It travels as that number in the trailing metadata key [`DeviceRefusal::METADATA_KEY`]
/// of the UNAUTHENTICATED status, because a client erases what the account left on it for
/// `Removed` and for nothing else — and until 2026-10-06 it decided that by matching the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRefusal {
    /// The row was deactivated (RevokeDevice, or Logout of this device). Permanent.
    Removed = 1,
    /// No row. Not removal: an unapproved join request answers this too.
    NotFound = 2,
}

impl DeviceRefusal {
    pub const METADATA_KEY: &'static str = "construct-device-refusal";

    /// The status text, as it read before the number existed — clients that predate the number
    /// still match it.
    pub fn message(self) -> &'static str {
        match self {
            DeviceRefusal::Removed => "Device is inactive",
            DeviceRefusal::NotFound => "Device not found",
        }
    }
}

impl AppError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Auth(_) | AppError::DeviceRefused(_) => StatusCode::UNAUTHORIZED,
            AppError::Csrf(_) => StatusCode::FORBIDDEN,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::Gone(_) => StatusCode::GONE,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::InviteExpired
            | AppError::InviteInvalidSignature
            | AppError::InviteAlreadyUsed => StatusCode::BAD_REQUEST,
            AppError::PublicKeyNotFound => StatusCode::NOT_FOUND,
            #[cfg(feature = "serialization")]
            AppError::Uuid(_) => StatusCode::BAD_REQUEST,
            #[cfg(feature = "http")]
            AppError::Reqwest(_) => StatusCode::BAD_GATEWAY,
            AppError::Federation(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a user-friendly error message (without sensitive details)
    pub fn user_message(&self) -> String {
        match self {
            AppError::Auth(msg) => format!("Authentication failed: {}", msg),
            AppError::DeviceRefused(r) => format!("Authentication failed: {}", r.message()),
            AppError::Csrf(_) => "CSRF validation failed".to_string(),
            AppError::Validation(msg) => format!("Validation error: {}", msg),
            AppError::NotFound(msg) => format!("Not found: {}", msg),
            AppError::Forbidden(msg) => format!("Forbidden: {}", msg),
            AppError::Gone(msg) => format!("Gone: {}", msg),
            AppError::Conflict(msg) => format!("Conflict: {}", msg),
            AppError::TooManyRequests(_) => "Rate limit exceeded".to_string(),
            AppError::InviteExpired => {
                "Invite has expired. Please ask for a new QR code.".to_string()
            }
            AppError::InviteInvalidSignature => {
                "Invalid invite signature. This invite may have been tampered with.".to_string()
            }
            AppError::InviteAlreadyUsed => "This invite has already been used.".to_string(),
            AppError::PublicKeyNotFound => "Public key not found for this user.".to_string(),
            #[cfg(feature = "database")]
            AppError::Database(_) => "Database error".to_string(),
            #[cfg(feature = "redis")]
            AppError::Redis(_) => "Cache error".to_string(),
            #[cfg(feature = "http")]
            AppError::Reqwest(_) => "External service error".to_string(),
            AppError::Federation(_) => "Federation error".to_string(),
            AppError::Config(_) => "Configuration error".to_string(),
            _ => "Internal server error".to_string(),
        }
    }

    /// Get error code for programmatic error handling
    pub fn error_code(&self) -> &'static str {
        match self {
            AppError::Auth(_) | AppError::DeviceRefused(_) => "AUTH_ERROR",
            AppError::Csrf(_) => "CSRF_ERROR",
            AppError::Validation(_) => "VALIDATION_ERROR",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::Forbidden(_) => "FORBIDDEN",
            AppError::Gone(_) => "GONE",
            AppError::Conflict(_) => "CONFLICT",
            AppError::TooManyRequests(_) => "RATE_LIMIT_EXCEEDED",
            AppError::InviteExpired => "INVITE_EXPIRED",
            AppError::InviteInvalidSignature => "INVITE_INVALID_SIGNATURE",
            AppError::InviteAlreadyUsed => "INVITE_ALREADY_USED",
            AppError::PublicKeyNotFound => "PUBLIC_KEY_NOT_FOUND",
            #[cfg(feature = "database")]
            AppError::Database(_) => "DATABASE_ERROR",
            #[cfg(feature = "redis")]
            AppError::Redis(_) => "REDIS_ERROR",
            #[cfg(feature = "http")]
            AppError::Reqwest(_) => "EXTERNAL_SERVICE_ERROR",
            AppError::Federation(_) => "FEDERATION_ERROR",
            AppError::Config(_) => "CONFIG_ERROR",
            AppError::Internal(_) => "INTERNAL_ERROR",
            _ => "UNKNOWN_ERROR",
        }
    }

    /// Log this error with appropriate level and context
    pub fn log(&self) {
        let status = self.status_code();
        let code = self.error_code();

        if status.is_server_error() {
            tracing::error!(
                error = %self,
                error_code = %code,
                status = %status.as_u16(),
                "Server error occurred"
            );
        } else if status == StatusCode::UNAUTHORIZED {
            tracing::warn!(
                error = %self,
                error_code = %code,
                "Authentication failed"
            );
        } else {
            tracing::debug!(
                error = %self,
                error_code = %code,
                "Client error occurred"
            );
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Log the error with appropriate level
        self.log();

        let status = self.status_code();
        let error_code = self.error_code();
        let user_message = self.user_message();

        // For invite errors, use spec-compliant format (INVITE_LINKS_QR_API_SPEC.md Section 10)
        // Format: {"error": "INVITE_EXPIRED", "status": 400}
        let is_invite_error = matches!(
            self,
            AppError::InviteExpired
                | AppError::InviteInvalidSignature
                | AppError::InviteAlreadyUsed
                | AppError::PublicKeyNotFound
        );

        let response_body = if status.is_server_error() {
            // For server errors, don't expose internal details to client
            json!({
                "error": "Internal server error",
                "error_code": error_code,
                "status": status.as_u16(),
            })
        } else if is_invite_error {
            // Invite errors use spec-compliant format
            json!({
                "error": error_code,
                "status": status.as_u16(),
            })
        } else {
            // Standard format for other errors
            json!({
                "error": user_message,
                "error_code": error_code,
                "status": status.as_u16(),
            })
        };

        (status, axum::Json(response_body)).into_response()
    }
}

// ============================================================================
// Conversion from common error types
// ============================================================================

// ============================================================================
// Helper functions for creating common errors
// ============================================================================

impl AppError {
    /// Create an authentication error
    pub fn auth(msg: impl Into<String>) -> Self {
        AppError::Auth(msg.into())
    }

    /// Create a CSRF validation error
    pub fn csrf(msg: impl Into<String>) -> Self {
        AppError::Csrf(msg.into())
    }

    /// Create a validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        AppError::Validation(msg.into())
    }

    /// Create a conflict error (409)
    pub fn conflict(msg: impl Into<String>) -> Self {
        AppError::Conflict(msg.into())
    }

    /// Create a forbidden error (403)
    pub fn forbidden(msg: impl Into<String>) -> Self {
        AppError::Forbidden(msg.into())
    }

    /// Create a gone error (410)
    pub fn gone(msg: impl Into<String>) -> Self {
        AppError::Gone(msg.into())
    }

    /// Create an internal server error
    pub fn internal(msg: impl Into<String>) -> Self {
        AppError::Internal(msg.into())
    }

    /// Create a federation error
    pub fn federation(msg: impl Into<String>) -> Self {
        AppError::Federation(msg.into())
    }

    /// Create a message processing error
    pub fn message(msg: impl Into<String>) -> Self {
        AppError::Message(msg.into())
    }

    /// Create a configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        AppError::Config(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{body::to_bytes, response::IntoResponse};
    use serde_json::{Value, json};
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    use super::*;

    fn assert_contract(error: AppError, status: StatusCode, user_message: &str, error_code: &str) {
        assert_eq!(error.status_code(), status);
        assert_eq!(error.user_message(), user_message);
        assert_eq!(error.error_code(), error_code);
    }

    #[test]
    fn device_refusals_keep_the_proto_numbers_and_legacy_messages() {
        assert_eq!(DeviceRefusal::Removed as i32, 1);
        assert_eq!(DeviceRefusal::Removed.message(), "Device is inactive");
        assert_eq!(DeviceRefusal::NotFound as i32, 2);
        assert_eq!(DeviceRefusal::NotFound.message(), "Device not found");
        assert_eq!(DeviceRefusal::METADATA_KEY, "construct-device-refusal");
    }

    #[test]
    fn core_variants_name_their_http_contract_without_exposing_internal_details() {
        let invalid_header = "bad\nheader"
            .parse::<hyper::header::HeaderValue>()
            .unwrap_err();
        let json_error = serde_json::from_str::<Value>("{").unwrap_err();

        for (error, status, message, code) in [
            (
                AppError::HttpHeader(invalid_header),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "UNKNOWN_ERROR",
            ),
            (
                AppError::Hyper("hyper-secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "UNKNOWN_ERROR",
            ),
            (
                AppError::Json(json_error),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "UNKNOWN_ERROR",
            ),
            (
                AppError::Io(std::io::Error::other("io-secret")),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "UNKNOWN_ERROR",
            ),
            (
                AppError::Auth("bad token".into()),
                StatusCode::UNAUTHORIZED,
                "Authentication failed: bad token",
                "AUTH_ERROR",
            ),
            (
                AppError::DeviceRefused(DeviceRefusal::Removed),
                StatusCode::UNAUTHORIZED,
                "Authentication failed: Device is inactive",
                "AUTH_ERROR",
            ),
            (
                AppError::DeviceRefused(DeviceRefusal::NotFound),
                StatusCode::UNAUTHORIZED,
                "Authentication failed: Device not found",
                "AUTH_ERROR",
            ),
            (
                AppError::Csrf("csrf-secret".into()),
                StatusCode::FORBIDDEN,
                "CSRF validation failed",
                "CSRF_ERROR",
            ),
            (
                AppError::Validation("bad field".into()),
                StatusCode::BAD_REQUEST,
                "Validation error: bad field",
                "VALIDATION_ERROR",
            ),
            (
                AppError::InviteExpired,
                StatusCode::BAD_REQUEST,
                "Invite has expired. Please ask for a new QR code.",
                "INVITE_EXPIRED",
            ),
            (
                AppError::InviteInvalidSignature,
                StatusCode::BAD_REQUEST,
                "Invalid invite signature. This invite may have been tampered with.",
                "INVITE_INVALID_SIGNATURE",
            ),
            (
                AppError::InviteAlreadyUsed,
                StatusCode::BAD_REQUEST,
                "This invite has already been used.",
                "INVITE_ALREADY_USED",
            ),
            (
                AppError::PublicKeyNotFound,
                StatusCode::NOT_FOUND,
                "Public key not found for this user.",
                "PUBLIC_KEY_NOT_FOUND",
            ),
            (
                AppError::NotFound("account".into()),
                StatusCode::NOT_FOUND,
                "Not found: account",
                "NOT_FOUND",
            ),
            (
                AppError::Forbidden("private".into()),
                StatusCode::FORBIDDEN,
                "Forbidden: private",
                "FORBIDDEN",
            ),
            (
                AppError::Gone("expired".into()),
                StatusCode::GONE,
                "Gone: expired",
                "GONE",
            ),
            (
                AppError::Conflict("duplicate".into()),
                StatusCode::CONFLICT,
                "Conflict: duplicate",
                "CONFLICT",
            ),
            (
                AppError::TooManyRequests("quota-secret".into()),
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
                "RATE_LIMIT_EXCEEDED",
            ),
            (
                AppError::Federation("federation-secret".into()),
                StatusCode::BAD_GATEWAY,
                "Federation error",
                "FEDERATION_ERROR",
            ),
            (
                AppError::Message("message-secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "UNKNOWN_ERROR",
            ),
            (
                AppError::Config("config-secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration error",
                "CONFIG_ERROR",
            ),
            (
                AppError::Internal("internal-secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "INTERNAL_ERROR",
            ),
            (
                AppError::Unknown(anyhow::anyhow!("unknown-secret")),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                "UNKNOWN_ERROR",
            ),
        ] {
            assert_contract(error, status, message, code);
        }
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn serialization_variants_keep_their_boundary_contracts() {
        assert_contract(
            AppError::Serialization(rmp_serde::encode::Error::Syntax("encode-secret".into())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
            "UNKNOWN_ERROR",
        );
        assert_contract(
            AppError::Deserialization(rmp_serde::decode::Error::Syntax("decode-secret".into())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
            "UNKNOWN_ERROR",
        );
        assert_contract(
            AppError::Uuid("not-a-uuid".parse::<uuid::Uuid>().unwrap_err()),
            StatusCode::BAD_REQUEST,
            "Internal server error",
            "UNKNOWN_ERROR",
        );
    }

    #[cfg(feature = "database")]
    #[test]
    fn database_errors_are_named_but_do_not_expose_the_driver_detail() {
        assert_contract(
            AppError::Database(sqlx::Error::Protocol("database-secret".into())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error",
            "DATABASE_ERROR",
        );
    }

    #[cfg(feature = "redis")]
    #[test]
    fn redis_errors_are_named_but_do_not_expose_the_driver_detail() {
        assert_contract(
            AppError::Redis(redis::RedisError::from((
                redis::ErrorKind::UnexpectedReturnType,
                "redis-secret",
            ))),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Cache error",
            "REDIS_ERROR",
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_client_errors_are_named_but_do_not_expose_the_request_detail() {
        let reqwest_error = reqwest::Client::new().get("\n").build().unwrap_err();
        assert_contract(
            AppError::Reqwest(reqwest_error),
            StatusCode::BAD_GATEWAY,
            "External service error",
            "EXTERNAL_SERVICE_ERROR",
        );
    }

    async fn response_json(error: AppError) -> (StatusCode, Value) {
        let response = error.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn standard_http_response_carries_the_exact_public_contract() {
        for (error, status, body, hidden) in [
            (
                AppError::Validation("bad field".into()),
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "Validation error: bad field",
                    "error_code": "VALIDATION_ERROR",
                    "status": 400,
                }),
                None,
            ),
            (
                AppError::TooManyRequests("quota-secret".into()),
                StatusCode::TOO_MANY_REQUESTS,
                json!({
                    "error": "Rate limit exceeded",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "status": 429,
                }),
                Some("quota-secret"),
            ),
        ] {
            let (actual_status, actual_body) = response_json(error).await;
            assert_eq!(actual_status, status);
            assert_eq!(actual_body, body);
            if let Some(hidden) = hidden {
                assert!(!actual_body.to_string().contains(hidden));
            }
        }
    }

    #[tokio::test]
    async fn invite_http_responses_use_the_spec_shape_without_a_second_code_field() {
        for (error, status, code) in [
            (
                AppError::InviteExpired,
                StatusCode::BAD_REQUEST,
                "INVITE_EXPIRED",
            ),
            (
                AppError::InviteInvalidSignature,
                StatusCode::BAD_REQUEST,
                "INVITE_INVALID_SIGNATURE",
            ),
            (
                AppError::InviteAlreadyUsed,
                StatusCode::BAD_REQUEST,
                "INVITE_ALREADY_USED",
            ),
            (
                AppError::PublicKeyNotFound,
                StatusCode::NOT_FOUND,
                "PUBLIC_KEY_NOT_FOUND",
            ),
        ] {
            let (actual_status, body) = response_json(error).await;
            assert_eq!(actual_status, status);
            assert_eq!(body, json!({"error": code, "status": status.as_u16()}));
        }
    }

    #[tokio::test]
    async fn server_http_responses_hide_details_while_preserving_the_error_class() {
        for (error, status, code, secret) in [
            (
                AppError::Internal("internal-secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "internal-secret",
            ),
            (
                AppError::Config("config-secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIG_ERROR",
                "config-secret",
            ),
            (
                AppError::Federation("federation-secret".into()),
                StatusCode::BAD_GATEWAY,
                "FEDERATION_ERROR",
                "federation-secret",
            ),
            (
                AppError::Unknown(anyhow::anyhow!("unknown-secret")),
                StatusCode::INTERNAL_SERVER_ERROR,
                "UNKNOWN_ERROR",
                "unknown-secret",
            ),
        ] {
            let (actual_status, body) = response_json(error).await;
            assert_eq!(actual_status, status);
            assert_eq!(
                body,
                json!({
                    "error": "Internal server error",
                    "error_code": code,
                    "status": status.as_u16(),
                })
            );
            assert!(!body.to_string().contains(secret));
        }
    }

    #[derive(Clone)]
    struct CaptureLevel(Arc<Mutex<Vec<Level>>>);

    impl<S> Layer<S> for CaptureLevel
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            self.0.lock().unwrap().push(*event.metadata().level());
        }
    }

    fn logged_level(error: AppError) -> Level {
        let levels = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLevel(levels.clone()));
        tracing::subscriber::with_default(subscriber, || error.log());
        let captured = levels.lock().unwrap();
        assert_eq!(captured.len(), 1, "one error produces one log event");
        captured[0]
    }

    #[test]
    fn log_level_follows_the_http_error_class() {
        assert_eq!(
            logged_level(AppError::Internal("fault".into())),
            Level::ERROR
        );
        assert_eq!(logged_level(AppError::Auth("refused".into())), Level::WARN);
        assert_eq!(
            logged_level(AppError::Validation("bad input".into())),
            Level::DEBUG
        );
    }

    #[test]
    fn convenience_constructors_preserve_the_variant_and_message() {
        assert!(matches!(AppError::auth("a"), AppError::Auth(msg) if msg == "a"));
        assert!(matches!(AppError::csrf("b"), AppError::Csrf(msg) if msg == "b"));
        assert!(matches!(AppError::validation("c"), AppError::Validation(msg) if msg == "c"));
        assert!(matches!(AppError::conflict("d"), AppError::Conflict(msg) if msg == "d"));
        assert!(matches!(AppError::forbidden("e"), AppError::Forbidden(msg) if msg == "e"));
        assert!(matches!(AppError::gone("f"), AppError::Gone(msg) if msg == "f"));
        assert!(matches!(AppError::internal("g"), AppError::Internal(msg) if msg == "g"));
        assert!(matches!(AppError::federation("h"), AppError::Federation(msg) if msg == "h"));
        assert!(matches!(AppError::message("i"), AppError::Message(msg) if msg == "i"));
        assert!(matches!(AppError::config("j"), AppError::Config(msg) if msg == "j"));
    }
}
