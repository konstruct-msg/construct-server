use axum::{http::StatusCode, response::IntoResponse};
use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use serde_json::json;
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

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

    // ===== Message Queue & Kafka Errors =====
    #[error("Kafka error: {0}")]
    Kafka(String),

    #[error("Message queue error: {0}")]
    MessageQueue(String),

    // ===== Authentication & Authorization Errors =====
    #[error("Authentication error: {0}")]
    Auth(String),

    #[cfg(feature = "jwt")]
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

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

impl AppError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Auth(_) => StatusCode::UNAUTHORIZED,
            #[cfg(feature = "jwt")]
            AppError::Jwt(_) => StatusCode::UNAUTHORIZED,
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
            #[cfg(feature = "database")]
            AppError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            #[cfg(feature = "redis")]
            AppError::Redis(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Kafka(_) | AppError::MessageQueue(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a user-friendly error message (without sensitive details)
    pub fn user_message(&self) -> String {
        match self {
            AppError::Auth(msg) => format!("Authentication failed: {}", msg),
            #[cfg(feature = "jwt")]
            AppError::Jwt(_) => "Invalid or expired token".to_string(),
            AppError::Csrf(_) => "CSRF validation failed".to_string(),
            AppError::Validation(msg) => format!("Validation error: {}", msg),
            AppError::NotFound(msg) => format!("Not found: {}", msg),
            AppError::Forbidden(msg) => format!("Forbidden: {}", msg),
            AppError::Gone(msg) => format!("Gone: {}", msg),
            AppError::Conflict(msg) => format!("Conflict: {}", msg),
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
            AppError::Kafka(_) => "Message queue error".to_string(),
            AppError::MessageQueue(_) => "Message queue error".to_string(),
            #[cfg(feature = "http")]
            AppError::Reqwest(_) => "External service error".to_string(),
            AppError::Federation(_) => "Federation error".to_string(),
            AppError::Config(msg) => format!("Configuration error: {}", msg),
            AppError::Internal(msg) => format!("Internal error: {}", msg),
            _ => "Internal server error".to_string(),
        }
    }

    /// Get error code for programmatic error handling
    pub fn error_code(&self) -> &'static str {
        match self {
            AppError::Auth(_) => "AUTH_ERROR",
            #[cfg(feature = "jwt")]
            AppError::Jwt(_) => "JWT_ERROR",
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
            AppError::Kafka(_) => "KAFKA_ERROR",
            AppError::MessageQueue(_) => "MESSAGE_QUEUE_ERROR",
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

#[cfg(feature = "kafka")]
impl From<rdkafka::error::KafkaError> for AppError {
    fn from(err: rdkafka::error::KafkaError) -> Self {
        tracing::error!(error = %err, "Kafka error occurred");
        AppError::Kafka(err.to_string())
    }
}

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

    /// Create a Kafka error
    pub fn kafka(msg: impl Into<String>) -> Self {
        AppError::Kafka(msg.into())
    }

    /// Create a WebSocket error
    /// Create a message queue error
    pub fn message_queue(msg: impl Into<String>) -> Self {
        AppError::MessageQueue(msg.into())
    }

    /// Convert AppError to hyper::Response for use in non-Axum handlers
    /// This is used in lib.rs where we use hyper directly instead of Axum
    pub fn to_hyper_response(self) -> Response<Full<Bytes>> {
        // Log the error with appropriate level
        self.log();

        let status = self.status_code();
        let error_code = self.error_code();
        let user_message = self.user_message();

        // For invite errors, use spec-compliant format (INVITE_LINKS_QR_API_SPEC.md Section 10)
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

        let json_bytes = serde_json::to_vec(&response_body).unwrap_or_else(|_| {
            // Fallback if JSON serialization fails
            b"{\"error\":\"Internal server error\"}".to_vec()
        });

        let mut response = Response::new(Full::new(Bytes::from(json_bytes)));
        *response.status_mut() = status;

        // Set Content-Type header
        if let Ok(content_type) = "application/json".parse() {
            response.headers_mut().insert("content-type", content_type);
        }

        response
    }
}
