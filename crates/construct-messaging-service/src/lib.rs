// ============================================================================
// construct-messaging-service
// ============================================================================
//
// Messaging service business logic: message dispatch, push notifications,
// control messages, and pending message confirmation.
// Extracted from shared/ for reuse across the monolith and the
// messaging-service microservice binary.
//
// ============================================================================

pub mod context;
pub mod core;

pub use context::MessagingServiceContext;
