// ============================================================================
// construct-notification-service
// ============================================================================
//
// Notification service business logic: device token registration,
// unregistration, and preferences management.
// Extracted from shared/ for reuse across the monolith and the
// notification-service microservice binary.
//
// ============================================================================

pub mod context;
pub mod notifications;

pub use context::NotificationServiceContext;
