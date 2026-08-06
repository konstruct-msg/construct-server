// ============================================================================
// construct-notification-service
// ============================================================================
//
// Holds NotificationServiceContext for APNs wiring.
// Register/unregister/preferences business logic for clients is in
// messaging-service (gRPC NotificationService + notification_core).
// REST handlers removed.
//
// ============================================================================

pub mod context;

pub use context::NotificationServiceContext;
