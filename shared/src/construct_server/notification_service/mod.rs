// Notification service business logic is in crates/construct-notification-service.
// This module re-exports it and keeps the handlers that need shared proto types.

pub use construct_notification_service::NotificationServiceContext;
pub mod handlers;

pub mod notifications {
    pub use construct_notification_service::notifications::*;
}
