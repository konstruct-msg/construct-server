// Notification service context lives in crates/construct-notification-service.
// Client device-token registration is gRPC NotificationService on messaging-service
// (`messaging-service/src/notification_core.rs` + notification_grpc). REST removed.

pub use construct_notification_service::NotificationServiceContext;
