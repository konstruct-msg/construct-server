// Messaging service business logic is in crates/construct-messaging-service.
// This module re-exports it and keeps the handlers that need shared proto types.

pub use construct_messaging_service::context::MessagingServiceContext;
pub mod handlers;

pub mod core {
    pub use construct_messaging_service::core::*;
}
