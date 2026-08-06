// User service business logic is in crates/construct-user-service.
// Client user/invite/account APIs are gRPC on identity-service.
// REST handlers (and REST-shaped invite/account wrappers) were removed.

pub use construct_user_service::UserServiceContext;

pub mod core {
    pub use construct_user_service::core::*;
}
