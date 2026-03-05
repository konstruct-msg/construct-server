// User service business logic is in crates/construct-user-service.
// This module re-exports it and keeps the handlers that need shared proto types.

pub use construct_user_service::UserServiceContext;

pub mod core {
    pub use construct_user_service::core::*;
}

pub mod invites {
    pub use construct_user_service::invites::*;
}

pub mod account {
    pub use construct_user_service::account::*;
}

pub mod account_deletion {
    pub use construct_user_service::account_deletion::*;
}
