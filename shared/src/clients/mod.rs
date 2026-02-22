//! gRPC clients for service-to-service communication.
//!
//! This module provides configured clients for each of the backend gRPC services.
//! It is intended to be the single entry point for any service that needs to
//! communicate with another service.
//!
//! The clients here will be configured with connection pooling, timeouts, and
//! retry logic.

pub mod auth;
pub mod messaging;
pub mod notification;
pub mod user;
