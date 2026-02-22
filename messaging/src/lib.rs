// ============================================================================
// Construct Server - Messaging Service
// ============================================================================
//
// This crate contains messaging-specific functionality separated from the
// monolithic shared crate to reduce binary sizes and improve maintainability.
//
// Contains:
// - Messaging service context and utilities
// - Message routing and delivery logic
// - Kafka integration for message persistence
//
// ============================================================================

pub mod messaging_service;
pub mod service;
pub mod routes;