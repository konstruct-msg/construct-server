// ============================================================================
// gRPC Server and Client for Message Gateway
// ============================================================================
//
// This module wraps the auto-generated gRPC code from message_gateway.proto
// ============================================================================

// Include generated code from build.rs
pub mod proto {
    tonic::include_proto!("construct.message_gateway.v1");
}

// Re-export with clear naming to avoid conflicts
pub use proto::message_gateway_client::MessageGatewayClient as MessageGatewayClient_;
pub use proto::message_gateway_server::{
    MessageGateway as MessageGatewayService, MessageGatewayServer,
};
pub use proto::*;
