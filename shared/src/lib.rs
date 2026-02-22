// Part 1: Include the Protobuf generated code
// This creates the `shared::proto` module structure.
pub mod shared {
    pub mod proto {
        pub mod core {
            pub mod v1 {
                #![allow(clippy::large_enum_variant)]
                tonic::include_proto!("shared.proto.core.v1");
            }
        }
        pub mod services {
            pub mod v1 {
                #![allow(clippy::large_enum_variant)]
                tonic::include_proto!("shared.proto.services.v1");
            }
        }
        pub mod messaging {
            pub mod v1 {
                #![allow(clippy::large_enum_variant)]
                tonic::include_proto!("shared.proto.messaging.v1");
            }
        }
        pub mod signaling {
            pub mod v1 {
                #![allow(clippy::large_enum_variant)]
                tonic::include_proto!("shared.proto.signaling.v1");
            }
        }
    }
}

// Part 2: The new clients module for PROTO-4
pub mod clients;

// Part 3: The legacy application logic modules
// Include the file containing all the `mod` declarations.
// We make it private to `lib.rs`...
mod construct_server;
// ...and then publicly re-export all of its contents.
// This restores the `db`, `kafka`, `auth`, etc. modules for other crates.
pub use construct_server::*;
