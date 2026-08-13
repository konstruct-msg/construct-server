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

// SentinelService uses its own package namespace `shared.proto.sentinel.v1`
pub mod sentinel {
    #![allow(clippy::large_enum_variant)]
    tonic::include_proto!("shared.proto.sentinel.v1");
}

/// Build identity, baked in by build.rs. See the note there for why the
/// workspace semver was not enough to answer "what is running in production?".
pub mod build_info {
    /// Full commit SHA, or "unknown" when built outside a git checkout.
    pub const GIT_SHA: &str = env!("CONSTRUCT_GIT_SHA");
    /// First 12 characters — what a human reads in /.well-known or Grafana.
    pub const GIT_SHA_SHORT: &str = env!("CONSTRUCT_GIT_SHA_SHORT");
    /// Workspace semver. Still useful, just not sufficient on its own.
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    /// Seconds since the epoch at compile time.
    pub const BUILT_UNIX: &str = env!("CONSTRUCT_BUILD_UNIX");

    /// `0.17.4+a1b2c3d4e5f6` — one string that identifies a build exactly.
    pub fn full() -> String {
        format!("{VERSION}+{GIT_SHA_SHORT}")
    }
}

// Part 2: The new clients module for PROTO-4
pub mod clients;

// Part 3: The legacy application logic modules
// Include the file containing all the `mod` declarations.
// We make it private to `lib.rs`...
mod construct_server;
// ...and then publicly re-export all of its contents.
// This restores the `db`, `message`, `auth`, etc. modules for other crates.
pub use construct_server::*;

#[cfg(test)]
mod build_info_tests {
    use super::build_info;

    /// The shape has to hold everywhere — including a source tarball with no git
    /// and no GIT_SHA, where the SHA is legitimately "unknown". Asserting the SHA
    /// is *real* would fail exactly there, so assert what is always true and let
    /// the deploy check the rest: /.well-known reports the commit, and CI tags the
    /// image with it, so an "unknown" in production is visible rather than silent.
    #[test]
    fn build_identity_is_well_formed() {
        assert!(!build_info::VERSION.is_empty());
        assert!(build_info::VERSION.contains('.'), "expected semver");
        assert!(
            build_info::GIT_SHA_SHORT.len() <= 12,
            "short sha must stay short: {}",
            build_info::GIT_SHA_SHORT
        );
        assert!(build_info::GIT_SHA.starts_with(build_info::GIT_SHA_SHORT));

        let full = build_info::full();
        assert!(full.starts_with(build_info::VERSION));
        assert!(full.contains('+'), "expected version+commit, got {full}");
    }

    /// Printed, not asserted: in a git checkout this must show a real SHA. If it
    /// says "unknown" here, build.rs stopped finding git and every deploy would
    /// silently lose its identity.
    #[test]
    fn print_build_identity() {
        println!("build identity: {}", build_info::full());
    }
}
