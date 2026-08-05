//! VeilService library surface — capability issuance for veil-front access.
//!
//! Binary entrypoint is `main.rs`; this crate root exists so unit tests and
//! future integration harnesses can `use veil_service::core` without linking
//! the gRPC/REST process.

pub mod core;
