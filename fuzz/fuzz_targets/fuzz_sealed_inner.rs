//! Fuzz target: `SealedInner::decode` — the first production call on bytes that
//! arrived with no credentials at all.
//!
//! `SendSealedMessage` deliberately does not call `extract_authed_user_id`
//! (messaging-service/src/grpc.rs). Between the socket and any authentication
//! there is one per-IP window and then this parser. It is the widest
//! pre-authentication surface the server has.
//!
//! Two claims, both checked here:
//!   * arbitrary bytes never panic the decoder (including nesting — prost's
//!     recursion limit is the only thing between us and a stack overflow, and
//!     nothing in this repo asserts it applies to *this* message shape);
//!   * decode → encode → decode is stable. An asymmetry here means two peers
//!     can hold different ideas of the same envelope, which is this repo's
//!     named defect class rather than a parser bug.

#![no_main]

use construct_server_shared::shared::proto::core::v1::SealedInner;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let Ok(inner) = SealedInner::decode(data) else {
        return;
    };

    // encoded_len must agree with what encode actually writes, or a caller sizing
    // a buffer from it writes out of bounds.
    let mut buf = Vec::with_capacity(inner.encoded_len());
    inner.encode(&mut buf).expect("encode into an owned Vec cannot fail");
    assert_eq!(
        buf.len(),
        inner.encoded_len(),
        "encoded_len disagrees with encode"
    );

    let reparsed = SealedInner::decode(buf.as_slice())
        .expect("a message we just encoded must decode again");
    assert_eq!(inner, reparsed, "SealedInner round-trip is not stable");
});
