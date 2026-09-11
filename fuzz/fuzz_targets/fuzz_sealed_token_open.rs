//! Fuzz target: `open_sealed_token_bytes` — the X25519 seal opener.
//!
//! Reached twice per unauthenticated envelope, on two different attacker-chosen
//! fields: `SealedInner.intake_tag_sealed` (intake.rs) and
//! `SealedInner.token_bytes` (token_redeem.rs). It slices a caller-supplied
//! buffer at three fixed offsets after one length check, which is the shape that
//! produces panics.
//!
//! The secret is fixed and non-secret on purpose: the property under test is
//! "no input panics", and a per-run key would make crashes unreproducible.

#![no_main]

use construct_crypto::privacy_pass::open_sealed_token_bytes;
use libfuzzer_sys::fuzz_target;
use x25519_dalek::StaticSecret;

fuzz_target!(|data: &[u8]| {
    // Deterministic, so a crashing input replays identically tomorrow.
    let secret = StaticSecret::from([0x2a_u8; 32]);
    let _ = open_sealed_token_bytes(data, &secret);
});
