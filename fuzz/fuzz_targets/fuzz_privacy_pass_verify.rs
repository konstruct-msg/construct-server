//! Fuzz target: Privacy Pass verification on attacker-chosen group elements.
//!
//! `verify_token` and `verify_dleq_proof` decompress Ristretto points and build
//! scalars from bytes the client supplies. Non-canonical encodings, the identity
//! element and small-order-adjacent inputs are what this target is for — they
//! must be *rejected*, never a panic and never an unwrap on a `None`.

#![no_main]

use arbitrary::Arbitrary;
use construct_crypto::privacy_pass::{verify_dleq_proof, verify_token};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    token: [u8; 32],
    nonce: [u8; 32],
    issuer_key: [u8; 32],
    issuer_public: [u8; 32],
    proof: [u8; 64],
    blinded: Vec<[u8; 32]>,
    evaluated: Vec<[u8; 32]>,
}

fuzz_target!(|input: Input| {
    // A forged token must be rejected, not crash the redemption path.
    let _ = verify_token(&input.token, &input.nonce, &input.issuer_key);

    // Cap the batch: the interesting cases are length mismatch and degenerate
    // points, not how long a multi-scalar multiplication takes.
    let n = 32;
    let blinded: Vec<[u8; 32]> = input.blinded.into_iter().take(n).collect();
    let evaluated: Vec<[u8; 32]> = input.evaluated.into_iter().take(n).collect();

    let accepted = verify_dleq_proof(&input.issuer_public, &blinded, &evaluated, &input.proof);

    // Forging a proof from `arbitrary` bytes is a 2^-128 event. If this ever
    // fires it is a soundness break, not a flake — which is the reason to assert
    // it here rather than trust that verification "looks right".
    assert!(!accepted, "DLEQ verification accepted an unforged proof");
});
