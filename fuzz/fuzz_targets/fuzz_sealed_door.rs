//! Fuzz target: the whole unauthenticated door, as one input.
//!
//! `fuzz_sealed_inner` and `fuzz_sealed_token_open` each cover one stage. This
//! one covers the *sequence*: a single blob of attacker bytes is parsed as a
//! `SealedInner` and its fields are then handed to the crypto in the order
//! `dispatch_sealed_sender` hands them over, so the fuzzer can reach states that
//! need the proto and the seal to agree — a length the parser accepts and the
//! opener slices, for instance.
//!
//! What this target does NOT prove: the Redis-touching decisions between these
//! calls (`check_intake_credential`'s epoch walk, `redeem_token_checked`'s spend
//! unit) are `pub(crate)` in a binary crate and unreachable from here. The glue
//! restated below — the emptiness checks and the `[u8; 32]` conversions — is a
//! second copy of production control flow and proves nothing about the original.
//! Closing that gap means giving `messaging-service` a library target, or moving
//! the pure parts of `intake.rs` into a crate. Until then this target covers the
//! parsers, not the policy.

#![no_main]

use construct_crypto::privacy_pass::{open_sealed_token_bytes, verify_token};
use construct_server_shared::shared::proto::core::v1::SealedInner;
use libfuzzer_sys::fuzz_target;
use prost::Message;
use x25519_dalek::StaticSecret;

/// Matches `intake::INTAKE_TAG_LEN`.
const INTAKE_TAG_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    let Ok(inner) = SealedInner::decode(data) else {
        return;
    };

    let secret = StaticSecret::from([0x2a_u8; 32]);
    let issuer_key = [0x11_u8; 32];

    // 1. Intake credential — checked before anything is charged.
    if !inner.intake_tag_sealed.is_empty()
        && let Ok(presented) = open_sealed_token_bytes(&inner.intake_tag_sealed, &secret)
    {
        let _ = presented.len() == INTAKE_TAG_LEN;
    }

    // 2. Privacy Pass redemption — the path an envelope without a credential takes.
    if !inner.token_nonce.is_empty()
        && !inner.token_bytes.is_empty()
        && let Ok(nonce) = <[u8; 32]>::try_from(inner.token_nonce.as_slice())
        && let Ok(decrypted) = open_sealed_token_bytes(&inner.token_bytes, &secret)
        && let Ok(token) = <[u8; 32]>::try_from(decrypted.as_slice())
    {
        assert!(
            !verify_token(&token, &nonce, &issuer_key),
            "a token reached through the sealed door verified against an unrelated issuer key"
        );
    }
});
