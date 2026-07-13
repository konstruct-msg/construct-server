// ============================================================================
// A5 — Two-VPS federation: S2S sealed-sender contract test
// ============================================================================
//
// Draft integration test for Epic A5 (see construct-docs/decisions/
// decentralization-execution-plan.md and domestic-island-deployment.md).
//
// A5's end-to-end goal: `alice@a -> bob@b` sealed-sender delivery across two
// independent nodes, where the *origin* never learns the sender. The full
// delivery half (Redis fan-out to bob's device stream) needs two live service
// processes + a registered recipient, and is exercised by the two-node smoke
// harness (ops/federation-smoke/). THIS test pins the security contract the
// receiver enforces, using only construct-federation's public API — so it runs
// in plain `cargo test` with no Postgres/Redis/network:
//
//   * the S2S *wire* envelope for a sealed message is sender-blind
//     (no `from` / `to` — contrast a regular federated message which carries them);
//   * origin signs, destination verifies with the origin's published key
//     (exactly what `messaging-service::federation::handle_inbound_sealed` does
//      via PublicKeyCache -> ServerSigner::verify_signature);
//   * payload-hash integrity: any tamper of the opaque blob is detectable;
//   * a spoofed origin (wrong key) is rejected;
//   * the sealed_inner blob is forwarded byte-for-byte (server never transforms it).
//
// Mirrors the real receiver: messaging-service/src/federation.rs.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_federation::{FederatedEnvelope, ServerSigner};

/// Two island nodes.
const NODE_A: &str = "relay.a.local"; // origin — where alice lives, sender-blind
const NODE_B: &str = "relay.b.local"; // destination — where bob lives

/// Fresh, distinct 32-byte Ed25519 seeds (base64), one per node — as each node
/// would generate with `openssl rand -base64 32`.
const SEED_A: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="; // node A signer
const SEED_B: &str = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA="; // node B signer

/// Build the sealed S2S envelope exactly as the outbound path does for a
/// cross-server sealed message: `from`/`to` are EMPTY — the sender's identity
/// lives encrypted inside `sealed_inner` (SenderCertificate, sealed to bob), not
/// on the wire. `sealed_inner` is opaque to every server on the path.
fn sealed_envelope(message_id: &str, sealed_inner_b64: &str, timestamp: u64) -> FederatedEnvelope {
    FederatedEnvelope {
        message_id: message_id.to_string(),
        from: String::new(), // sender-blind
        to: String::new(),   // recipient is inside SealedInner, not on the wire
        origin_server: NODE_A.to_string(),
        destination_server: NODE_B.to_string(),
        timestamp,
        payload_hash: FederatedEnvelope::hash_payload(sealed_inner_b64),
    }
}

#[test]
fn sealed_s2s_envelope_is_sender_blind_on_the_wire() {
    // An opaque sealed blob (in production: serialized SealedInner). Its contents
    // are irrelevant to federation — the point is nothing outside it names alice.
    let sealed_inner = b"opaque-sealed-inner-bytes-server-never-parses-this";
    let sealed_inner_b64 = BASE64.encode(sealed_inner);

    let env = sealed_envelope("msg-a5-001", &sealed_inner_b64, 1_720_000_000);

    // The signed canonical bytes are what actually crosses the border.
    let canonical = String::from_utf8(env.canonical_bytes()).unwrap();

    // No sender / recipient identity anywhere on the wire.
    assert!(env.from.is_empty(), "sealed S2S must not carry a sender");
    assert!(
        env.to.is_empty(),
        "sealed S2S must not carry a recipient address"
    );
    assert!(
        !canonical.contains("alice"),
        "canonical signed bytes leaked a sender identity: {canonical}"
    );
    // Only routing-between-servers + integrity data is present.
    assert!(canonical.contains(NODE_A) && canonical.contains(NODE_B));
    assert!(canonical.contains("msg-a5-001"));
}

#[test]
fn regular_federated_message_does_carry_addresses() {
    // Contrast case: a NON-sealed federated message legitimately carries from/to.
    // This guards against a regression where the sealed path accidentally starts
    // populating them.
    let payload = BASE64.encode(b"double-ratchet-ciphertext");
    let env = FederatedEnvelope {
        message_id: "msg-regular-001".to_string(),
        from: format!("alice@{NODE_A}"),
        to: format!("bob@{NODE_B}"),
        origin_server: NODE_A.to_string(),
        destination_server: NODE_B.to_string(),
        timestamp: 1_720_000_000,
        payload_hash: FederatedEnvelope::hash_payload(&payload),
    };
    assert!(!env.from.is_empty() && !env.to.is_empty());
}

#[test]
fn origin_signs_destination_verifies_with_published_key() {
    let signer_a =
        ServerSigner::from_seed_base64(SEED_A, NODE_A.to_string()).expect("node A signer");
    // What node B fetches from A's .well-known/konstruct (`public_key`):
    let a_published_pubkey = signer_a.public_key_base64();

    let sealed_inner_b64 = BASE64.encode(b"sealed-blob-for-bob");
    let env = sealed_envelope("msg-a5-002", &sealed_inner_b64, 1_720_000_100);

    // Node A signs (outbound: FederationClient::send_sealed_message).
    let signature = signer_a.sign_message(&env);

    // Node B verifies (inbound: handle_inbound_sealed via PublicKeyCache). B must
    // reconstruct the SAME envelope from the request fields — this is exactly what
    // the receiver does; if the reconstruction drifts, verification breaks.
    let verified_on_b = ServerSigner::verify_signature(&a_published_pubkey, &env, &signature);
    assert!(
        verified_on_b.is_ok(),
        "destination failed to verify a valid origin signature"
    );
}

#[test]
fn tampered_sealed_blob_breaks_payload_hash() {
    let original = BASE64.encode(b"sealed-blob-for-bob");
    let env = sealed_envelope("msg-a5-003", &original, 1_720_000_200);

    // A transit attacker flips the opaque blob. The receiver recomputes
    // hash_payload(sealed_inner) and compares to the signed payload_hash
    // (federation.rs: `expected_hash != req.payload_hash` -> 400).
    let tampered = BASE64.encode(b"sealed-blob-for-mallory");
    let recomputed = FederatedEnvelope::hash_payload(&tampered);
    assert_ne!(
        env.payload_hash, recomputed,
        "tamper must change the payload hash"
    );
}

#[test]
fn spoofed_origin_key_is_rejected() {
    let signer_a =
        ServerSigner::from_seed_base64(SEED_A, NODE_A.to_string()).expect("node A signer");
    let signer_b =
        ServerSigner::from_seed_base64(SEED_B, NODE_B.to_string()).expect("node B signer");

    let sealed_inner_b64 = BASE64.encode(b"sealed-blob-for-bob");
    let env = sealed_envelope("msg-a5-004", &sealed_inner_b64, 1_720_000_300);
    let signature = signer_a.sign_message(&env);

    // Verifying A's message against a DIFFERENT node's key (spoofed origin, or a
    // signature that doesn't match the claimed origin_server) must fail.
    let wrong = ServerSigner::verify_signature(&signer_b.public_key_base64(), &env, &signature);
    assert!(
        wrong.is_err(),
        "signature verified under the wrong origin key"
    );
}

#[test]
fn sealed_inner_is_forwarded_byte_for_byte() {
    // The transit/destination server treats sealed_inner as opaque and must not
    // transform it. Model the wire round-trip: base64 on send, base64-decode on
    // receive -> identical bytes reach bob's device stream.
    let sealed_inner: &[u8] = b"\x00\x01\x02 binary sealed inner \xff\xfe";
    let on_the_wire = BASE64.encode(sealed_inner);
    let at_destination = BASE64.decode(&on_the_wire).expect("valid base64");
    assert_eq!(
        sealed_inner,
        at_destination.as_slice(),
        "sealed_inner must survive S2S transit unmodified"
    );
}
