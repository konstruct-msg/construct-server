/// X3DH (Extended Triple Diffie-Hellman) Protocol Compliance Tests
/// 
/// SPECIFICATION: Signal Protocol - X3DH Key Agreement Protocol
/// Reference: https://signal.org/docs/specifications/x3dh/
/// 
/// These tests verify that our X3DH implementation conforms to the Signal specification.

use crate::test_utils::*;

#[tokio::test]
async fn test_x3dh_key_bundle_contains_all_required_fields() {
    // SPEC: Signal Protocol §2.1 - Key Bundle Format
    // A key bundle MUST contain:
    // - Identity Key (IK)
    // - Signed PreKey (SPK)
    // - Signed PreKey Signature
    // - One-Time PreKey (OPK) - optional
    
    let ctx = spawn_app().await;
    
    // Register user
    let user = register_test_user(&ctx, "alice").await;
    
    // Get key bundle
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/api/v1/keys/{}", ctx.messaging_address, user.user_id))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .send()
        .await
        .expect("Failed to get key bundle");
    
    assert_eq!(response.status(), 200, "Failed to fetch key bundle");
    
    let bundle: serde_json::Value = response.json().await.unwrap();
    
    // SPEC REQUIREMENT: Identity Key MUST be present
    assert!(
        bundle.get("identityPublicKey").is_some(),
        "PROTOCOL VIOLATION: Missing identityPublicKey in key bundle"
    );
    
    // SPEC REQUIREMENT: Signed PreKey MUST be present
    assert!(
        bundle.get("signedPrekey").is_some(),
        "PROTOCOL VIOLATION: Missing signedPrekey in key bundle"
    );
    
    // SPEC REQUIREMENT: Signed PreKey Signature MUST be present
    assert!(
        bundle.get("signedPrekeySignature").is_some(),
        "PROTOCOL VIOLATION: Missing signedPrekeySignature in key bundle"
    );
    
    // SPEC REQUIREMENT: Suite ID MUST be present (our extension)
    assert!(
        bundle.get("suiteId").is_some(),
        "Missing suiteId in key bundle"
    );
    
    // One-Time PreKey is optional (may be null if pool exhausted)
    // This is OK per spec
}
