//! Public Key Endpoint Test
//!
//! Critical test to verify that GET /api/v1/users/{user_id}/public-key
//! returns the REQUESTED user's public key, NOT the authenticated user's key.
//!
//! ## The Bug This Tests
//!
//! INCORRECT implementation (hypothetical bug):
//! ```rust
//! async fn get_public_key(user_id: String, auth: AuthToken) {
//!     // ❌ Returns bundle of REQUESTING user from auth token
//!     db.get_public_key(auth.user_id).await
//! }
//! ```
//!
//! CORRECT implementation:
//! ```rust
//! async fn get_public_key(user_id: String, auth: AuthToken) {
//!     // ✅ Returns bundle of TARGET user from URL parameter
//!     db.get_public_key(&user_id).await
//! }
//! ```
//!
//! ## Why This Bug Breaks E2EE
//!
//! Signal Protocol X3DH requires Alice to fetch Bob's identity key:
//! ```
//! shared_secret = DH(alice_ephemeral, bob_identity) + DH(alice_identity, bob_signed_prekey) + ...
//! ```
//!
//! If server returns Alice's own identity key when she requests Bob's:
//! - Alice computes shared_secret using her OWN identity key thinking it's Bob's
//! - Bob computes shared_secret using his ACTUAL identity key
//! - Shared secrets don't match → InvalidCiphertext on decryption
//!
//! ## Test Procedure
//!
//! 1. Register Kim with identity key = AAAA...
//! 2. Register Max with identity key = BBBB...
//! 3. Kim requests GET /api/v1/users/{max_id}/public-key
//! 4. Verify response contains identity_public = BBBB... (Max's key)
//! 5. Verify response DOES NOT contain AAAA... (Kim's key)

mod test_utils;

use base64::{Engine as _, engine::general_purpose};
use test_utils::{TestUser, spawn_app};

/// Helper to register a user and extract their identity public key
/// Uses existing register_test_user helper and returns the generated identity key
async fn register_user_and_get_identity(
    ctx: &test_utils::TestApp,
    username: &str,
) -> (TestUser, String) {
    // Use existing test helper which generates proper keys
    let user = test_utils::register_test_user(ctx, username).await;

    // Fetch the user's public key bundle to get their identity key
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            ctx.auth_address, user.user_id
        ))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .send()
        .await
        .expect("Failed to get own public key");

    assert_eq!(response.status(), 200, "Should be able to get own key");

    let bundle: serde_json::Value = response.json().await.unwrap();
    let bundle_data_b64 = bundle["keyBundle"]["bundleData"].as_str().unwrap();
    let bundle_data_bytes = general_purpose::STANDARD.decode(bundle_data_b64).unwrap();
    let bundle_data: serde_json::Value = serde_json::from_slice(&bundle_data_bytes).unwrap();

    let identity_key = bundle_data["supportedSuites"][0]["identityKey"]
        .as_str()
        .unwrap()
        .to_string();

    (user, identity_key)
}

#[tokio::test]
async fn test_get_public_key_returns_target_user_not_requester() {
    let ctx = spawn_app().await;

    // Register Kim and Max with DIFFERENT identity keys
    let (kim, kim_identity_b64) = register_user_and_get_identity(&ctx, "kim_pubkey_test").await;
    let (max, max_identity_b64) = register_user_and_get_identity(&ctx, "max_pubkey_test").await;

    println!(
        "✅ Kim registered with identity key: {}...",
        &kim_identity_b64[..20]
    );
    println!(
        "✅ Max registered with identity key: {}...",
        &max_identity_b64[..20]
    );

    // Verify keys are different
    assert_ne!(
        kim_identity_b64, max_identity_b64,
        "Kim and Max should have different identity keys"
    );

    // === TEST 1: Kim requests Max's public key ===

    let client = reqwest::Client::new();
    let kim_requests_max_response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            ctx.auth_address, max.user_id
        ))
        .header("Authorization", format!("Bearer {}", kim.access_token))
        .send()
        .await
        .expect("Failed to get Max's public key");

    assert_eq!(
        kim_requests_max_response.status(),
        200,
        "Kim should be able to get Max's public key"
    );

    let max_bundle: serde_json::Value = kim_requests_max_response
        .json()
        .await
        .expect("Failed to parse Max's key bundle");

    // Extract identity_public from nested structure
    // Response format: { keyBundle: { bundleData: "base64...", ... }, ... }
    let bundle_data_b64 = max_bundle["keyBundle"]["bundleData"]
        .as_str()
        .expect("keyBundle.bundleData should exist");

    let bundle_data_bytes = general_purpose::STANDARD
        .decode(bundle_data_b64)
        .expect("bundleData should be valid base64");

    let bundle_data: serde_json::Value =
        serde_json::from_slice(&bundle_data_bytes).expect("bundleData should be valid JSON");

    let identity_public = bundle_data["supportedSuites"][0]["identityKey"]
        .as_str()
        .expect("identityKey should exist");

    println!("📦 Response identity key: {}...", &identity_public[..20]);

    // CRITICAL ASSERTION: Should return Max's key, NOT Kim's key
    assert_eq!(
        identity_public, max_identity_b64,
        "❌ BUG DETECTED: Server returned Kim's identity key when Kim requested Max's key!\n\
         This is a critical bug that breaks X3DH key exchange.\n\
         Expected: {}\n\
         Got:      {}",
        max_identity_b64, identity_public
    );

    assert_ne!(
        identity_public, kim_identity_b64,
        "❌ CRITICAL BUG: Server returned requester's OWN identity key instead of target user's key!\n\
         This breaks Signal Protocol X3DH completely."
    );

    println!("✅ PASS: Server correctly returned Max's identity key (not Kim's)");

    // === TEST 2: Max requests Kim's public key (reverse direction) ===

    let max_requests_kim_response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            ctx.auth_address, kim.user_id
        ))
        .header("Authorization", format!("Bearer {}", max.access_token))
        .send()
        .await
        .expect("Failed to get Kim's public key");

    assert_eq!(max_requests_kim_response.status(), 200);

    let kim_bundle: serde_json::Value = max_requests_kim_response
        .json()
        .await
        .expect("Failed to parse Kim's key bundle");

    let kim_bundle_data_b64 = kim_bundle["keyBundle"]["bundleData"].as_str().unwrap();
    let kim_bundle_data_bytes = general_purpose::STANDARD
        .decode(kim_bundle_data_b64)
        .unwrap();
    let kim_bundle_data: serde_json::Value =
        serde_json::from_slice(&kim_bundle_data_bytes).unwrap();

    let kim_identity_from_response = kim_bundle_data["supportedSuites"][0]["identityKey"]
        .as_str()
        .unwrap();

    // Should return Kim's key, NOT Max's key
    assert_eq!(
        kim_identity_from_response, kim_identity_b64,
        "Server should return Kim's identity key when Max requests it"
    );

    assert_ne!(
        kim_identity_from_response, max_identity_b64,
        "❌ CRITICAL BUG: Server returned requester's identity key instead of target user's key"
    );

    println!("✅ PASS: Server correctly returned Kim's identity key (not Max's)");

    // === TEST 3: Verify keys are still different ===

    assert_ne!(
        identity_public, kim_identity_from_response,
        "Keys should be different for different users"
    );

    println!("🎉 ALL TESTS PASSED!");
    println!("   ✓ Kim → Max: Got Max's key");
    println!("   ✓ Max → Kim: Got Kim's key");
    println!("   ✓ Keys are different");
    println!("   ✓ No auth token confusion");
}

#[tokio::test]
async fn test_get_own_public_key() {
    let ctx = spawn_app().await;

    let (kim, kim_identity_b64) = register_user_and_get_identity(&ctx, "kim_own_test").await;

    // Kim requests her OWN public key (valid use case for key verification)
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/api/v1/users/{}/public-key",
            ctx.auth_address, kim.user_id
        ))
        .header("Authorization", format!("Bearer {}", kim.access_token))
        .send()
        .await
        .expect("Failed to get own public key");

    assert_eq!(response.status(), 200);

    let bundle: serde_json::Value = response.json().await.unwrap();
    let bundle_data_b64 = bundle["keyBundle"]["bundleData"].as_str().unwrap();
    let bundle_data_bytes = general_purpose::STANDARD.decode(bundle_data_b64).unwrap();
    let bundle_data: serde_json::Value = serde_json::from_slice(&bundle_data_bytes).unwrap();

    let identity_from_response = bundle_data["supportedSuites"][0]["identityKey"]
        .as_str()
        .unwrap();

    assert_eq!(
        identity_from_response, kim_identity_b64,
        "Should be able to retrieve own public key"
    );

    println!("✅ User can successfully retrieve their own public key");
}
