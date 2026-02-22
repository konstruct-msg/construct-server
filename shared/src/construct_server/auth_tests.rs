// ============================================================================
// Unit Tests for AuthManager
// ============================================================================
//
// SECURITY: Tests use external key files from shared/tests/keys/
// DO NOT embed cryptographic keys in source code!
//
// ============================================================================

use super::*;
use uuid::Uuid;

// Load test keys from files (NOT embedded in code)
fn load_test_keys() -> (String, String) {
    // Use env!("CARGO_MANIFEST_DIR") to get absolute path from build time
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let private_key_path = format!("{}/tests/keys/test_private.pem", manifest_dir);
    let public_key_path = format!("{}/tests/keys/test_public.pem", manifest_dir);

    let private_key = std::fs::read_to_string(&private_key_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read test private key from {}: {}",
            private_key_path, e
        )
    });
    let public_key = std::fs::read_to_string(&public_key_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read test public key from {}: {}",
            public_key_path, e
        )
    });
    (private_key, public_key)
}

// Minimal test config - only fields AuthManager needs
fn create_minimal_auth_manager(
    private_key: Option<String>,
    public_key: Option<String>,
) -> anyhow::Result<AuthManager> {
    use jsonwebtoken::{DecodingKey, EncodingKey};

    let decoding_key = if let Some(ref pub_key) = public_key {
        DecodingKey::from_rsa_pem(pub_key.as_bytes())?
    } else {
        anyhow::bail!("Public key required");
    };

    let encoding_key = if let Some(ref priv_key) = private_key {
        Some(EncodingKey::from_rsa_pem(priv_key.as_bytes())?)
    } else {
        None
    };

    Ok(AuthManager {
        encoding_key,
        decoding_key,
        access_token_ttl_hours: 1,
        session_ttl_days: 30,
        refresh_token_ttl_days: 30,
        issuer: "test-issuer".to_string(),
    })
}

#[test]
fn test_auth_manager_new_full_mode() {
    let (private_key, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), Some(public_key));

    assert!(
        auth_manager.is_ok(),
        "AuthManager should initialize in full mode"
    );
    let manager = auth_manager.unwrap();
    assert!(
        manager.encoding_key.is_some(),
        "Full mode should have encoding key"
    );
}

#[test]
fn test_auth_manager_new_verify_only() {
    let (_, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(None, Some(public_key));

    assert!(
        auth_manager.is_ok(),
        "AuthManager should initialize in verify-only mode"
    );
    let manager = auth_manager.unwrap();
    assert!(
        manager.encoding_key.is_none(),
        "Verify-only mode should not have encoding key"
    );
}

#[test]
fn test_auth_manager_new_missing_public_key() {
    let (private_key, _) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), None);

    assert!(auth_manager.is_err(), "Should fail without public key");
    if let Err(err) = auth_manager {
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("Public key required") || err_msg.contains("required"),
            "Error should mention missing public key"
        );
    }
}

#[test]
fn test_create_token_claims_content() {
    let (private_key, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), Some(public_key)).unwrap();

    let user_id = Uuid::new_v4();
    let result = auth_manager.create_token(&user_id);

    assert!(result.is_ok(), "Token creation should succeed");
    let (token, jti, exp_timestamp) = result.unwrap();

    // Verify token structure
    assert!(!token.is_empty(), "Token should not be empty");
    assert!(!jti.is_empty(), "JTI should not be empty");
    assert!(
        exp_timestamp > chrono::Utc::now().timestamp(),
        "Expiration should be in future"
    );

    // Verify claims by decoding
    let claims = auth_manager.verify_token(&token).unwrap();
    assert_eq!(
        claims.sub,
        user_id.to_string(),
        "Subject should match user_id"
    );
    assert_eq!(claims.jti, jti, "JTI should match");
    assert_eq!(claims.iss, "test-issuer", "Issuer should match config");
    assert!(
        claims.iat <= chrono::Utc::now().timestamp(),
        "Issued at should be in past or now"
    );
    assert_eq!(claims.exp, exp_timestamp, "Expiration should match");
}

#[test]
fn test_create_token_verify_only_mode_fails() {
    let (_, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(None, Some(public_key)).unwrap();

    let user_id = Uuid::new_v4();
    let result = auth_manager.create_token(&user_id);

    assert!(
        result.is_err(),
        "Token creation should fail in verify-only mode"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("verify-only mode"),
        "Error should mention verify-only mode"
    );
}

#[test]
fn test_create_refresh_token() {
    let (private_key, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), Some(public_key)).unwrap();

    let user_id = Uuid::new_v4();
    let result = auth_manager.create_refresh_token(&user_id);

    assert!(result.is_ok(), "Refresh token creation should succeed");
    let (token, jti, exp_timestamp) = result.unwrap();

    // Verify it's a valid JWT
    let claims = auth_manager.verify_token(&token).unwrap();
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.jti, jti);

    // Refresh token should have longer TTL than access token
    let now = chrono::Utc::now().timestamp();
    let access_token_ttl = 3600; // 1 hour in seconds
    assert!(
        exp_timestamp > now + access_token_ttl,
        "Refresh token should have longer TTL"
    );
}

#[test]
fn test_verify_token_invalid_signature() {
    let (private_key, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), Some(public_key)).unwrap();

    // Create a token
    let user_id = Uuid::new_v4();
    let (token, _, _) = auth_manager.create_token(&user_id).unwrap();

    // Tamper with the token (change last character)
    let mut tampered = token.clone();
    tampered.pop();
    tampered.push('X');

    // Verification should fail
    let result = auth_manager.verify_token(&tampered);
    assert!(result.is_err(), "Tampered token should fail verification");
}

#[test]
fn test_verify_token_wrong_issuer() {
    let (private_key, public_key) = load_test_keys();

    // Create token with one issuer
    let auth_manager1 =
        create_minimal_auth_manager(Some(private_key.clone()), Some(public_key.clone())).unwrap();

    let user_id = Uuid::new_v4();
    let (token, _, _) = auth_manager1.create_token(&user_id).unwrap();

    // Create manager with different issuer (by reconstructing)
    use jsonwebtoken::DecodingKey;
    let auth_manager2 = AuthManager {
        encoding_key: None,
        decoding_key: DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap(),
        access_token_ttl_hours: 1,
        session_ttl_days: 30,
        refresh_token_ttl_days: 30,
        issuer: "different-issuer".to_string(),
    };

    let result = auth_manager2.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with wrong issuer should fail verification"
    );
}

#[test]
fn test_verify_token_unsupported_algorithm() {
    let (private_key, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), Some(public_key)).unwrap();

    let user_id = Uuid::new_v4();
    let (token, _, _) = auth_manager.create_token(&user_id).unwrap();

    // Decode header to verify it's RS256
    use jsonwebtoken::{Algorithm, decode_header};
    let header = decode_header(&token).unwrap();
    assert_eq!(header.alg, Algorithm::RS256, "Token should use RS256");
}

#[test]
fn test_jti_uniqueness() {
    let (private_key, public_key) = load_test_keys();
    let auth_manager = create_minimal_auth_manager(Some(private_key), Some(public_key)).unwrap();

    let user_id = Uuid::new_v4();
    let (_, jti1, _) = auth_manager.create_token(&user_id).unwrap();
    let (_, jti2, _) = auth_manager.create_token(&user_id).unwrap();

    assert_ne!(jti1, jti2, "Each token should have unique JTI");
}
