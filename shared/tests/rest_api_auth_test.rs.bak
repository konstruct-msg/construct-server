// ============================================================================
// REST API Auth Endpoints Tests
// ============================================================================
//
// Tests for authentication endpoints:
// - POST /api/v1/auth/register - Register new user
// - POST /api/v1/auth/login - Login user
// - POST /auth/refresh - Refresh access token
// - POST /auth/logout - Logout user
//
// ============================================================================

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::{BundleData, SuiteKeyMaterial, UploadableKeyBundle};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{cleanup_rate_limits, spawn_app};

// Helper function to generate a valid test username (letters, numbers, underscores only)
fn generate_test_username(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        Uuid::new_v4().to_string().replace('-', "_")
    )
}

// Helper function to create HTTP client with API headers (bypasses CSRF)
fn create_api_client() -> reqwest::Client {
    reqwest::Client::builder()
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "X-Requested-With",
                reqwest::header::HeaderValue::from_static("XMLHttpRequest"),
            );
            headers
        })
        .build()
        .unwrap()
}

// Helper function to create a valid test key bundle with real Ed25519 keys and signatures
fn create_test_bundle(user_id: Option<String>) -> UploadableKeyBundle {
    // Generate a real Ed25519 key pair for signing
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Create key material for suite 1 (CLASSIC_X25519)
    let suite_material = SuiteKeyMaterial {
        suite_id: 1,
        identity_key: BASE64.encode(vec![0u8; 32]), // 32 bytes for X25519
        signed_prekey: BASE64.encode(vec![1u8; 32]), // 32 bytes for X25519
        signed_prekey_signature: BASE64.encode(vec![2u8; 64]), // 64 bytes for Ed25519 signature
        one_time_prekeys: vec![],
    };

    // Create BundleData
    let bundle_data = BundleData {
        user_id: user_id.unwrap_or_else(|| "temp-user-id".to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_material],
    };

    // Serialize to canonical bytes for signing
    let canonical_bytes = bundle_data.canonical_bytes().unwrap();

    // Sign the bundle data with the real Ed25519 key
    let signature = signing_key.sign(&canonical_bytes);

    // Create and return UploadableKeyBundle with valid signature
    UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()), // Real Ed25519 public key (32 bytes)
        bundle_data: BASE64.encode(canonical_bytes),
        signature: BASE64.encode(signature.to_bytes()), // Real Ed25519 signature (64 bytes)
        nonce: None,
        timestamp: None,
    }
}

// Helper function to extract tokens from auth response
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse {
    user_id: String,
    access_token: String,
    refresh_token: String,
    expires_at: i64,
}

// ============================================================================
// POST /api/v1/auth/register Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_register_success() {
    // Cleanup rate limits before test to avoid interference
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let bundle = create_test_bundle(None);
    let request = json!({
        "username": generate_test_username("testuser"),
        "password": "TestPassword123!",
        "keyBundle": bundle  // camelCase matches serde(rename_all = "camelCase")
    });

    let client = create_api_client();
    let response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&request)
        .send()
        .await
        .unwrap();

    let status = response.status();
    match status {
        reqwest::StatusCode::CREATED => {
            let auth_response: AuthResponse = response.json().await.unwrap();
            assert!(!auth_response.user_id.is_empty());
            assert!(!auth_response.access_token.is_empty());
            assert!(!auth_response.refresh_token.is_empty());
            assert!(auth_response.expires_at > 0);
        }
        _ => {
            let error_text = response.text().await.unwrap();
            eprintln!("Error response (status {}): {}", status, error_text);
            panic!("Expected 201 CREATED, got {}: {}", status, error_text);
        }
    }
}

#[tokio::test]
#[serial]
async fn test_register_duplicate_username() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");

    // First registration
    let bundle1 = create_test_bundle(None);
    let request1 = json!({
        "username": username.clone(),
        "password": "TestPassword123!",
        "keyBundle": bundle1
    });

    let client = create_api_client();
    let response1 = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&request1)
        .send()
        .await
        .unwrap();

    let status1 = response1.status();
    if status1 != reqwest::StatusCode::CREATED {
        let error_text = response1.text().await.unwrap();
        panic!(
            "First registration failed (status {}): {}",
            status1, error_text
        );
    }

    // Second registration with same username
    let bundle2 = create_test_bundle(None);
    let request2 = json!({
        "username": username,
        "password": "TestPassword123!",
        "keyBundle": bundle2
    });

    let response2 = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&request2)
        .send()
        .await
        .unwrap();

    assert_eq!(response2.status(), reqwest::StatusCode::BAD_REQUEST);
    let error_body: serde_json::Value = response2.json().await.unwrap();
    assert!(error_body.get("error").is_some());
    let error_msg = error_body["error"].as_str().unwrap();
    assert!(
        error_msg.to_lowercase().contains("username") || error_msg.to_lowercase().contains("taken")
    );
}

#[tokio::test]
#[serial]
async fn test_register_invalid_password() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let bundle = create_test_bundle(None);
    let request = json!({
        "username": generate_test_username("testuser"),
        "password": "short", // Too short
        "keyBundle": bundle
    });

    let client = create_api_client();
    let response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let error_body: serde_json::Value = response.json().await.unwrap();
    assert!(error_body.get("error").is_some());
    let error_msg = error_body["error"].as_str().unwrap().to_lowercase();
    // Error message should mention password, length, or strength
    assert!(
        error_msg.contains("password")
            || error_msg.contains("length")
            || error_msg.contains("strength")
            || error_msg.contains("short")
    );
}

#[tokio::test]
#[serial]
async fn test_register_invalid_username() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let bundle = create_test_bundle(None);
    let request = json!({
        "username": "ab", // Too short (minimum 3 characters)
        "password": "TestPassword123!",
        "keyBundle": bundle
    });

    let client = create_api_client();
    let response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let error_body: serde_json::Value = response.json().await.unwrap();
    assert!(error_body.get("error").is_some());
}

#[tokio::test]
#[serial]
async fn test_register_missing_key_bundle() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let request = json!({
        "username": generate_test_username("testuser"),
        "password": "TestPassword123!"
        // Missing keyBundle
    });

    let client = create_api_client();
    let response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request or 422 Unprocessable Entity (validation error)
    // Axum returns 422 for missing required fields
    assert!(
        response.status() == reqwest::StatusCode::BAD_REQUEST
            || response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
#[serial]
async fn test_register_rate_limiting() {
    // Cleanup rate limits before test
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let client = create_api_client();

    // Try to register 6 times (limit is 5 per hour per IP)
    for i in 0..6 {
        let bundle = create_test_bundle(None);
        let request = json!({
            "username": format!("{}_{}", generate_test_username("testuser"), i),
            "password": "TestPassword123!",
            "keyBundle": bundle
        });

        let response = client
            .post(&format!("http://{}/api/v1/auth/register", app.address))
            .json(&request)
            .send()
            .await
            .unwrap();

        if i < 5 {
            // First 5 should succeed
            assert_eq!(response.status(), reqwest::StatusCode::CREATED);
        } else {
            // 6th should be rate limited
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            let error_body: serde_json::Value = response.json().await.unwrap();
            assert!(error_body.get("error").is_some());
            let error_msg = error_body["error"].as_str().unwrap();
            assert!(
                error_msg.to_lowercase().contains("too many")
                    || error_msg.to_lowercase().contains("rate limit")
            );
        }
    }
}

// ============================================================================
// POST /api/v1/auth/login Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_login_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");
    let password = "TestPassword123!";

    // First register a user
    let bundle = create_test_bundle(None);
    let register_request = json!({
        "username": username.clone(),
        "password": password,
        "keyBundle": bundle
    });

    let client = create_api_client();
    let register_response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let register_status = register_response.status();
    if register_status != reqwest::StatusCode::CREATED {
        let error_text = register_response.text().await.unwrap();
        panic!(
            "Registration failed (status {}): {}",
            register_status, error_text
        );
    }

    // Now try to login
    let login_request = json!({
        "username": username,
        "password": password
    });

    let login_response = client
        .post(&format!("http://{}/api/v1/auth/login", app.address))
        .json(&login_request)
        .send()
        .await
        .unwrap();

    assert_eq!(login_response.status(), reqwest::StatusCode::OK);

    let auth_response: AuthResponse = login_response.json().await.unwrap();
    assert!(!auth_response.user_id.is_empty());
    assert!(!auth_response.access_token.is_empty());
    assert!(!auth_response.refresh_token.is_empty());
    assert!(auth_response.expires_at > 0);
}

#[tokio::test]
#[serial]
async fn test_login_invalid_credentials() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");
    let password = "TestPassword123!";

    // Register a user
    let bundle = create_test_bundle(None);
    let register_request = json!({
        "username": username.clone(),
        "password": password,
        "keyBundle": bundle
    });

    let client = create_api_client();
    let register_response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(register_response.status(), reqwest::StatusCode::CREATED);

    // Try to login with wrong password
    let login_request = json!({
        "username": username,
        "password": "WrongPassword123!"
    });

    let login_response = client
        .post(&format!("http://{}/api/v1/auth/login", app.address))
        .json(&login_request)
        .send()
        .await
        .unwrap();

    assert_eq!(login_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let error_body: serde_json::Value = login_response.json().await.unwrap();
    assert!(error_body.get("error").is_some());
    let error_msg = error_body["error"].as_str().unwrap();
    assert!(
        error_msg.to_lowercase().contains("invalid")
            || error_msg.to_lowercase().contains("password")
    );
}

#[tokio::test]
#[serial]
async fn test_login_nonexistent_user() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let login_request = json!({
        "username": generate_test_username("nonexistent"),
        "password": "TestPassword123!"
    });

    let client = create_api_client();
    let login_response = client
        .post(&format!("http://{}/api/v1/auth/login", app.address))
        .json(&login_request)
        .send()
        .await
        .unwrap();

    assert_eq!(login_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let error_body: serde_json::Value = login_response.json().await.unwrap();
    assert!(error_body.get("error").is_some());
    let error_msg = error_body["error"].as_str().unwrap();
    assert!(
        error_msg.to_lowercase().contains("invalid")
            || error_msg.to_lowercase().contains("username")
    );
}

// ============================================================================
// POST /auth/refresh Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_refresh_token_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");
    let password = "TestPassword123!";

    // Register and login to get tokens
    let bundle = create_test_bundle(None);
    let register_request = json!({
        "username": username.clone(),
        "password": password,
        "keyBundle": bundle
    });

    let client = create_api_client();
    let register_response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let register_status = register_response.status();
    if register_status != reqwest::StatusCode::CREATED {
        let error_text = register_response.text().await.unwrap();
        panic!(
            "Registration failed (status {}): {}",
            register_status, error_text
        );
    }
    let auth_response: AuthResponse = register_response.json().await.unwrap();
    let refresh_token = auth_response.refresh_token;

    // Now refresh the token
    let refresh_request = json!({
        "refreshToken": refresh_token
    });

    let refresh_response = client
        .post(&format!("http://{}/auth/refresh", app.address))
        .json(&refresh_request)
        .send()
        .await
        .unwrap();

    assert_eq!(refresh_response.status(), reqwest::StatusCode::OK);

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RefreshTokenResponse {
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    }

    let refresh_response_body: RefreshTokenResponse = refresh_response.json().await.unwrap();
    assert!(!refresh_response_body.access_token.is_empty());
    assert!(!refresh_response_body.refresh_token.is_empty());
    assert!(refresh_response_body.expires_at > 0);

    // New refresh token should be different from old one (token rotation)
    assert_ne!(refresh_response_body.refresh_token, refresh_token);
}

#[tokio::test]
#[serial]
async fn test_refresh_token_invalid() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let refresh_request = json!({
        "refreshToken": "invalid.token.here"
    });

    let client = create_api_client();
    let refresh_response = client
        .post(&format!("http://{}/auth/refresh", app.address))
        .json(&refresh_request)
        .send()
        .await
        .unwrap();

    assert_eq!(refresh_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let error_body: serde_json::Value = refresh_response.json().await.unwrap();
    assert!(error_body.get("error").is_some());
}

#[tokio::test]
#[serial]
async fn test_refresh_token_revoked() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");
    let password = "TestPassword123!";

    // Register and login to get tokens
    let bundle = create_test_bundle(None);
    let register_request = json!({
        "username": username.clone(),
        "password": password,
        "keyBundle": bundle
    });

    let client = create_api_client();
    let register_response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let register_status = register_response.status();
    if register_status != reqwest::StatusCode::CREATED {
        let error_text = register_response.text().await.unwrap();
        panic!(
            "Registration failed (status {}): {}",
            register_status, error_text
        );
    }
    let auth_response: AuthResponse = register_response.json().await.unwrap();
    let access_token = auth_response.access_token;
    let refresh_token = auth_response.refresh_token;

    // Logout (which should revoke the refresh token)
    // Using allDevices: true to ensure refresh token is revoked
    // (single-device logout requires refresh token JTI which we don't have in this test)
    let logout_request = json!({
        "allDevices": true
    });

    let logout_response = client
        .post(&format!("http://{}/auth/logout", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&logout_request)
        .send()
        .await
        .unwrap();

    assert_eq!(logout_response.status(), reqwest::StatusCode::OK);

    // Try to refresh with revoked token
    let refresh_request = json!({
        "refreshToken": refresh_token
    });

    let refresh_response = client
        .post(&format!("http://{}/auth/refresh", app.address))
        .json(&refresh_request)
        .send()
        .await
        .unwrap();

    // Should fail - token was revoked
    assert_eq!(refresh_response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let error_body: serde_json::Value = refresh_response.json().await.unwrap();
    assert!(error_body.get("error").is_some());
}

// ============================================================================
// POST /auth/logout Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_logout_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");
    let password = "TestPassword123!";

    // Register and login to get tokens
    let bundle = create_test_bundle(None);
    let register_request = json!({
        "username": username.clone(),
        "password": password,
        "keyBundle": bundle
    });

    let client = create_api_client();
    let register_response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let register_status = register_response.status();
    if register_status != reqwest::StatusCode::CREATED {
        let error_text = register_response.text().await.unwrap();
        panic!(
            "Registration failed (status {}): {}",
            register_status, error_text
        );
    }
    let auth_response: AuthResponse = register_response.json().await.unwrap();
    let access_token = auth_response.access_token;

    // Logout
    let logout_request = json!({
        "allDevices": false
    });

    let logout_response = client
        .post(&format!("http://{}/auth/logout", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&logout_request)
        .send()
        .await
        .unwrap();

    assert_eq!(logout_response.status(), reqwest::StatusCode::OK);
    let logout_body: serde_json::Value = logout_response.json().await.unwrap();
    assert_eq!(logout_body.get("status").unwrap().as_str().unwrap(), "ok");
}

#[tokio::test]
#[serial]
async fn test_logout_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;

    let logout_request = json!({
        "allDevices": false
    });

    let client = create_api_client();
    let logout_response = client
        .post(&format!("http://{}/auth/logout", app.address))
        .json(&logout_request)
        .send()
        .await
        .unwrap();

    // Should require authentication
    assert!(
        logout_response.status() == reqwest::StatusCode::UNAUTHORIZED
            || logout_response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_logout_invalidates_tokens() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let username = generate_test_username("testuser");
    let password = "TestPassword123!";

    // Register and login to get tokens
    let bundle = create_test_bundle(None);
    let register_request = json!({
        "username": username.clone(),
        "password": password,
        "keyBundle": bundle
    });

    let client = create_api_client();
    let register_response = client
        .post(&format!("http://{}/api/v1/auth/register", app.address))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let register_status = register_response.status();
    if register_status != reqwest::StatusCode::CREATED {
        let error_text = register_response.text().await.unwrap();
        panic!(
            "Registration failed (status {}): {}",
            register_status, error_text
        );
    }
    let auth_response: AuthResponse = register_response.json().await.unwrap();
    let access_token = auth_response.access_token;
    let refresh_token = auth_response.refresh_token;

    // Logout
    let logout_request = json!({
        "allDevices": true // Logout from all devices
    });

    let logout_response = client
        .post(&format!("http://{}/auth/logout", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&logout_request)
        .send()
        .await
        .unwrap();

    assert_eq!(logout_response.status(), reqwest::StatusCode::OK);

    // Try to refresh with revoked token
    let refresh_request = json!({
        "refreshToken": refresh_token
    });

    let refresh_response = client
        .post(&format!("http://{}/auth/refresh", app.address))
        .json(&refresh_request)
        .send()
        .await
        .unwrap();

    // Should fail - token was revoked
    assert_eq!(refresh_response.status(), reqwest::StatusCode::UNAUTHORIZED);
}
