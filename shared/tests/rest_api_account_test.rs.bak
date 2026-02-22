// ============================================================================
// REST API Account Endpoints Tests
// ============================================================================
//
// Tests for account management endpoints:
// - GET /api/v1/account - Get account information
// - PUT /api/v1/account - Update account (password)
// - DELETE /api/v1/account - Delete account
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

// Helper function to generate a valid test username
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

// Helper function to create a valid test key bundle
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

// Helper function to register a user and get auth tokens
async fn register_user(
    client: &reqwest::Client,
    app_address: &str,
    username: &str,
    password: &str,
) -> (String, String) {
    let bundle = create_test_bundle(None);

    let request = json!({
        "username": username,
        "password": password,
        "keyBundle": bundle
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/register", app_address))
        .json(&request)
        .send()
        .await
        .unwrap();

    let status = response.status();
    if status != reqwest::StatusCode::CREATED {
        let error_text = response.text().await.unwrap();
        panic!("Registration failed (status {}): {}", status, error_text);
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthResponse {
        user_id: String,
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    }

    let auth_response: AuthResponse = response.json().await.unwrap();
    (auth_response.user_id, auth_response.access_token)
}

// ============================================================================
// GET /api/v1/account Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_account_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Get account information
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AccountInfo {
        user_id: String,
        username: String,
        created_at: Option<String>,
    }

    let account: AccountInfo = response.json().await.unwrap();
    assert_eq!(account.user_id, user_id);
    assert_eq!(account.username, username);
    // Password hash should NOT be in response
}

#[tokio::test]
#[serial]
async fn test_get_account_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to get account without authentication
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized or 403 Forbidden
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[serial]
async fn test_get_account_invalid_token() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to get account with invalid token
    let response = client
        .get(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", "Bearer invalid_token_here")
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized or 403 Forbidden
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

// ============================================================================
// PUT /api/v1/account Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_update_account_password_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "OldPassword123!").await;

    // Update password
    let request = json!({
        "newPassword": "NewPassword456!",
        "oldPassword": "OldPassword123!"
    });

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["message"], "Account updated successfully");

    // Verify new password works by logging in
    let login_request = json!({
        "username": username,
        "password": "NewPassword456!"
    });

    let login_response = client
        .post(&format!("http://{}/api/v1/auth/login", app.address))
        .json(&login_request)
        .send()
        .await
        .unwrap();

    assert_eq!(login_response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_update_account_password_wrong_old_password() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "OldPassword123!").await;

    // Try to update password with wrong old password
    let request = json!({
        "newPassword": "NewPassword456!",
        "oldPassword": "WrongPassword123!"
    });

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized (invalid old password)
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
}

#[tokio::test]
#[serial]
async fn test_update_account_password_missing_old_password() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "OldPassword123!").await;

    // Try to update password without old password
    let request = json!({
        "newPassword": "NewPassword456!"
    });

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
}

#[tokio::test]
#[serial]
async fn test_update_account_password_too_short() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "OldPassword123!").await;

    // Try to update password with too short password
    let request = json!({
        "newPassword": "Short1!",
        "oldPassword": "OldPassword123!"
    });

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("at least 8 characters")
    );
}

#[tokio::test]
#[serial]
async fn test_update_account_username_not_implemented() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Try to update username (not yet implemented)
    let request = json!({
        "username": "new_username"
    });

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request (not implemented)
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("not yet implemented")
    );
}

#[tokio::test]
#[serial]
async fn test_update_account_no_fields() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user
    let username = generate_test_username("testuser");
    let (_user_id, access_token) =
        register_user(&client, &app.address, &username, "TestPassword123!").await;

    // Try to update account without any fields
    let request = json!({});

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("error").is_some());
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("No update fields provided")
    );
}

#[tokio::test]
#[serial]
async fn test_update_account_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to update account without authentication
    let request = json!({
        "newPassword": "NewPassword456!",
        "oldPassword": "OldPassword123!"
    });

    let response = client
        .put(&format!("http://{}/api/v1/account", app.address))
        .json(&request)
        .send()
        .await
        .unwrap();

    // Should return 401 Unauthorized or 403 Forbidden
    assert!(
        response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
    );
}

// ============================================================================
// Account Deletion Tests
// ============================================================================
//
// NOTE: Legacy password-based DELETE /api/v1/account was removed in Phase 5.0.1
//
// Account deletion now uses device-signed flow (more secure):
// - GET /api/v1/users/me/delete-challenge
// - POST /api/v1/users/me/delete-confirm
//
// See: account_deletion.rs for implementation
// See: DEVICE_SIGNED_ACCOUNT_DELETION_SPEC.md for specification
//
// TODO: Add integration tests for device-signed deletion flow
// (requires client-side Ed25519 signing which is complex in tests)
// ============================================================================
