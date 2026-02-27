// ============================================================================
// Notification Service Tests - Phase 2.9
// ============================================================================
//
// Tests for notification service endpoints:
// - POST /api/v1/notifications/register-device - Register device token
// - POST /api/v1/notifications/unregister-device - Unregister device token
// - PUT /api/v1/notifications/preferences - Update notification preferences
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

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_test_username(prefix: &str) -> String {
    // Username must be 3-20 chars, so use only first 8 chars of UUID
    format!("{}_{}", prefix, &Uuid::new_v4().to_string()[0..8])
}

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

#[allow(dead_code)]
fn create_test_bundle(user_id: Option<String>) -> UploadableKeyBundle {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let suite_material = SuiteKeyMaterial {
        suite_id: 1,
        identity_key: BASE64.encode(vec![0u8; 32]),
        signed_prekey: BASE64.encode(vec![1u8; 32]),
        signed_prekey_signature: BASE64.encode(vec![2u8; 64]),
        one_time_prekeys: vec![],
    };

    let bundle_data = BundleData {
        user_id: user_id.unwrap_or_else(|| "temp-user-id".to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        supported_suites: vec![suite_material],
    };

    let canonical_bytes = bundle_data.canonical_bytes().unwrap();
    let signature = signing_key.sign(&canonical_bytes);

    UploadableKeyBundle {
        master_identity_key: BASE64.encode(verifying_key.as_bytes()),
        bundle_data: BASE64.encode(canonical_bytes),
        signature: BASE64.encode(signature.to_bytes()),
        nonce: None,
        timestamp: None,
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct AuthResponse {
    user_id: String,
    access_token: String,
    refresh_token: String,
    expires_at: i64,
}

/// Helper function to register a user and get user_id using passwordless auth
///
/// NOTE: For microservices behind Gateway, we return user_id directly
/// The tests will use X-User-Id header to bypass JWT auth (internal trust pattern)
async fn register_and_get_user_id(client: &reqwest::Client, auth_url: &str) -> String {
    use test_utils::register_user_passwordless;

    let (user_id, _access_token) = register_user_passwordless(
        client,
        &auth_url.replace("http://", "").replace("https://", ""),
        Some(&generate_test_username("notif")),
    )
    .await;

    user_id
}

/// Generate a valid device token (64 hex characters for APNs)
fn generate_device_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

// ============================================================================
// POST /api/v1/notifications/register-device Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn device_token_register_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register user and get token
    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    // Register device token
    let device_token = generate_device_token();
    let request = json!({
        "deviceToken": device_token,
        "deviceName": "iPhone Test",
        "notificationFilter": "visible_all"
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["message"], "Device token registered");
}

#[tokio::test]
#[serial]
async fn device_token_register_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let request = json!({
        "deviceToken": generate_device_token(),
        "notificationFilter": "silent"
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        // No Authorization header
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn device_token_register_invalid_format_empty() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    // Empty device token
    let request = json!({
        "deviceToken": "",
        "notificationFilter": "silent"
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn device_token_register_invalid_format_too_long() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    // Device token > 128 chars
    let request = json!({
        "deviceToken": "a".repeat(200),
        "notificationFilter": "silent"
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn device_token_register_invalid_filter() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    // Invalid notification filter
    let request = json!({
        "deviceToken": generate_device_token(),
        "notificationFilter": "invalid_filter_name"
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn device_token_register_duplicate_updates() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;
    let device_token = generate_device_token();

    // First registration
    let request1 = json!({
        "deviceToken": device_token.clone(),
        "deviceName": "iPhone v1",
        "notificationFilter": "silent"
    });

    let response1 = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request1)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response1.status(), reqwest::StatusCode::OK);

    // Second registration (same token, different name) - should update
    let request2 = json!({
        "deviceToken": device_token.clone(),
        "deviceName": "iPhone v2",
        "notificationFilter": "visible_all"
    });

    let response2 = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request2)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response2.status(), reqwest::StatusCode::OK);
}

// ============================================================================
// POST /api/v1/notifications/unregister-device Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn device_token_unregister_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;
    let device_token = generate_device_token();

    // First register the device
    let register_request = json!({
        "deviceToken": device_token.clone(),
        "notificationFilter": "silent"
    });

    let register_response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&register_request)
        .send()
        .await
        .expect("Failed to send register request");

    assert_eq!(register_response.status(), reqwest::StatusCode::OK);

    // Now unregister
    let unregister_request = json!({
        "deviceToken": device_token
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/unregister-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&unregister_request)
        .send()
        .await
        .expect("Failed to send unregister request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["message"], "Device token unregistered");
}

#[tokio::test]
#[serial]
async fn device_token_unregister_not_found() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    // Try to unregister non-existent token
    let request = json!({
        "deviceToken": generate_device_token()
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/unregister-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn device_token_unregister_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let request = json!({
        "deviceToken": generate_device_token()
    });

    let response = client
        .post(format!(
            "{}/api/v1/notifications/unregister-device",
            app.notification_url()
        ))
        // No Authorization header
        .json(&request)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ============================================================================
// PUT /api/v1/notifications/preferences Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn notification_preferences_update_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;
    let device_token = generate_device_token();

    // First register the device
    let register_request = json!({
        "deviceToken": device_token.clone(),
        "notificationFilter": "silent"
    });

    let register_response = client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&register_request)
        .send()
        .await
        .expect("Failed to send register request");

    assert_eq!(register_response.status(), reqwest::StatusCode::OK);

    // Update preferences
    let update_request = json!({
        "deviceToken": device_token,
        "notificationFilter": "visible_dm",
        "enabled": true
    });

    let response = client
        .put(format!(
            "{}/api/v1/notifications/preferences",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&update_request)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["message"], "Preferences updated");
}

#[tokio::test]
#[serial]
async fn notification_preferences_disable_notifications() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;
    let device_token = generate_device_token();

    // First register the device
    let register_request = json!({
        "deviceToken": device_token.clone(),
        "notificationFilter": "visible_all"
    });

    client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&register_request)
        .send()
        .await
        .expect("Failed to send register request");

    // Disable notifications
    let update_request = json!({
        "deviceToken": device_token,
        "notificationFilter": "silent",
        "enabled": false
    });

    let response = client
        .put(format!(
            "{}/api/v1/notifications/preferences",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&update_request)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn notification_preferences_invalid_filter() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;
    let device_token = generate_device_token();

    // First register the device
    let register_request = json!({
        "deviceToken": device_token.clone(),
        "notificationFilter": "silent"
    });

    client
        .post(format!(
            "{}/api/v1/notifications/register-device",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&register_request)
        .send()
        .await
        .expect("Failed to send register request");

    // Try to update with invalid filter
    let update_request = json!({
        "deviceToken": device_token,
        "notificationFilter": "not_a_valid_filter",
        "enabled": true
    });

    let response = client
        .put(format!(
            "{}/api/v1/notifications/preferences",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&update_request)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn notification_preferences_device_not_found() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    // Try to update preferences for non-existent device
    let update_request = json!({
        "deviceToken": generate_device_token(),
        "notificationFilter": "visible_all",
        "enabled": true
    });

    let response = client
        .put(format!(
            "{}/api/v1/notifications/preferences",
            app.notification_url()
        ))
        .header("X-User-Id", &user_id)
        .json(&update_request)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial]
async fn notification_preferences_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let update_request = json!({
        "deviceToken": generate_device_token(),
        "notificationFilter": "visible_all",
        "enabled": true
    });

    let response = client
        .put(format!(
            "{}/api/v1/notifications/preferences",
            app.notification_url()
        ))
        // No Authorization header
        .json(&update_request)
        .send()
        .await
        .expect("Failed to send update request");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ============================================================================
// All Valid Filters Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn device_token_register_all_valid_filters() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let user_id = register_and_get_user_id(&client, &app.auth_url()).await;

    let valid_filters = [
        "silent",
        "visible_all",
        "visible_dm",
        "visible_mentions",
        "visible_contacts",
    ];

    for filter in valid_filters {
        let device_token = generate_device_token();
        let request = json!({
            "deviceToken": device_token,
            "notificationFilter": filter
        });

        let response = client
            .post(format!(
                "{}/api/v1/notifications/register-device",
                app.notification_url()
            ))
            .header("X-User-Id", &user_id)
            .json(&request)
            .send()
            .await
            .expect("Failed to send request");

        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "Filter '{}' should be valid",
            filter
        );
    }
}
