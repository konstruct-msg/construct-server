// ============================================================================
// REST API Account Endpoints Tests - Device-Based Architecture
// ============================================================================
//
// Tests for account management endpoints:
// - GET /api/v1/account - Get account information
// - Device-signed account deletion (tested in separate file)
//
// ============================================================================

#![allow(dead_code)]
#![allow(clippy::needless_borrows_for_generic_args)]

use serial_test::serial;
use uuid::Uuid;

mod test_utils;
use test_utils::{cleanup_rate_limits, register_user_passwordless, spawn_app};

// Helper function to generate a valid test username
fn generate_test_username(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        &Uuid::new_v4().to_string().replace('-', "_")[0..8]
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

// ============================================================================
// GET /api/v1/account Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_account_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user (device-based)
    let username = generate_test_username("testuser");
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Get account information (using X-User-Id header for microservices behind Gateway)
    let response = client
        .get(format!("http://{}/api/v1/account", app.user_address))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct AccountInfo {
        user_id: String,
        username: Option<String>,
        created_at: Option<String>,
    }

    let account: AccountInfo = response.json().await.unwrap();
    assert_eq!(account.user_id, user_id);
    assert_eq!(account.username.as_deref(), Some(username.as_str()));
}

#[tokio::test]
#[serial]
async fn test_get_account_requires_auth() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to get account without authentication
    let response = client
        .get(format!("http://{}/api/v1/account", app.user_address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_get_account_invalid_token() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Try to get account with invalid token
    let response = client
        .get(format!("http://{}/api/v1/account", app.user_address))
        .header("Authorization", "Bearer invalid_token_here")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_get_account_without_username() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register a user WITHOUT username (privacy-focused)
    let (user_id, _access_token) =
        register_user_passwordless(&client, &app.auth_address, None).await;

    // Get account information (using X-User-Id header for microservices behind Gateway)
    let response = client
        .get(format!("http://{}/api/v1/account", app.user_address))
        .header("X-User-Id", &user_id)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct AccountInfo {
        user_id: String,
        username: Option<String>,
    }

    let account: AccountInfo = response.json().await.unwrap();
    assert_eq!(account.user_id, user_id);
    // Username should be None or empty for privacy-focused users
    assert!(account.username.is_none() || account.username == Some("".to_string()));
}
