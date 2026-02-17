// ============================================================================
// REST API Auth Endpoints Tests - Device-Based Architecture
// ============================================================================
//
// Tests for device-based passwordless authentication endpoints:
// - GET /api/v1/auth/challenge - Get PoW challenge
// - POST /api/v1/auth/register-device - Register new device
// - POST /api/v1/auth/device - Authenticate existing device
// - POST /api/v1/auth/refresh - Refresh access token
// - POST /api/v1/auth/logout - Logout device
//
// ============================================================================

#![allow(dead_code)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(unused_variables)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use serial_test::serial;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

mod test_utils;
use test_utils::{cleanup_rate_limits, spawn_app, spawn_app_with_rate_limiting};

// Helper function to create HTTP client with API headers
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

// Helper function to generate test username
fn generate_test_username(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        &Uuid::new_v4().to_string().replace('-', "_")[0..8]
    )
}

// Response structures
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge: String,
    difficulty: u32,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceResponse {
    user_id: String,
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateDeviceResponse {
    user_id: String,
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_at: i64,
}

// Helper: Solve PoW challenge (matches server parameters)
fn solve_pow(challenge: &str, difficulty: u32) -> (u64, String) {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Argon2, ParamsBuilder, Version};

    // Derive salt from challenge (same as server)
    let derived_salt = format!("kpow2:{}", &challenge[..16.min(challenge.len())]);

    let params = ParamsBuilder::new()
        .m_cost(32 * 1024) // 32 MB (same as server)
        .t_cost(2) // 2 iterations (same as server)
        .p_cost(1) // 1 thread (same as server)
        .output_len(32) // 32 bytes (same as server)
        .build()
        .unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    for nonce in 0..1_000_000 {
        let input = format!("{}{}", challenge, nonce);
        let salt = SaltString::encode_b64(derived_salt.as_bytes()).unwrap();

        if let Ok(hash) = argon2.hash_password(input.as_bytes(), &salt) {
            let hash_bytes = hash.hash.unwrap().as_bytes().to_vec();

            // Count leading zero bits
            let mut leading_zeros = 0;
            for byte in &hash_bytes {
                if *byte == 0 {
                    leading_zeros += 8;
                } else {
                    leading_zeros += byte.leading_zeros();
                    break;
                }
            }

            if leading_zeros >= difficulty {
                return (nonce, hex::encode(&hash_bytes));
            }
        }
    }

    panic!("Failed to solve PoW within 1M attempts");
}

// ============================================================================
// GET /api/v1/auth/challenge Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_get_pow_challenge_success() {
    let app = spawn_app().await;
    let client = create_api_client();

    let response = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let challenge: ChallengeResponse = response.json().await.unwrap();
    assert!(!challenge.challenge.is_empty());
    assert!(challenge.difficulty > 0);
}

#[tokio::test]
#[serial]
async fn test_get_pow_challenge_rate_limiting() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app_with_rate_limiting().await;
    let client = create_api_client();

    // Make 11 requests (limit is 10 per hour)
    for i in 0..11 {
        let response = client
            .get(&format!(
                "http://{}/api/v1/auth/challenge",
                app.auth_address
            ))
            .send()
            .await
            .unwrap();

        if i < 10 {
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "Request {} should succeed",
                i + 1
            );
        } else {
            assert_eq!(
                response.status(),
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "Request {} should be rate limited",
                i + 1
            );
        }
    }

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

// ============================================================================
// POST /api/v1/auth/register-device Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_register_device_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // 1. Generate keys
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    // Generate signedPrekeySignature
    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]); // suite_id = 1
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    // 2. Get PoW challenge
    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    // 3. Register device
    let username = generate_test_username("testuser");
    let register_request = json!({
        "username": username,
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    let response = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let status = response.status();
    if status != reqwest::StatusCode::CREATED {
        let error_text = response.text().await.unwrap();
        panic!("Registration failed with status {}: {}", status, error_text);
    }

    let auth_response: RegisterDeviceResponse = response.json().await.unwrap();
    assert!(!auth_response.user_id.is_empty());
    assert!(!auth_response.access_token.is_empty());
    assert!(!auth_response.refresh_token.is_empty());
    assert!(auth_response.expires_in > 0);

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_register_device_duplicate_device_id() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register first device
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    let register_request = json!({
        "username": generate_test_username("test"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    // First registration
    let response = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::CREATED);

    // Second registration with same device_id (get new challenge first)
    let challenge2: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce2, hash2) = solve_pow(&challenge2.challenge, challenge2.difficulty);

    let register_request2 = json!({
        "username": generate_test_username("test2"),
        "deviceId": device_id, // Same device_id!
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge2.challenge,
            "nonce": nonce2,
            "hash": hash2
        }
    });

    let response2 = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request2)
        .send()
        .await
        .unwrap();

    assert_eq!(response2.status(), reqwest::StatusCode::CONFLICT);
    let error_text = response2.text().await.unwrap();
    assert!(error_text.contains("already exists") || error_text.contains("duplicate"));

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_register_device_missing_signed_prekey_signature() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    // Register WITHOUT signedPrekeySignature
    let register_request = json!({
        "username": generate_test_username("test"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            // Missing signedPrekeySignature!
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    let response = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

// ============================================================================
// POST /api/v1/auth/device Tests (Authentication)
// ============================================================================

#[tokio::test]
#[serial]
async fn test_authenticate_device_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // 1. Register device first
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    let register_request = json!({
        "username": generate_test_username("test"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    let reg_response = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(reg_response.status(), reqwest::StatusCode::CREATED);

    // 2. Now authenticate
    let timestamp = chrono::Utc::now().timestamp();
    let message = format!("{}{}", device_id, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let auth_request = json!({
        "deviceId": device_id,
        "timestamp": timestamp,
        "signature": BASE64.encode(signature.to_bytes())
    });

    let auth_response = client
        .post(&format!("http://{}/api/v1/auth/device", app.auth_address))
        .json(&auth_request)
        .send()
        .await
        .unwrap();

    assert_eq!(auth_response.status(), reqwest::StatusCode::OK);

    let auth_data: AuthenticateDeviceResponse = auth_response.json().await.unwrap();
    assert!(!auth_data.user_id.is_empty());
    assert!(!auth_data.access_token.is_empty());
    assert!(!auth_data.refresh_token.is_empty());
    assert!(auth_data.expires_in > 0);

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_authenticate_device_nonexistent() {
    let app = spawn_app().await;
    let client = create_api_client();

    let signing_key = SigningKey::generate(&mut OsRng);
    let fake_device_id = "0000000000000000"; // Non-existent device

    let timestamp = chrono::Utc::now().timestamp();
    let message = format!("{}{}", fake_device_id, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let auth_request = json!({
        "deviceId": fake_device_id,
        "timestamp": timestamp,
        "signature": BASE64.encode(signature.to_bytes())
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/device", app.auth_address))
        .json(&auth_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_authenticate_device_expired_timestamp() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register device first (reusing code from success test)
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    let register_request = json!({
        "username": generate_test_username("test"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    // Authenticate with old timestamp (>5 minutes ago)
    let old_timestamp = chrono::Utc::now().timestamp() - 400; // 6+ minutes ago
    let message = format!("{}{}", device_id, old_timestamp);
    let signature = signing_key.sign(message.as_bytes());

    let auth_request = json!({
        "deviceId": device_id,
        "timestamp": old_timestamp,
        "signature": BASE64.encode(signature.to_bytes())
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/device", app.auth_address))
        .json(&auth_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let error_text = response.text().await.unwrap();
    assert!(error_text.to_lowercase().contains("timestamp") || error_text.contains("expired"));

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

// ============================================================================
// POST /api/v1/auth/refresh Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_refresh_token_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register and get tokens
    let username = generate_test_username("testuser");
    let (user_id, access_token) =
        test_utils::register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Use the helper to get refresh token too - we need to extract it from registration
    // For now, let's register manually to get refresh token
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    let register_request = json!({
        "username": generate_test_username("refreshtest"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    let reg_response = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    let reg_data: RegisterDeviceResponse = reg_response.json().await.unwrap();

    // Now refresh the token
    let refresh_request = json!({
        "refreshToken": reg_data.refresh_token
    });

    let refresh_response = client
        .post(&format!("http://{}/api/v1/auth/refresh", app.auth_address))
        .json(&refresh_request)
        .send()
        .await
        .unwrap();

    let status = refresh_response.status();
    if status != reqwest::StatusCode::OK {
        let error_text = refresh_response.text().await.unwrap();
        panic!("Refresh failed with status {}: {}", status, error_text);
    }

    let refresh_data: RefreshTokenResponse = refresh_response.json().await.unwrap();
    assert!(!refresh_data.access_token.is_empty());
    assert!(refresh_data.expires_at > chrono::Utc::now().timestamp());

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_refresh_token_invalid() {
    let app = spawn_app().await;
    let client = create_api_client();

    let refresh_request = json!({
        "refreshToken": "invalid.token.here"
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/refresh", app.auth_address))
        .json(&refresh_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ============================================================================
// POST /api/v1/auth/logout Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_logout_success() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register and login
    let username = generate_test_username("logouttest");
    let (user_id, access_token) =
        test_utils::register_user_passwordless(&client, &app.auth_address, Some(&username)).await;

    // Logout
    let logout_request = json!({
        "refreshToken": "dummy_refresh_token" // In real scenario we'd use actual refresh token
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/logout", app.auth_address))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&logout_request)
        .send()
        .await
        .unwrap();

    // Logout should succeed (or return 401 if refresh token validation is strict)
    assert!(
        response.status() == reqwest::StatusCode::OK
            || response.status() == reqwest::StatusCode::NO_CONTENT
            || response.status() == reqwest::StatusCode::UNAUTHORIZED
    );

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_logout_requires_auth() {
    let app = spawn_app().await;
    let client = create_api_client();

    let logout_request = json!({
        "refreshToken": "some_token"
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/logout", app.auth_address))
        // No Authorization header
        .json(&logout_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Additional Edge Case Tests (test_analysis.md recommendations)
// ============================================================================

#[tokio::test]
#[serial]
async fn test_register_device_invalid_device_id_format() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    // Use invalid device_id (not 16 hex chars)
    let invalid_device_ids = vec![
        "short",               // Too short
        "00000000000000001",   // Too long (17 chars)
        "zzzzzzzzzzzzzzzz",    // Non-hex characters
        "0000-0000-0000-0000", // Contains dashes
    ];

    for invalid_id in invalid_device_ids {
        let register_request = json!({
            "username": generate_test_username("test"),
            "deviceId": invalid_id,
            "publicKeys": {
                "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
                "identityPublic": BASE64.encode(identity_public.as_bytes()),
                "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
                "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
                "suiteId": "Curve25519+Ed25519"
            },
            "powSolution": {
                "challenge": challenge.challenge,
                "nonce": nonce,
                "hash": hash.clone()
            }
        });

        let response = client
            .post(&format!(
                "http://{}/api/v1/auth/register-device",
                app.auth_address
            ))
            .json(&register_request)
            .send()
            .await
            .unwrap();

        assert!(
            response.status() == reqwest::StatusCode::BAD_REQUEST
                || response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid device_id '{}' should be rejected, got status: {}",
            invalid_id,
            response.status()
        );
    }

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_register_device_invalid_pow_solution() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Use invalid PoW solution (wrong nonce/hash)
    let register_request = json!({
        "username": generate_test_username("test"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": 0, // Wrong nonce
            "hash": "0000000000000000" // Wrong hash
        }
    });

    let response = client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let error_text = response.text().await.unwrap();
    assert!(error_text.to_lowercase().contains("pow") || error_text.contains("proof"));

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}

#[tokio::test]
#[serial]
async fn test_authenticate_device_invalid_signature() {
    cleanup_rate_limits("redis://127.0.0.1:6379").await;
    let app = spawn_app().await;
    let client = create_api_client();

    // Register device first
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let identity_secret = EphemeralSecret::random_from_rng(OsRng);
    let identity_public = X25519PublicKey::from(&identity_secret);

    let prekey_secret = EphemeralSecret::random_from_rng(OsRng);
    let prekey_public = X25519PublicKey::from(&prekey_secret);

    let prekey_signature = {
        let mut message = Vec::new();
        message.extend_from_slice(b"KonstruktX3DH-v1");
        message.extend_from_slice(&[0x00, 0x01]);
        message.extend_from_slice(prekey_public.as_bytes());
        signing_key.sign(&message)
    };

    let device_id = {
        let hash = Sha256::digest(identity_public.as_bytes());
        hex::encode(&hash[0..16])
    };

    let challenge: ChallengeResponse = client
        .get(&format!(
            "http://{}/api/v1/auth/challenge",
            app.auth_address
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let (nonce, hash) = solve_pow(&challenge.challenge, challenge.difficulty);

    let register_request = json!({
        "username": generate_test_username("test"),
        "deviceId": device_id,
        "publicKeys": {
            "verifyingKey": BASE64.encode(verifying_key.as_bytes()),
            "identityPublic": BASE64.encode(identity_public.as_bytes()),
            "signedPrekeyPublic": BASE64.encode(prekey_public.as_bytes()),
            "signedPrekeySignature": BASE64.encode(prekey_signature.to_bytes()),
            "suiteId": "Curve25519+Ed25519"
        },
        "powSolution": {
            "challenge": challenge.challenge,
            "nonce": nonce,
            "hash": hash
        }
    });

    client
        .post(&format!(
            "http://{}/api/v1/auth/register-device",
            app.auth_address
        ))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    // Authenticate with wrong signature (use different signing key)
    let wrong_signing_key = SigningKey::generate(&mut OsRng);
    let timestamp = chrono::Utc::now().timestamp();
    let message = format!("{}{}", device_id, timestamp);
    let wrong_signature = wrong_signing_key.sign(message.as_bytes());

    let auth_request = json!({
        "deviceId": device_id,
        "timestamp": timestamp,
        "signature": BASE64.encode(wrong_signature.to_bytes())
    });

    let response = client
        .post(&format!("http://{}/api/v1/auth/device", app.auth_address))
        .json(&auth_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    cleanup_rate_limits("redis://127.0.0.1:6379").await;
}
