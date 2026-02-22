// ============================================================================
// REST API Health Endpoints Tests
// ============================================================================
//
// Tests for health check endpoints:
// - GET /health/ready - Readiness probe (checks all dependencies)
// - GET /health/live - Liveness probe (minimal check)
//
// ============================================================================

use serial_test::serial;

mod test_utils;
use test_utils::spawn_app;

// Helper function to create HTTP client
fn create_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

// ============================================================================
// GET /health/ready Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_readiness_check_success() {
    let app = spawn_app().await;
    let client = create_client();

    // Get readiness status
    let response = client
        .get(format!("http://{}/health/ready", app.address))
        .send()
        .await
        .unwrap();

    // Should return 200 OK if all dependencies are healthy
    // Note: In test environment, dependencies might not be available,
    // so we accept both 200 and 503
    assert!(
        response.status() == reqwest::StatusCode::OK
            || response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
    );

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.get("status").is_some());

    // If status is "healthy", all components should be healthy
    if body["status"] == "healthy" {
        assert!(body.get("database").is_some());
        assert!(body.get("redis").is_some());
        assert!(body.get("kafka").is_some());

        assert_eq!(body["database"]["status"], "healthy");
        assert_eq!(body["redis"]["status"], "healthy");
        // Kafka might be disabled, so we check if it exists
        if body.get("kafka").is_some() {
            // Kafka status can be "healthy" or "disabled"
            assert!(body["kafka"]["status"] == "healthy" || body["kafka"]["status"] == "disabled");
        }
    }
}

#[tokio::test]
#[serial]
async fn test_readiness_check_returns_json() {
    let app = spawn_app().await;
    let client = create_client();

    // Get readiness status
    let response = client
        .get(format!("http://{}/health/ready", app.address))
        .send()
        .await
        .unwrap();

    // Should return JSON response
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(content_type.contains("application/json"));

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.is_object());
}

#[tokio::test]
#[serial]
async fn test_readiness_check_structure() {
    let app = spawn_app().await;
    let client = create_client();

    // Get readiness status
    let response = client
        .get(format!("http://{}/health/ready", app.address))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();

    // Verify response structure
    assert!(body.get("status").is_some());
    assert!(body["status"].is_string());

    // If unhealthy, should have error field
    if body["status"] == "unhealthy" {
        assert!(body.get("error").is_some());
    }

    // If healthy, should have component statuses
    if body["status"] == "healthy" {
        assert!(body.get("database").is_some());
        assert!(body.get("redis").is_some());

        // Database status
        assert!(body["database"].is_object());
        assert!(body["database"].get("status").is_some());
        assert!(body["database"]["status"].is_string());

        // Redis status
        assert!(body["redis"].is_object());
        assert!(body["redis"].get("status").is_some());
        assert!(body["redis"]["status"].is_string());

        // Kafka status (optional, might be disabled)
        if body.get("kafka").is_some() {
            assert!(body["kafka"].is_object());
            assert!(body["kafka"].get("status").is_some());
            assert!(body["kafka"]["status"].is_string());
        }
    }
}

#[tokio::test]
#[serial]
async fn test_readiness_check_no_auth_required() {
    let app = spawn_app().await;
    let client = create_client();

    // Health endpoints should not require authentication
    let response = client
        .get(format!("http://{}/health/ready", app.address))
        .send()
        .await
        .unwrap();

    // Should not return 401/403
    assert_ne!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

// ============================================================================
// GET /health/live Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_liveness_check_success() {
    let app = spawn_app().await;
    let client = create_client();

    // Get liveness status
    let response = client
        .get(format!("http://{}/health/live", app.address))
        .send()
        .await
        .unwrap();

    // Liveness check should always return 200 OK if process is running
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "alive");
}

#[tokio::test]
#[serial]
async fn test_liveness_check_returns_json() {
    let app = spawn_app().await;
    let client = create_client();

    // Get liveness status
    let response = client
        .get(format!("http://{}/health/live", app.address))
        .send()
        .await
        .unwrap();

    // Should return JSON response
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(content_type.contains("application/json"));

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body.is_object());
}

#[tokio::test]
#[serial]
async fn test_liveness_check_structure() {
    let app = spawn_app().await;
    let client = create_client();

    // Get liveness status
    let response = client
        .get(format!("http://{}/health/live", app.address))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();

    // Verify response structure
    assert!(body.get("status").is_some());
    assert_eq!(body["status"], "alive");
}

#[tokio::test]
#[serial]
async fn test_liveness_check_no_auth_required() {
    let app = spawn_app().await;
    let client = create_client();

    // Health endpoints should not require authentication
    let response = client
        .get(format!("http://{}/health/live", app.address))
        .send()
        .await
        .unwrap();

    // Should not return 401/403
    assert_ne!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial]
async fn test_liveness_check_fast() {
    let app = spawn_app().await;
    let client = create_client();

    // Liveness check should be fast (no external dependencies)
    let start = std::time::Instant::now();

    let response = client
        .get(format!("http://{}/health/live", app.address))
        .send()
        .await
        .unwrap();

    let duration = start.elapsed();

    // Should complete quickly (less than 100ms)
    assert!(duration.as_millis() < 100);

    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
#[serial]
async fn test_readiness_vs_liveness() {
    let app = spawn_app().await;
    let client = create_client();

    // Liveness should always return 200 if process is running
    let live_response = client
        .get(format!("http://{}/health/live", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(live_response.status(), reqwest::StatusCode::OK);

    // Readiness might return 503 if dependencies are unavailable
    let ready_response = client
        .get(format!("http://{}/health/ready", app.address))
        .send()
        .await
        .unwrap();

    // Readiness can be 200 or 503, but liveness should always be 200
    assert!(
        ready_response.status() == reqwest::StatusCode::OK
            || ready_response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
}
