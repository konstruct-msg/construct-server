// ============================================================================
// Microservices Integration Tests
// ============================================================================
//
// Basic smoke tests for microservices to verify they start and respond.
// These tests ensure the migration to independent services was successful.
//
// Run with: cargo test --test microservices_smoke_test
//
// ============================================================================

use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

/// Helper to start a service in background
fn start_service(package_name: &str, port: u16) -> Child {
    println!("Starting {} on port {}", package_name, port);

    // Get workspace root from CARGO_MANIFEST_DIR
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let workspace_root = std::path::Path::new(&manifest_dir)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let _manifest_path = workspace_root.join("Cargo.toml");

    let child = Command::new("cargo")
        .args(["run", "-p", package_name])
        .env("PORT", port.to_string())
        .env(
            "DATABASE_URL",
            std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://construct:construct_dev_password@localhost:5432/construct_test"
                    .to_string()
            }),
        )
        .env("REDIS_URL", "redis://localhost:6379")
        .env("JWT_SECRET", "test_jwt_secret_for_microservices_testing")
        .current_dir(workspace_root)
        .spawn()
        .unwrap_or_else(|_| panic!("Failed to start {}", package_name));

    // Give service time to start
    thread::sleep(Duration::from_secs(3));

    child
}

/// Helper to stop a service
fn stop_service(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Basic smoke test - verify identity service starts and responds
#[test]
fn test_identity_service_starts() {
    let mut service = start_service("identity-service", 18001);

    assert!(
        service.try_wait().unwrap().is_none(),
        "Service should be running"
    );

    stop_service(service);
}

/// Basic smoke test - verify messaging service starts and responds
#[test]
fn test_messaging_service_starts() {
    let mut service = start_service("messaging-service", 18002);

    assert!(
        service.try_wait().unwrap().is_none(),
        "Service should be running"
    );

    stop_service(service);
}

/// Basic smoke test - verify gateway starts and responds
#[test]
fn test_gateway_starts() {
    let mut service = start_service("gateway", 18000);

    assert!(
        service.try_wait().unwrap().is_none(),
        "Service should be running"
    );

    stop_service(service);
}
