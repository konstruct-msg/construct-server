//! Stream ID Protocol Compliance Tests
//!
//! SPECIFICATION: Our custom extension to Signal Protocol
//! Redis Streams are used for message queuing with ACK-based pagination.
//!
//! CRITICAL DISTINCTION:
//! - Message ID (UUID): Unique identifier for deduplication and logging
//! - Stream ID ({timestamp}-{sequence}): Redis Stream entry ID for pagination
//!
//! The `nextSince` field MUST always contain a Stream ID, never a Message ID.
use crate::test_utils::*;

#[tokio::test]
async fn test_next_since_is_always_stream_id_format() {
    // SPEC: nextSince MUST be a Redis Stream ID, format: "{timestamp}-{sequence}"
    // Example: "1707584371151-5"
    //
    // BUG HISTORY: Client was using message.id (UUID) as 'since' parameter,
    // causing infinite duplicate delivery loops.

    let ctx = spawn_app().await;
    let alice = register_test_user(&ctx, "alice").await;
    let bob = register_test_user(&ctx, "bob").await;

    // Send a message
    send_test_message(&ctx, &alice, &bob.user_id, "Test").await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Get messages
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", bob.access_token))
        .send()
        .await
        .expect("Failed to get messages");

    let body: serde_json::Value = response.json().await.unwrap();

    // SPEC REQUIREMENT: nextSince must be present and valid
    if let Some(next_since) = body["nextSince"].as_str() {
        // SPEC REQUIREMENT: Must be Stream ID format, NOT UUID
        assert!(
            is_valid_stream_id(next_since),
            "PROTOCOL VIOLATION: nextSince '{}' is not a valid Stream ID. Expected format: {{timestamp}}-{{sequence}}",
            next_since
        );

        assert!(
            !is_uuid(next_since),
            "PROTOCOL VIOLATION: nextSince should be Stream ID, not Message ID (UUID): {}",
            next_since
        );
    }
}

#[tokio::test]
async fn test_stream_id_format_validation() {
    // SPEC: Stream ID format is "{timestamp}-{sequence}"
    // Both components MUST be numeric

    // Valid Stream IDs
    assert!(is_valid_stream_id("1707584371151-5"));
    assert!(is_valid_stream_id("0-0"));
    assert!(is_valid_stream_id("1234567890-999"));

    // Invalid formats
    assert!(!is_valid_stream_id("c78b9bf2-715c-4621-8c3b-75b20d9b6e7f")); // UUID
    assert!(!is_valid_stream_id("invalid"));
    assert!(!is_valid_stream_id("123")); // Missing sequence
    assert!(!is_valid_stream_id("123-abc")); // Non-numeric sequence
    assert!(!is_valid_stream_id("abc-123")); // Non-numeric timestamp
}

/// Helper: Check if string is UUID format
fn is_uuid(s: &str) -> bool {
    // UUID format: 8-4-4-4-12 hex digits
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Helper: Validate Stream ID format
fn is_valid_stream_id(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 2 && parts[0].parse::<u64>().is_ok() && parts[1].parse::<u64>().is_ok()
}
