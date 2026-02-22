//! Next Since Bug Test
//!
//! Tests the critical bug where server returns `nextSince: null` when no messages,
//! causing clients to get stuck in infinite polling loop.
//!
//! ## The Bug
//!
//! **Expected:**
//! ```json
//! GET /api/v1/messages?since=1771079450941-0
//! → { "messages": [], "nextSince": "1771079450941-0", "hasMore": false }
//! ```
//!
//! **Actual (buggy):**
//! ```json
//! GET /api/v1/messages?since=1771079450941-0
//! → { "messages": [], "nextSince": null, "hasMore": false }
//! ```
//!
//! **Impact:** Client keeps using same `since` value forever, never receives new messages.

mod test_utils;

use test_utils::{register_test_user, spawn_app};

#[tokio::test]
async fn test_next_since_returned_when_no_messages() {
    let ctx = spawn_app().await;

    // Register a user
    let user = register_test_user(&ctx, "alice_nextsince").await;

    println!("✅ User registered: {}", user.user_id);

    // Make GET /messages request with valid since parameter
    let client = reqwest::Client::new();
    let since_value = "1771079450941-0"; // Valid Stream ID format

    let response = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .query(&[("since", since_value), ("timeout", "1")]) // 1 second timeout
        .send()
        .await
        .expect("Failed to get messages");

    assert_eq!(response.status(), 200, "GET /messages should return 200");

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");

    println!(
        "📦 Response: {}",
        serde_json::to_string_pretty(&body).unwrap()
    );

    // Check messages array (should be empty)
    let messages = body["messages"]
        .as_array()
        .expect("messages should be array");
    assert!(messages.is_empty(), "Should have no messages");

    // ✅ CRITICAL: Check nextSince field
    let next_since = &body["nextSince"];

    assert!(
        !next_since.is_null(),
        "❌ BUG DETECTED: nextSince is null when no messages!\n\
         This causes infinite polling loop.\n\
         Expected: nextSince=\"{}\" (same as 'since' parameter)\n\
         Got: nextSince=null",
        since_value
    );

    let next_since_str = next_since
        .as_str()
        .expect("nextSince should be string when present");

    assert_eq!(
        next_since_str, since_value,
        "When no messages, nextSince should echo back the 'since' parameter.\n\
         This allows client to keep polling from same position."
    );

    println!("✅ PASS: nextSince correctly returned when no messages");
    println!("   nextSince: \"{}\"", next_since_str);
}

#[tokio::test]
async fn test_next_since_returned_after_timeout() {
    let ctx = spawn_app().await;

    let user = register_test_user(&ctx, "bob_timeout").await;

    println!("✅ User registered: {}", user.user_id);

    // Poll with timeout (no messages will arrive)
    let client = reqwest::Client::new();
    let since_value = "1234567890123-0";

    let start = std::time::Instant::now();
    let response = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .query(&[("since", since_value), ("timeout", "2")]) // 2 second timeout
        .send()
        .await
        .expect("Failed to get messages");

    let elapsed = start.elapsed();
    println!("⏱️  Request took: {:?}", elapsed);

    assert!(
        elapsed.as_secs() >= 1,
        "Should wait at least 1 second (long polling)"
    );

    let body: serde_json::Value = response.json().await.unwrap();

    // After timeout with no messages, nextSince should still be present
    let next_since = &body["nextSince"];

    assert!(
        !next_since.is_null(),
        "❌ BUG: nextSince is null after timeout!\n\
         Even when long polling times out with no messages,\n\
         nextSince should be present to allow client to continue polling."
    );

    assert_eq!(
        next_since.as_str().unwrap(),
        since_value,
        "nextSince should match original since parameter after timeout"
    );

    println!("✅ PASS: nextSince correctly returned after timeout");
}

#[tokio::test]
async fn test_next_since_with_invalid_since_parameter() {
    let ctx = spawn_app().await;

    let user = register_test_user(&ctx, "charlie_invalid").await;

    // Send INVALID since parameter (not a Stream ID)
    let client = reqwest::Client::new();
    let invalid_since = "not-a-valid-stream-id-format";

    let response = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .query(&[("since", invalid_since), ("timeout", "1")])
        .send()
        .await
        .expect("Failed to get messages");

    let body: serde_json::Value = response.json().await.unwrap();

    println!(
        "📦 Response with invalid since: {}",
        serde_json::to_string_pretty(&body).unwrap()
    );

    let next_since = &body["nextSince"];

    // Current behavior: Returns null for invalid since
    // This is actually OK - server rejects invalid input
    // Client should start from "0-0" on next request

    if next_since.is_null() {
        println!("⚠️  Server returns null for invalid since parameter (acceptable behavior)");
        println!("   Client should restart from \"0-0\" or omit since parameter");
    } else {
        println!("✅ Server still returns nextSince even for invalid input");
        println!("   nextSince: \"{}\"", next_since.as_str().unwrap());
    }

    // This test just documents the behavior - both approaches are valid
    // as long as VALID since parameters always get nextSince back
}

#[tokio::test]
async fn test_next_since_first_request_no_since_parameter() {
    let ctx = spawn_app().await;

    let user = register_test_user(&ctx, "diana_first").await;

    // First request - no 'since' parameter at all
    let client = reqwest::Client::new();

    let response = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", user.access_token))
        .query(&[("timeout", "1")])
        .send()
        .await
        .expect("Failed to get messages");

    let body: serde_json::Value = response.json().await.unwrap();

    println!(
        "📦 First request (no since): {}",
        serde_json::to_string_pretty(&body).unwrap()
    );

    let next_since = &body["nextSince"];

    // For first request, nextSince might be:
    // - "0-0" (start of stream)
    // - null (no position yet)
    // - current timestamp (latest position)

    if next_since.is_null() {
        println!("⚠️  Server returns null for first request (potential issue)");
        println!("   Client should use \"0-0\" on next request");
    } else {
        println!("✅ Server returns nextSince even for first request");
        println!("   nextSince: \"{}\"", next_since.as_str().unwrap());
    }

    // Document the behavior for first request
}
