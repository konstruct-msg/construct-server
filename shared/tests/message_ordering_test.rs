//! Message Ordering Tests
//!
//! Validates that server returns messages sorted by messageNumber,
//! not by arrival order (stream_id), to ensure proper Double Ratchet
//! session initialization.
#![allow(clippy::needless_borrows_for_generic_args)]
//!
//! Critical Bug: Without sorting, message #8 might arrive before #0,
//! causing InvalidCiphertext when client tries to initialize session.

mod test_utils;

use base64::{Engine as _, engine::general_purpose};
use reqwest::StatusCode;
use serde_json::json;
use test_utils::{register_test_user, spawn_app};

/// Helper: Send message with specific messageNumber
async fn send_message_with_number(
    ctx: &test_utils::TestApp,
    sender: &test_utils::TestUser,
    recipient_id: &str,
    message_number: u32,
    content: &str,
) -> reqwest::Result<reqwest::Response> {
    let client = reqwest::Client::new();

    // Create properly formatted ciphertext for suite 1:
    // nonce (12 bytes) + encrypted_content + tag (16 bytes)
    // Minimum: 12 + 0 + 16 = 28 bytes
    let mut dummy_ciphertext = vec![0u8; 12]; // nonce
    dummy_ciphertext.extend_from_slice(content.as_bytes()); // plaintext (encrypted in real scenario)
    dummy_ciphertext.extend_from_slice(&[0u8; 16]); // tag

    client
        .post(&format!("http://{}/api/v1/messages", ctx.messaging_address))
        .bearer_auth(&sender.access_token)
        .header("x-user-id", &sender.user_id) // Add X-User-Id for TrustedUser extractor
        .json(&json!({
            "recipientId": recipient_id,
            "suiteId": 1,
            "ephemeralPublicKey": general_purpose::STANDARD.encode([0u8; 32]),
            "messageNumber": message_number,
            "previousChainLength": 0,
            "ciphertext": general_purpose::STANDARD.encode(&dummy_ciphertext)
        }))
        .send()
        .await
}

/// Test that messages are returned in messageNumber order, not arrival order
#[tokio::test]
async fn test_messages_sorted_by_message_number() {
    let ctx = spawn_app().await;

    // Register two users
    let alice = register_test_user(&ctx, "alice_ordering").await;
    let bob = register_test_user(&ctx, "bob_ordering").await;

    println!("✅ Alice and Bob registered");

    // Alice sends 5 messages to Bob with DECREASING message numbers
    // to simulate out-of-order arrival
    let messages_to_send = vec![
        (4, "Message 4"),
        (2, "Message 2"),
        (0, "Message 0 - SESSION INIT"), // Critical: must be first for decryption
        (3, "Message 3"),
        (1, "Message 1"),
    ];

    for (msg_num, content) in messages_to_send {
        println!("📤 Attempting to send message #{msg_num}...");
        println!(
            "  Token (first 20 chars): {}",
            &alice.access_token[..20.min(alice.access_token.len())]
        );
        println!("  Recipient: {}", bob.user_id);

        let response = send_message_with_number(&ctx, &alice, &bob.user_id, msg_num, content)
            .await
            .expect("Failed to send message");

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        println!("  Status: {}, Body: {}", status, body);

        assert_eq!(
            status,
            StatusCode::OK,
            "Failed to send message #{}: {}",
            msg_num,
            body
        );

        println!("✅ Sent message #{}", msg_num);
    }

    // Small delay to ensure all messages are in Redis
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Bob polls for messages (since=0-0 to get all messages from start)
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/api/v1/messages", ctx.messaging_address))
        .query(&[("since", "0-0"), ("limit", "100")]) // Get all messages, disable long polling
        .bearer_auth(&bob.access_token)
        .header("x-user-id", &bob.user_id) // Add X-User-Id for TrustedUser extractor
        .send()
        .await
        .expect("Failed to poll messages");

    assert_eq!(response.status(), StatusCode::OK);

    let json: serde_json::Value = response.json().await.expect("Failed to parse response");

    let messages = json["messages"]
        .as_array()
        .expect("messages should be array");

    assert_eq!(messages.len(), 5, "Should receive all 5 messages");

    // ✅ CRITICAL: Verify messages are sorted by messageNumber
    let message_numbers: Vec<u32> = messages
        .iter()
        .map(|m| m["messageNumber"].as_u64().unwrap() as u32)
        .collect();

    println!("📥 Received message numbers: {:?}", message_numbers);

    // Expected order: [0, 1, 2, 3, 4] (sorted by messageNumber)
    // NOT: [4, 2, 0, 3, 1] (arrival order)
    assert_eq!(
        message_numbers,
        vec![0, 1, 2, 3, 4],
        "Messages MUST be sorted by messageNumber for Double Ratchet protocol"
    );

    // ✅ Verify first message is #0 (critical for session initialization)
    assert_eq!(
        messages[0]["messageNumber"].as_u64().unwrap(),
        0,
        "First message MUST be messageNumber 0 for session initialization"
    );

    println!("✅ Messages correctly sorted by messageNumber");
}

/// Test that single message #0 is processed correctly
#[tokio::test]
async fn test_session_init_message_zero_first() {
    let ctx = spawn_app().await;

    let alice = register_test_user(&ctx, "alice_init").await;
    let bob = register_test_user(&ctx, "bob_init").await;

    // Send message #0 (session initialization)
    let response = send_message_with_number(&ctx, &alice, &bob.user_id, 0, "Session init message")
        .await
        .expect("Failed to send init message");

    assert_eq!(response.status(), StatusCode::OK);

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Bob polls
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/api/v1/messages", ctx.messaging_address))
        .query(&[("since", "0-0"), ("limit", "100")])
        .bearer_auth(&bob.access_token)
        .header("x-user-id", &bob.user_id)
        .send()
        .await
        .expect("Failed to poll");

    let json: serde_json::Value = response.json().await.unwrap();
    let messages = json["messages"].as_array().unwrap();

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["messageNumber"].as_u64().unwrap(), 0);

    println!("✅ Session init message #0 received correctly");
}

/// Test large batch of out-of-order messages
#[tokio::test]
async fn test_large_batch_out_of_order() {
    let ctx = spawn_app().await;

    let alice = register_test_user(&ctx, "alice_batch").await;
    let bob = register_test_user(&ctx, "bob_batch").await;

    // Send 20 messages in reverse order (19, 18, 17, ..., 1, 0)
    for msg_num in (0..20).rev() {
        send_message_with_number(
            &ctx,
            &alice,
            &bob.user_id,
            msg_num,
            &format!("Message {}", msg_num),
        )
        .await
        .expect("Failed to send message");
    }

    println!("✅ Sent 20 messages in reverse order");

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Bob polls
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/api/v1/messages", ctx.messaging_address))
        .query(&[("since", "0-0"), ("limit", "100")])
        .bearer_auth(&bob.access_token)
        .header("x-user-id", &bob.user_id)
        .send()
        .await
        .expect("Failed to poll");

    assert_eq!(response.status(), StatusCode::OK);

    let json: serde_json::Value = response.json().await.unwrap();
    let messages = json["messages"].as_array().unwrap();

    assert_eq!(messages.len(), 20, "Should receive all 20 messages");

    // Verify sorted order
    let message_numbers: Vec<u32> = messages
        .iter()
        .map(|m| m["messageNumber"].as_u64().unwrap() as u32)
        .collect();

    let expected: Vec<u32> = (0..20).collect();

    assert_eq!(
        message_numbers, expected,
        "All 20 messages must be in correct order"
    );

    println!("✅ All 20 messages correctly sorted: 0-19");
}

/// Test message ordering with random order
#[tokio::test]
async fn test_random_order_messages() {
    let ctx = spawn_app().await;

    let alice = register_test_user(&ctx, "alice_random").await;
    let bob = register_test_user(&ctx, "bob_random").await;

    // Send 10 messages in random order
    let random_order = vec![5, 2, 8, 0, 3, 9, 1, 6, 4, 7];

    for msg_num in random_order {
        send_message_with_number(
            &ctx,
            &alice,
            &bob.user_id,
            msg_num,
            &format!("Random msg {}", msg_num),
        )
        .await
        .expect("Failed to send");
    }

    println!("✅ Sent 10 messages in random order: [5,2,8,0,3,9,1,6,4,7]");

    tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

    // Bob polls
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("http://{}/api/v1/messages", ctx.messaging_address))
        .query(&[("since", "0-0"), ("limit", "100")])
        .bearer_auth(&bob.access_token)
        .header("x-user-id", &bob.user_id)
        .send()
        .await
        .expect("Failed to poll");

    let json: serde_json::Value = response.json().await.unwrap();
    let messages = json["messages"].as_array().unwrap();

    // Verify ALL messages are sorted correctly
    let message_numbers: Vec<u32> = messages
        .iter()
        .map(|m| m["messageNumber"].as_u64().unwrap() as u32)
        .collect();

    let expected: Vec<u32> = (0..10).collect();

    assert_eq!(
        message_numbers, expected,
        "Messages must be sorted even when sent in random order"
    );

    // Verify first message is ALWAYS #0
    assert_eq!(
        messages[0]["messageNumber"].as_u64().unwrap(),
        0,
        "CRITICAL: First message must be #0 for Double Ratchet session init"
    );

    println!("✅ Random order messages correctly sorted to 0-9");
}
