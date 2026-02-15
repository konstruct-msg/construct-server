/// Double Ratchet Protocol Compliance Tests
/// 
/// SPECIFICATION: Signal Protocol - Double Ratchet Algorithm
/// Reference: https://signal.org/docs/specifications/doubleratchet/
/// 
/// CRITICAL: The Double Ratchet requires strict message ordering.
/// Messages MUST be delivered in the order they were sent (FIFO).

use crate::test_utils::*;

#[tokio::test]
async fn test_first_message_has_message_number_zero() {
    // SPEC: Signal Protocol §3.3 - Initial message MUST have messageNumber=0
    // This is CRITICAL for session initialization.
    // 
    // BUG HISTORY: This test would have caught the InvalidCiphertext bug!
    // Root cause: Messages were not delivered starting from messageNumber=0
    
    let ctx = spawn_app().await;
    let alice = register_test_user(&ctx, "alice").await;
    let bob = register_test_user(&ctx, "bob").await;
    
    // Alice sends first message to Bob
    send_test_message(&ctx, &alice, &bob.user_id, "Hello Bob!").await;
    
    // Wait for delivery
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Bob retrieves messages
    let messages = get_all_messages(&ctx, &bob).await;
    
    assert!(
        !messages.is_empty(),
        "No messages received - delivery failed"
    );
    
    let first_msg = &messages[0];
    
    // SPEC REQUIREMENT: First message MUST have messageNumber = 0
    assert_eq!(
        first_msg["header"]["messageNumber"].as_u64().unwrap(),
        0,
        "PROTOCOL VIOLATION: First message must have messageNumber=0 for session initialization"
    );
}

#[tokio::test]
async fn test_message_numbers_increment_sequentially() {
    // SPEC: Signal Protocol §3.4 - messageNumber increments sequentially
    // Each message in a sending chain has messageNumber = previous + 1
    
    let ctx = spawn_app().await;
    let alice = register_test_user(&ctx, "alice").await;
    let bob = register_test_user(&ctx, "bob").await;
    
    // Alice sends 5 messages
    for i in 0..5 {
        send_test_message(&ctx, &alice, &bob.user_id, &format!("Message {}", i)).await;
    }
    
    // Wait for delivery
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Bob retrieves all messages
    let messages = get_all_messages(&ctx, &bob).await;
    
    assert_eq!(
        messages.len(),
        5,
        "Expected 5 messages, got {}",
        messages.len()
    );
    
    // SPEC REQUIREMENT: messageNumber must be 0, 1, 2, 3, 4
    for (i, msg) in messages.iter().enumerate() {
        let msg_num = msg["header"]["messageNumber"].as_u64().unwrap();
        assert_eq!(
            msg_num, i as u64,
            "PROTOCOL VIOLATION: Expected messageNumber={}, got {}",
            i, msg_num
        );
    }
}

#[tokio::test]
async fn test_messages_delivered_in_fifo_order() {
    // SPEC: Our protocol extension - Messages MUST be delivered in FIFO order
    // This is CRITICAL for Double Ratchet to work correctly.
    // 
    // WHY: Double Ratchet state machine requires processing messages in order.
    // Out-of-order delivery causes InvalidCiphertext errors.
    
    let ctx = spawn_app().await;
    let alice = register_test_user(&ctx, "alice").await;
    let bob = register_test_user(&ctx, "bob").await;
    
    // Alice sends 10 messages rapidly
    for i in 0..10 {
        send_test_message(&ctx, &alice, &bob.user_id, &format!("Message #{}", i)).await;
    }
    
    // Wait for all messages to be delivered
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // Bob retrieves all messages
    let messages = get_all_messages(&ctx, &bob).await;
    
    assert_eq!(
        messages.len(),
        10,
        "Not all messages delivered"
    );
    
    // CRITICAL: Verify FIFO order
    for (i, msg) in messages.iter().enumerate() {
        let msg_num = msg["header"]["messageNumber"].as_u64().unwrap();
        assert_eq!(
            msg_num, i as u64,
            "FIFO VIOLATION: Message out of order at position {}. Expected messageNumber={}, got {}",
            i, i, msg_num
        );
    }
}

#[tokio::test]
async fn test_multiple_message_retrieval_preserves_order() {
    // SPEC: Stream ID pagination MUST preserve FIFO order across requests
    // 
    // Scenario: Alice sends 10 messages. Bob fetches in 2 requests (5 + 5).
    // Result: Both batches MUST maintain sequential messageNumber.
    
    let ctx = spawn_app().await;
    let alice = register_test_user(&ctx, "alice").await;
    let bob = register_test_user(&ctx, "bob").await;
    
    // Send 10 messages
    for i in 0..10 {
        send_test_message(&ctx, &alice, &bob.user_id, &format!("Message {}", i)).await;
    }
    
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // First request: Get messages (should return first batch)
    let client = reqwest::Client::new();
    let response1 = client
        .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
        .header("Authorization", format!("Bearer {}", bob.access_token))
        .query(&[("limit", "5")])
        .send()
        .await
        .expect("Failed to get messages");
    
    let body1: serde_json::Value = response1.json().await.unwrap();
    let messages1 = body1["messages"].as_array().unwrap();
    let next_since = body1["nextSince"].as_str();
    
    // Verify first batch: messageNumber 0-4
    for (i, msg) in messages1.iter().enumerate() {
        assert_eq!(
            msg["header"]["messageNumber"].as_u64().unwrap(),
            i as u64,
            "First batch: wrong messageNumber at position {}", i
        );
    }
    
    // Second request: Use nextSince to get remaining messages
    if let Some(since) = next_since {
        let response2 = client
            .get(format!("http://{}/api/v1/messages", ctx.messaging_address))
            .header("Authorization", format!("Bearer {}", bob.access_token))
            .query(&[("since", since), ("limit", "5")])
            .send()
            .await
            .expect("Failed to get messages");
        
        let body2: serde_json::Value = response2.json().await.unwrap();
        let messages2 = body2["messages"].as_array().unwrap();
        
        // Verify second batch: messageNumber continues from 5-9
        for (i, msg) in messages2.iter().enumerate() {
            assert_eq!(
                msg["header"]["messageNumber"].as_u64().unwrap(),
                (5 + i) as u64,
                "Second batch: wrong messageNumber at position {}", i
            );
        }
    }
}
