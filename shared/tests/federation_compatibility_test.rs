// ============================================================================
// Federation Compatibility Tests
// ============================================================================
//
// These tests verify that:
// 1. Current API remains backward compatible with existing clients (UUID-only)
// 2. New federated ID format (uuid@domain) works correctly
// 3. Message Gateway Service accepts both formats
// 4. No breaking changes to message structure
// ============================================================================

use construct_types::ChatMessage;
use construct_types::UserId;
use uuid::Uuid;

#[test]
fn test_local_uuid_format_still_works() {
    // Test that existing clients using UUID-only format still work
    let local_uuid = Uuid::new_v4().to_string();

    // Parse as UserId
    let user_id = UserId::parse(&local_uuid).expect("Failed to parse local UUID");

    assert!(user_id.is_local(), "Should be recognized as local user");
    assert_eq!(user_id.to_string(), local_uuid);
}

#[test]
fn test_federated_id_format_works() {
    // Test that new federated format works
    let uuid = Uuid::new_v4();
    let federated_id = format!("{}@server.com", uuid);

    // Parse as UserId
    let user_id = UserId::parse(&federated_id).expect("Failed to parse federated ID");

    assert!(
        user_id.is_federated(),
        "Should be recognized as federated user"
    );
    assert_eq!(user_id.domain(), Some("server.com"));
    assert_eq!(user_id.uuid(), &uuid);
    assert_eq!(user_id.to_string(), federated_id);
}

#[test]
fn test_chat_message_validates_local_users() {
    // Test that ChatMessage.is_valid() accepts local UUID format
    let sender = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    let msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: sender.clone(),
        to: recipient.clone(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]), // 32 bytes required
        message_number: Some(1),
        content: Some("base64encodedcontent".to_string()),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    assert!(msg.is_valid(), "Message with local UUIDs should be valid");
}

#[test]
fn test_chat_message_validates_federated_users() {
    // Test that ChatMessage.is_valid() accepts federated format
    let sender = format!("{}@local.server", Uuid::new_v4());
    let recipient = format!("{}@remote.server", Uuid::new_v4());

    let msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: sender.clone(),
        to: recipient.clone(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("base64encodedcontent".to_string()),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    assert!(msg.is_valid(), "Message with federated IDs should be valid");
}

#[test]
fn test_chat_message_validates_mixed_format() {
    // Test that we can send from local to federated and vice versa
    let local_uuid = Uuid::new_v4().to_string();
    let federated_id = format!("{}@remote.server", Uuid::new_v4());

    // Local sender to federated recipient
    let msg1 = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: local_uuid.clone(),
        to: federated_id.clone(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("base64encodedcontent".to_string()),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    assert!(msg1.is_valid(), "Local to federated should be valid");

    // Federated sender to local recipient
    let msg2 = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: federated_id.clone(),
        to: local_uuid.clone(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("base64encodedcontent".to_string()),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    assert!(msg2.is_valid(), "Federated to local should be valid");
}

#[test]
fn test_invalid_formats_rejected() {
    // Test that invalid formats are properly rejected

    // Empty string
    assert!(
        UserId::parse("").is_err(),
        "Empty string should be rejected"
    );

    // Not a UUID
    assert!(
        UserId::parse("not-a-uuid").is_err(),
        "Invalid UUID should be rejected"
    );

    // Invalid federated format (bad UUID)
    assert!(
        UserId::parse("not-a-uuid@server.com").is_err(),
        "Invalid UUID in federated format should be rejected"
    );

    // Empty domain
    assert!(
        UserId::parse(&format!("{}@", Uuid::new_v4())).is_err(),
        "Empty domain should be rejected"
    );

    // Invalid domain (no dot)
    assert!(
        UserId::parse(&format!("{}@localhost", Uuid::new_v4())).is_err(),
        "Domain without dot should be rejected"
    );

    // Domain with spaces
    assert!(
        UserId::parse(&format!("{}@server .com", Uuid::new_v4())).is_err(),
        "Domain with spaces should be rejected"
    );
}

#[test]
fn test_chat_message_rejects_invalid_ids() {
    // Test that ChatMessage.is_valid() rejects messages with invalid user IDs

    let valid_uuid = Uuid::new_v4().to_string();

    // Invalid sender ID
    let msg1 = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: "not-a-valid-id".to_string(),
        to: valid_uuid.clone(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("content".to_string()),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    assert!(
        !msg1.is_valid(),
        "Message with invalid sender should be rejected"
    );

    // Invalid recipient ID
    let msg2 = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: valid_uuid.clone(),
        to: "not-a-valid-id".to_string(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("content".to_string()),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    assert!(
        !msg2.is_valid(),
        "Message with invalid recipient should be rejected"
    );
}

#[test]
fn test_message_serialization_compatibility() {
    // Test that messages can be serialized/deserialized with both ID formats

    // Local UUID format
    let local_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: Uuid::new_v4().to_string(),
        to: Uuid::new_v4().to_string(),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("base64content".to_string()),
        timestamp: 1234567890,
    };

    // Serialize with MessagePack
    let bytes = rmp_serde::to_vec(&local_msg).expect("Failed to serialize local message");

    // Deserialize
    let deserialized: ChatMessage =
        rmp_serde::from_slice(&bytes).expect("Failed to deserialize local message");
    assert!(
        deserialized.is_valid(),
        "Deserialized local message should be valid"
    );
    assert_eq!(deserialized.from, local_msg.from);
    assert_eq!(deserialized.to, local_msg.to);

    // Federated format
    let federated_msg = ChatMessage {
        id: Uuid::new_v4().to_string(),
        from: format!("{}@local.server", Uuid::new_v4()),
        to: format!("{}@remote.server", Uuid::new_v4()),
        message_type: construct_types::MessageType::default(),
        ephemeral_public_key: Some(vec![0u8; 32]),
        message_number: Some(1),
        content: Some("base64content".to_string()),
        timestamp: 1234567890,
    };

    // Serialize with MessagePack
    let bytes = rmp_serde::to_vec(&federated_msg).expect("Failed to serialize federated message");

    // Deserialize
    let deserialized: ChatMessage =
        rmp_serde::from_slice(&bytes).expect("Failed to deserialize federated message");
    assert!(
        deserialized.is_valid(),
        "Deserialized federated message should be valid"
    );
    assert_eq!(deserialized.from, federated_msg.from);
    assert_eq!(deserialized.to, federated_msg.to);
}

#[test]
fn test_user_id_domain_extraction() {
    // Test that we can extract domain information correctly

    let local_id = UserId::parse(&Uuid::new_v4().to_string()).unwrap();
    assert!(local_id.is_local());
    assert_eq!(local_id.domain(), None);
    assert!(!local_id.is_from_domain("any.server"));

    let federated_id = UserId::parse(&format!("{}@example.com", Uuid::new_v4())).unwrap();
    assert!(federated_id.is_federated());
    assert_eq!(federated_id.domain(), Some("example.com"));
    assert!(federated_id.is_from_domain("example.com"));
    assert!(!federated_id.is_from_domain("other.com"));
}

#[test]
fn test_user_id_uuid_extraction() {
    // Test that we can extract UUID correctly from both formats

    let uuid = Uuid::new_v4();

    // Local format
    let local_id = UserId::parse(&uuid.to_string()).unwrap();
    assert_eq!(*local_id.uuid(), uuid);

    // Federated format
    let federated_id = UserId::parse(&format!("{}@example.com", uuid)).unwrap();
    assert_eq!(*federated_id.uuid(), uuid);
}

#[test]
fn test_complex_domain_formats() {
    // Test various valid domain formats

    let uuid = Uuid::new_v4();

    // Subdomain
    let id1 = UserId::parse(&format!("{}@mail.example.com", uuid));
    assert!(id1.is_ok());
    assert_eq!(id1.unwrap().domain(), Some("mail.example.com"));

    // Multiple subdomains
    let id2 = UserId::parse(&format!("{}@mail.server.example.com", uuid));
    assert!(id2.is_ok());
    assert_eq!(id2.unwrap().domain(), Some("mail.server.example.com"));

    // Hyphenated domain
    let id3 = UserId::parse(&format!("{}@my-server.com", uuid));
    assert!(id3.is_ok());
    assert_eq!(id3.unwrap().domain(), Some("my-server.com"));
}

#[cfg(test)]
mod messagepack_format_tests {
    use super::*;

    #[test]
    fn test_backward_compatibility_with_old_clients() {
        // Simulate an old client that only knows UUID format
        // Ensure new server can still handle it

        let old_format_msg = ChatMessage {
            id: Uuid::new_v4().to_string(),
            from: Uuid::new_v4().to_string(),
            to: Uuid::new_v4().to_string(),
            message_type: construct_types::MessageType::default(),
            ephemeral_public_key: Some(vec![0u8; 32]),
            message_number: Some(1),
            content: Some("old_client_message".to_string()),
            timestamp: 1234567890,
        };

        // Old client serializes with MessagePack
        let bytes = rmp_serde::to_vec(&old_format_msg).unwrap();

        // New server deserializes
        let msg: ChatMessage = rmp_serde::from_slice(&bytes).unwrap();

        // Server validates (should pass with backward compatibility)
        assert!(msg.is_valid(), "Old format messages should still be valid");

        // Server processes sender as local user
        let sender_id = UserId::parse(&msg.from).unwrap();
        assert!(
            sender_id.is_local(),
            "Old format should be treated as local user"
        );
    }

    #[test]
    fn test_forward_compatibility_with_federated_clients() {
        // Simulate a new client that uses federated format
        // Ensure server handles it correctly

        let new_format_msg = ChatMessage {
            id: Uuid::new_v4().to_string(),
            from: format!("{}@local.server", Uuid::new_v4()),
            to: format!("{}@remote.server", Uuid::new_v4()),
            message_type: construct_types::MessageType::default(),
            ephemeral_public_key: Some(vec![0u8; 32]),
            message_number: Some(1),
            content: Some("federated_client_message".to_string()),
            timestamp: 1234567890,
        };

        // New client serializes with MessagePack
        let bytes = rmp_serde::to_vec(&new_format_msg).unwrap();

        // Server deserializes
        let msg: ChatMessage = rmp_serde::from_slice(&bytes).unwrap();

        // Server validates (should pass with federated support)
        assert!(msg.is_valid(), "Federated format messages should be valid");

        // Server can route based on recipient domain
        let recipient_id = UserId::parse(&msg.to).unwrap();
        assert!(recipient_id.is_federated());
        assert_eq!(recipient_id.domain(), Some("remote.server"));
    }
}
