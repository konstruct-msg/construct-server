//! Account identifier compatibility: local UUIDs, federated UUIDs and domain parsing.

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
    assert_eq!(user_id.uuid(), Some(&uuid));
    assert_eq!(user_id.to_string(), federated_id);
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
    assert_eq!(*local_id.uuid().unwrap(), uuid);

    // Federated format
    let federated_id = UserId::parse(&format!("{}@example.com", uuid)).unwrap();
    assert_eq!(*federated_id.uuid().unwrap(), uuid);
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
