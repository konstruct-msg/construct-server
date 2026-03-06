//! Unit test for nextSince logic
//!
//! Tests the fix for the critical bug where server returned `nextSince: null`

use serde_json::json;

#[test]
fn test_next_since_always_present_in_json() {
    // Test that Option<String> serializes even when Some()
    
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct TestResponse {
        messages: Vec<String>,
        next_since: Option<String>,
    }
    
    // Case 1: nextSince is Some(value)
    let response1 = TestResponse {
        messages: vec![],
        next_since: Some("1234567890-0".to_string()),
    };
    
    let json1 = serde_json::to_value(&response1).unwrap();
    assert!(json1.get("nextSince").is_some(), "nextSince field should exist");
    assert_eq!(json1["nextSince"], "1234567890-0");
    println!("✅ Case 1: nextSince with value serializes correctly");
    println!("   JSON: {}", serde_json::to_string_pretty(&json1).unwrap());
    
    // Case 2: nextSince is None (this will serialize as null in JSON)
    let response2 = TestResponse {
        messages: vec![],
        next_since: None,
    };
    
    let json2 = serde_json::to_value(&response2).unwrap();
    assert!(json2.get("nextSince").is_some(), "nextSince field should exist even when None");
    assert!(json2["nextSince"].is_null(), "nextSince should be null in JSON");
    println!("✅ Case 2: nextSince with None serializes as null");
    println!("   JSON: {}", serde_json::to_string_pretty(&json2).unwrap());
    
    // This confirms: Option<String> without skip_serializing_if will ALWAYS include the field
    // - Some(value) → "nextSince": "value"
    // - None → "nextSince": null
}

#[test]
fn test_next_since_logic_never_returns_none() {
    // Simulate the fixed logic - should NEVER return None
    
    fn compute_next_since(
        has_messages: bool,
        last_stream_id: Option<&str>,
        client_since: Option<&str>,
    ) -> Option<String> {
        if has_messages {
            // Has messages - return last stream_id (with fallback)
            last_stream_id
                .map(|id| id.to_string())
                .or_else(|| client_since.map(|s| s.to_string()))
                .or(Some("0-0".to_string()))
        } else {
            // No messages - return client's since or "0-0"
            client_since
                .map(|s| s.to_string())
                .or(Some("0-0".to_string()))
        }
    }
    
    // Test cases
    let cases = vec![
        // (has_messages, last_stream_id, client_since, expected_result)
        (true, Some("1234-5"), Some("1234-0"), Some("1234-5")),      // Has messages
        (true, Some("1234-5"), None, Some("1234-5")),                // Has messages, no client since
        (false, None, Some("1234-0"), Some("1234-0")),               // No messages, echo client
        (false, None, None, Some("0-0")),                            // No messages, no client since
        (true, None, Some("1234-0"), Some("1234-0")),                // Edge: has messages but no stream_id
        (false, Some("ignored"), Some("1234-0"), Some("1234-0")),    // No messages (stream_id ignored)
    ];
    
    for (i, (has_messages, last_stream_id, client_since, expected)) in cases.iter().enumerate() {
        let result = compute_next_since(*has_messages, *last_stream_id, *client_since);
        
        assert!(
            result.is_some(),
            "Case {}: nextSince should NEVER be None! Got: {:?}",
            i,
            result
        );
        
        assert_eq!(
            result.as_deref(),
            *expected,
            "Case {}: Wrong nextSince value",
            i
        );
        
        println!(
            "✅ Case {}: has_msg={}, last_id={:?}, client_since={:?} → nextSince={}",
            i,
            has_messages,
            last_stream_id,
            client_since,
            result.unwrap()
        );
    }
    
    println!("\n🎉 All cases pass - nextSince is NEVER None!");
}
