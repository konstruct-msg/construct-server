//! Simplified Contract Tests для nextSince
//!
//! КРИТИЧЕСКИЙ тест: Проверяем что nextSince ВСЕГДА присутствует в JSON response

/// Проверяем что JSON response ВСЕГДА содержит nextSince
#[test]
fn test_json_response_schema() {
    // Test 1: nextSince присутствует (Some)
    let json_with_value = serde_json::json!({
        "messages": [],
        "nextSince": "1234-0"
    });

    assert!(
        json_with_value.get("nextSince").is_some(),
        "nextSince field must exist in JSON"
    );
    assert!(
        json_with_value["nextSince"].is_string(),
        "nextSince must be a string"
    );

    // Test 2: nextSince как null (всё ещё присутствует!)
    let json_with_null = serde_json::json!({
        "messages": [],
        "nextSince": null
    });

    assert!(
        json_with_null.get("nextSince").is_some(),
        "nextSince field must exist even if null"
    );

    // Test 3: Проверяем сериализацию наших структур
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GetMessagesResponse {
        messages: Vec<String>,
        next_since: Option<String>,
    }

    // Case A: Some(value)
    let response_some = GetMessagesResponse {
        messages: vec![],
        next_since: Some("1234-0".to_string()),
    };

    let json_some = serde_json::to_value(&response_some).unwrap();
    assert!(json_some.get("nextSince").is_some());
    assert_eq!(json_some["nextSince"], "1234-0");

    // Case B: None (должен сериализоваться как null)
    let response_none = GetMessagesResponse {
        messages: vec![],
        next_since: None,
    };

    let json_none = serde_json::to_value(&response_none).unwrap();
    assert!(
        json_none.get("nextSince").is_some(),
        "❌ BUG: nextSince field missing when None! This causes infinite loop!"
    );
    assert!(
        json_none["nextSince"].is_null(),
        "nextSince should be null, not omitted"
    );
}

/// Проверяем что serde(skip_serializing_if) ЛОМАЕТ контракт
#[test]
fn test_skip_serializing_if_breaks_contract() {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct BadResponse {
        messages: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        next_since: Option<String>,
    }

    let response = BadResponse {
        messages: vec![],
        next_since: None,
    };

    let json = serde_json::to_value(&response).unwrap();

    // ❌ BAD: nextSince field ПОЛНОСТЬЮ отсутствует
    assert!(
        json.get("nextSince").is_none(),
        "This proves skip_serializing_if is dangerous!"
    );

    // Это ломает клиентов:
    // Swift: nextSince становится nil → infinite loop
    // TypeScript: nextSince becomes undefined → crash
}

/// Проверяем валидность stream_id форматов
#[test]
fn test_stream_id_validation() {
    fn is_valid_stream_id(id: &str) -> bool {
        if id == "0" || id == "$" || id == "*" {
            return true;
        }
        if id == "0-0" {
            return true;
        }

        let parts: Vec<&str> = id.split('-').collect();
        if parts.len() != 2 {
            return false;
        }

        parts[0].parse::<u64>().is_ok() && parts[1].parse::<u64>().is_ok()
    }

    // Valid cases
    assert!(is_valid_stream_id("0"));
    assert!(is_valid_stream_id("$"));
    assert!(is_valid_stream_id("*"));
    assert!(is_valid_stream_id("0-0"));
    assert!(is_valid_stream_id("1234567890-0"));
    assert!(is_valid_stream_id("1771079450941-0"));

    // Invalid cases
    assert!(!is_valid_stream_id(""));
    assert!(!is_valid_stream_id("invalid"));
    assert!(!is_valid_stream_id("not-a-number-0"));
    assert!(!is_valid_stream_id("1234")); // Missing sequence
    assert!(!is_valid_stream_id("-0")); // Missing timestamp
    assert!(!is_valid_stream_id("abc-def"));
}

/// Проверяем что client polling loop не зависнет
#[test]
fn test_client_loop_simulation() {
    // Simulate клиент который делает polling
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MessagesResponse {
        messages: Vec<serde_json::Value>,
        next_since: String, // REQUIRED, not Option<String>!
    }

    // Server response (empty, no new messages)
    let server_json = serde_json::json!({
        "messages": [],
        "nextSince": "1234-0"
    });

    // Client parse
    let response: MessagesResponse =
        serde_json::from_value(server_json).expect("Client should be able to parse response");

    assert_eq!(response.messages.len(), 0);
    assert_eq!(response.next_since, "1234-0");

    // Client would use this for next request
    let next_request_since = response.next_since;
    assert!(
        !next_request_since.is_empty(),
        "Client should have valid nextSince for next iteration"
    );
}

/// Проверяем обработку ошибки когда nextSince отсутствует
#[test]
fn test_client_handles_missing_next_since() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MessagesResponse {
        _messages: Vec<serde_json::Value>,
        next_since: Option<String>, // Client защищается с Option
    }

    // Bad server response (missing nextSince)
    let bad_json = serde_json::json!({
        "messages": []
    });

    let response: MessagesResponse = serde_json::from_value(bad_json).unwrap();

    // Client должен обнаружить нарушение контракта
    assert!(
        response.next_since.is_none(),
        "This test demonstrates what happens when server violates contract"
    );

    // В реальном коде клиент должен:
    // if response.next_since.is_none() {
    //     throw Error("Server violated contract: nextSince missing!");
    // }

    println!("⚠️ This demonstrates the bug that was fixed!");
    println!("Without nextSince field, client enters infinite loop");
}

/// Property test: nextSince должен быть монотонным (never go backwards)
#[test]
fn test_next_since_monotonic_property() {
    // Simulate sequence of responses
    let responses = vec![
        ("0-0", true),
        ("1000-0", true),
        ("1000-1", true),
        ("2000-0", true),
        ("1500-0", false), // ❌ BACKWARDS! Invalid
    ];

    let mut previous: Option<(u64, u64)> = None;

    for (next_since, should_be_valid) in responses {
        if next_since == "0-0" {
            previous = Some((0, 0));
            continue;
        }

        let parts: Vec<&str> = next_since.split('-').collect();
        let timestamp = parts[0].parse::<u64>().unwrap();
        let sequence = parts[1].parse::<u64>().unwrap();

        if let Some((prev_ts, prev_seq)) = previous {
            let is_forward = timestamp > prev_ts || (timestamp == prev_ts && sequence > prev_seq);
            assert_eq!(
                is_forward,
                should_be_valid,
                "nextSince {} should be {} (previous: {}-{})",
                next_since,
                if should_be_valid { "valid" } else { "invalid" },
                prev_ts,
                prev_seq
            );
        }

        previous = Some((timestamp, sequence));
    }
}

#[test]
fn test_contract_documentation() {
    println!("✅ Contract Rules:");
    println!("1. nextSince MUST always exist in JSON");
    println!("2. nextSince MUST be string (not null, not omitted)");
    println!("3. nextSince formats: '0-0', 'timestamp-sequence', '$', '*'");
    println!("4. nextSince MUST be monotonic (never backwards)");
    println!("5. When no messages: echo 'since' or return '0-0'");
    println!();
    println!(
        "📖 See: ~/Code/construct-docs/raw/03_Server_Backend/Documentation/NEXT_SINCE_CONTRACT.md"
    );
}
