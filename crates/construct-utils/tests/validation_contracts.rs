use construct_utils::{
    SecureString, validate_password_strength, validate_secret_strength, validate_username,
};

#[test]
fn secure_string_hides_the_same_bytes_it_explicitly_exposes() {
    // No real credentials. Use non-ASCII and NUL so a lossy conversion also fails.
    let input = "secret-fixture\0🔒";
    let secret = SecureString::from(input);
    assert_eq!(format!("{secret:?}"), "[REDACTED]");
    assert_eq!(format!("{secret}"), "[REDACTED]");
    assert_eq!(secret.as_ref().as_bytes(), input.as_bytes());
    assert_eq!(secret.into_inner().as_bytes(), input.as_bytes());
}

#[test]
fn username_and_password_accept_both_length_boundaries() {
    for valid in ["A_1".into(), "a".repeat(64)] {
        assert_eq!(validate_username(&valid), Ok(()), "length {}", valid.len());
    }
    for (invalid, reason) in [
        ("A_".into(), "Username must be at least 3 characters long"),
        ("a".repeat(65), "Username must not exceed 64 characters"),
    ] {
        assert_eq!(validate_username(&invalid), Err(reason.to_owned()));
    }

    for len in [9, 10, 128, 129] {
        let password = format!("Aa1{}", "a".repeat(len - 3));
        let expected = match len {
            9 => Err("Password must be at least 10 characters long"),
            129 => Err("Password must not exceed 128 characters"),
            _ => Ok(()),
        };
        assert_eq!(
            validate_password_strength(&password),
            expected.map_err(str::to_owned),
            "length {len}"
        );
    }
}

#[test]
fn short_secret_checks_distinguish_length_uniformity_and_repetition() {
    for (secret, min_length, expected) in [
        ("ab", 3, Err("Secret must be at least 3 characters long")),
        (
            "aaa",
            3,
            Err("Secret must not consist of a single repeated character"),
        ),
        ("aba", 3, Ok(())),
        (
            "abab",
            4,
            Err("Secret must not contain simple repeating patterns"),
        ),
        (
            "ababa",
            4,
            Err("Secret must not contain simple repeating patterns"),
        ),
        ("abcd", 4, Ok(())),
    ] {
        assert_eq!(
            validate_secret_strength(secret, min_length),
            expected.map_err(str::to_owned),
            "fixture {secret:?}"
        );
    }
}

#[test]
fn long_nonperiodic_secrets_need_eight_distinct_characters() {
    // A simple repeat would be rejected before reaching the diversity check.
    let seven = "abcdefg".to_owned() + &"a".repeat(25);
    let eight = "abcdefgh".to_owned() + &"a".repeat(24);
    assert_eq!((seven.len(), eight.len()), (32, 32));
    assert_eq!(validate_secret_strength(&seven[..31], 31), Ok(()));
    assert_eq!(
        validate_secret_strength(&seven, 32),
        Err("Secret must contain at least 8 different characters".into())
    );
    assert_eq!(validate_secret_strength(&eight, 32), Ok(()));
}

#[test]
fn secret_pattern_checks_accept_utf8_without_slicing_inside_a_character() {
    assert_eq!(validate_secret_strength("🔒alpha123", 4), Ok(()));
    assert_eq!(
        validate_secret_strength("é1é1", 4),
        Err("Secret must not contain simple repeating patterns".into())
    );
}
