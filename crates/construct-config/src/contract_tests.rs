//! Config decisions run in a fresh process with a blank .env. No process-global env writes
//! race other unit tests, and no developer/CI secrets are read by the contract fixture.
use crate::{Config, SecretNeeds};
use std::{path::PathBuf, process::Command};

const CHILD: &str = "CONSTRUCT_CONFIG_CONTRACT_CHILD";
const HEX: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SALT: &str = "config-contract-unique-log-hash-salt";
const CSRF: &str = "config-contract-csrf-secret-at-least-32";

fn child() -> bool {
    std::env::var_os(CHILD).is_some()
}
fn value(name: &str) -> String {
    std::env::var(name).expect(name)
}
fn check<T>(result: anyhow::Result<T>) {
    let expected = value("EXPECT_ERROR");
    if expected.is_empty() {
        result.unwrap_or_else(|e| panic!("expected success: {e:#}"));
    } else {
        let err = result
            .err()
            .unwrap_or_else(|| panic!("expected refusal for {expected}"));
        assert!(
            format!("{err:#}").contains(&expected),
            "expected {expected}, got {err:#}"
        );
    }
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join(".env"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
fn run(test: &str, vars: &[(&str, String)], expected: &str) {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("construct-config-235-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir(&fixture.0).unwrap();
    // dotenv stops here, instead of searching parents for a real operator file.
    std::fs::write(fixture.0.join(".env"), "").unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            &format!("contract_tests::{test}"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(CHILD, "1")
        .env("EXPECT_ERROR", expected)
        .env("ENVIRONMENT", "development")
        .env("INSTANCE_DOMAIN", "test.example")
        .envs(vars.iter().map(|(k, v)| (*k, v)))
        .current_dir(&fixture.0);
    if vars.iter().any(|(k, _)| *k == "OMIT_DOMAIN") {
        command.env_remove("INSTANCE_DOMAIN");
    }
    if vars.iter().any(|(k, _)| *k == "OMIT_ENV") {
        command.env_remove("ENVIRONMENT");
    }
    #[cfg(unix)]
    if let Some((_, target)) = vars.iter().find(|(k, _)| *k == "NON_TEXT") {
        use std::os::unix::ffi::OsStringExt;
        command.env(target, std::ffi::OsString::from_vec(vec![0xff]));
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{test}, expected={expected}:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 passed; 0 failed"),
        "child did not execute one test: {stdout}"
    );
}

const ENCODED: &[(&str, usize, bool)] = &[
    ("SERVER_SIGNING_KEY", 32, false),
    ("BUNDLE_SIGNING_KEY", 32, false),
    ("BUNDLE_SIGNING_PUBLIC_KEY", 32, false),
    ("SERVER_TRUST_SENDER_CERT_KEY", 64, false),
    ("SERVER_TRUST_KT_HEAD_KEY", 64, false),
    ("TOKEN_ISSUER_KEY", 32, true),
    ("APNS_DEVICE_TOKEN_ENCRYPTION_KEY", 32, true),
    ("USERNAME_HMAC_SECRET", 32, true),
    ("CONTACT_HMAC_SECRET", 32, true),
    ("REQUEST_ENVELOPE_KEY", 32, true),
];
const SENSITIVE: &[&str] = &[
    "SERVER_SIGNING_KEY",
    "TOKEN_ISSUER_KEY",
    "BUNDLE_SIGNING_KEY",
    "BUNDLE_SIGNING_PUBLIC_KEY",
    "SERVER_TRUST_SENDER_CERT_KEY",
    "SERVER_TRUST_KT_HEAD_KEY",
    "APNS_DEVICE_TOKEN_ENCRYPTION_KEY",
    "USERNAME_HMAC_SECRET",
    "CONTACT_HMAC_SECRET",
    "MEDIA_HMAC_SECRET",
    "MEDIA_UPLOAD_TOKEN_SECRET",
    "CSRF_SECRET",
    "LOG_HASH_SALT",
    "TURN_SECRET",
    "REQUEST_ENVELOPE_KEY",
    "MASQUE_AUTH_TOKEN",
];
fn encode(len: usize, hex: bool) -> String {
    use base64::Engine as _;
    if hex {
        "a1".repeat(len)
    } else {
        base64::engine::general_purpose::STANDARD.encode(vec![0xa1; len])
    }
}

#[test]
fn encoded_secrets_are_validated_even_when_unused() {
    if child() {
        check(crate::secret_hygiene::validate());
        check(Config::from_env_for(SecretNeeds::GATEWAY));
        return;
    }
    for &(name, len, hex) in ENCODED {
        run("encoded_secrets_are_validated_even_when_unused", &[], "");
        for valid in [String::new(), " \t".into(), encode(len, hex)] {
            run(
                "encoded_secrets_are_validated_even_when_unused",
                &[(name, valid)],
                "",
            );
        }
        for invalid in [
            encode(len - 1, hex),
            encode(len + 1, hex),
            "!invalid!".into(),
            encode(len, !hex),
        ] {
            run(
                "encoded_secrets_are_validated_even_when_unused",
                &[(name, invalid)],
                name,
            );
        }
    }
}

#[test]
fn all_sensitive_names_reject_literal_quotes() {
    if child() {
        check(crate::secret_hygiene::validate());
        return;
    }
    for name in SENSITIVE {
        for quoted in ["\"secret\"", "'secret'"] {
            run(
                "all_sensitive_names_reject_literal_quotes",
                &[(*name, quoted.into())],
                "quotes",
            );
        }
    }
}

#[test]
fn known_plaintext_defaults_require_explicit_opt_in() {
    if child() {
        check(crate::secret_hygiene::validate());
        return;
    }
    for text in [
        "changeme",
        "change-me-in-production",
        "construct-insecure-username-hmac",
        "construct-insecure-contact-hmac",
        "construct-insecure-envelope-key!!",
        "construct-insecure-envelope-key!",
    ] {
        run(
            "known_plaintext_defaults_require_explicit_opt_in",
            &[("TURN_SECRET", text.into())],
            "insecure",
        );
        for opt in ["true", "1", "TRUE"] {
            run(
                "known_plaintext_defaults_require_explicit_opt_in",
                &[
                    ("TURN_SECRET", text.into()),
                    ("ALLOW_INSECURE_SECRETS", opt.into()),
                ],
                "",
            );
        }
    }
}

fn role(name: &str) -> SecretNeeds {
    match name {
        "ALL" => SecretNeeds::ALL,
        "IDENTITY" => SecretNeeds::IDENTITY,
        "MESSAGING" => SecretNeeds::MESSAGING,
        "KEY" => SecretNeeds::KEY,
        "GROUP" => SecretNeeds::GROUP,
        "MEDIA" => SecretNeeds::MEDIA,
        "SIGNALING" => SecretNeeds::SIGNALING,
        "GATEWAY" => SecretNeeds::GATEWAY,
        "VEIL" => SecretNeeds::VEIL,
        _ => panic!("unknown fixture role"),
    }
}
const REQUIRED: &[(&str, &str)] = &[
    (
        "DATABASE_URL",
        "postgres://fixture:fixture@localhost/fixture",
    ),
    ("REDIS_URL", "redis://localhost"),
    ("USERNAME_HMAC_SECRET", HEX),
    ("CONTACT_HMAC_SECRET", HEX),
    ("REQUEST_ENVELOPE_KEY", HEX),
    ("LOG_HASH_SALT", SALT),
    ("CSRF_SECRET", CSRF),
];
// This table is the reviewed contract, not computed from SecretNeeds itself.
const ROLES: &[(&str, &str)] = &[
    ("ALL", "1111111"),
    ("IDENTITY", "1111110"),
    ("MESSAGING", "1100010"),
    ("KEY", "1100000"),
    ("GROUP", "1100000"),
    ("MEDIA", "1000000"),
    ("SIGNALING", "0000000"),
    ("GATEWAY", "0000000"),
    ("VEIL", "1000000"),
];
#[test]
fn every_service_requires_exactly_its_own_slice() {
    if child() {
        let needs = role(&value("ROLE"));
        let actual = [
            needs.database_url,
            needs.redis_url,
            needs.username_hmac,
            needs.contact_hmac,
            needs.request_envelope,
            needs.log_hash_salt,
            needs.csrf,
        ];
        let mask = value("MASK");
        assert_eq!(
            actual,
            mask.bytes()
                .map(|v| v == b'1')
                .collect::<Vec<_>>()
                .as_slice()
        );
        let result = Config::from_env_for(needs);
        if !value("EXPECT_ERROR").is_empty() {
            check(result);
            return;
        }
        let cfg = result.unwrap();
        assert_eq!(cfg.database_url.is_empty(), !actual[0]);
        assert_eq!(cfg.redis_url.is_empty(), !actual[1]);
        for (secret, required) in [
            (&cfg.security.username_hmac_secret, actual[2]),
            (&cfg.security.contact_hmac_secret, actual[3]),
            (&cfg.security.request_envelope_key, actual[4]),
        ] {
            assert_eq!(
                secret.as_slice(),
                if required { &[0xa1; 32][..] } else { &[][..] }
            );
        }
        assert_eq!(cfg.logging.hash_salt, if actual[5] { SALT } else { "" });
        assert_eq!(cfg.csrf.secret, if actual[6] { CSRF } else { "" });
        assert_eq!(cfg.csrf.enabled, actual[6]);
        return;
    }
    for &(name, mask) in ROLES {
        let mut vars = vec![
            ("ENVIRONMENT", "production".into()),
            ("ROLE", name.into()),
            ("MASK", mask.into()),
        ];
        for ((key, val), bit) in REQUIRED.iter().zip(mask.bytes()) {
            if bit == b'1' {
                vars.push((*key, (*val).into()));
            }
        }
        run("every_service_requires_exactly_its_own_slice", &vars, "");
        for ((key, _), bit) in REQUIRED.iter().zip(mask.bytes()) {
            if bit != b'1' {
                continue;
            }
            for missing in [None, Some(""), Some(" \t")] {
                let mut bad = vars.clone();
                bad.retain(|(k, _)| k != key);
                if let Some(value) = missing {
                    bad.push((*key, value.into()));
                }
                run("every_service_requires_exactly_its_own_slice", &bad, key);
            }
        }
    }
}

#[test]
fn production_detection_covers_all_deployment_indicators() {
    if child() {
        assert_eq!(crate::is_production_environment(), value("PROD") == "yes");
        return;
    }
    run(
        "production_detection_covers_all_deployment_indicators",
        &[("OMIT_ENV", "1".into()), ("PROD", "no".into())],
        "",
    );
    for (key, text, prod) in [
        ("PRODUCTION", "true", true),
        ("PRODUCTION", "1", true),
        ("PRODUCTION", "TRUE", true),
        ("PRODUCTION", "false", false),
        ("ENVIRONMENT", "production", true),
        ("ENVIRONMENT", "staging", true),
        ("ENVIRONMENT", "Production", true),
        ("ENVIRONMENT", "development", false),
        ("ENVIRONMENT", "DEV", false),
        ("ENVIRONMENT", "local", false),
        ("ENVIRONMENT", "test", false),
        ("ENVIRONMENT", "", false),
        ("FLY_APP_NAME", "", true),
        ("FLY_REGION", "ams", true),
        ("RAILWAY_ENVIRONMENT", "production", true),
        ("RAILWAY_ENVIRONMENT", "development", false),
    ] {
        run(
            "production_detection_covers_all_deployment_indicators",
            &[
                (key, text.into()),
                ("PROD", if prod { "yes" } else { "no" }.into()),
            ],
            "",
        );
    }
}

#[test]
fn federation_never_guesses_the_instance_domain() {
    if child() {
        check(Config::from_env_for(SecretNeeds::GATEWAY));
        return;
    }
    // An absent domain overrides the harness's normally healthy value explicitly.
    for text in ["", " \t"] {
        run(
            "federation_never_guesses_the_instance_domain",
            &[("INSTANCE_DOMAIN", text.into())],
            "INSTANCE_DOMAIN",
        );
    }
    run(
        "federation_never_guesses_the_instance_domain",
        &[("OMIT_DOMAIN", "1".into())],
        "INSTANCE_DOMAIN",
    );
}

#[test]
fn explicitly_enabled_federation_needs_its_signing_key() {
    if child() {
        let result = Config::from_env_for(SecretNeeds::GATEWAY);
        if value("EXPECT_ERROR").is_empty() {
            let cfg = result.unwrap();
            assert_eq!(cfg.federation.enabled, value("ENABLED") == "yes");
        } else {
            check(result);
        }
        return;
    }
    for vars in [
        vec![],
        vec![("SERVER_SIGNING_KEY", "".into())],
        vec![("SERVER_SIGNING_KEY", " \t".into())],
    ] {
        let mut vars = vars;
        vars.push(("FEDERATION_ENABLED", "true".into()));
        run(
            "explicitly_enabled_federation_needs_its_signing_key",
            &vars,
            "SERVER_SIGNING_KEY",
        );
    }
    run(
        "explicitly_enabled_federation_needs_its_signing_key",
        &[
            ("FEDERATION_ENABLED", "true".into()),
            ("SERVER_SIGNING_KEY", encode(32, false)),
            ("ENABLED", "yes".into()),
        ],
        "",
    );
    run(
        "explicitly_enabled_federation_needs_its_signing_key",
        &[
            ("FEDERATION_ENABLED", "false".into()),
            ("ENABLED", "no".into()),
        ],
        "",
    );
}

#[test]
fn production_media_requires_at_least_one_nonblank_secret() {
    if child() {
        check(Config::from_env_for(SecretNeeds::GATEWAY));
        return;
    }
    for flag in ["true", "1"] {
        run(
            "production_media_requires_at_least_one_nonblank_secret",
            &[
                ("ENVIRONMENT", "production".into()),
                ("MEDIA_ENABLED", flag.into()),
            ],
            "MEDIA_",
        );
    }
    for key in ["MEDIA_HMAC_SECRET", "MEDIA_UPLOAD_TOKEN_SECRET"] {
        run(
            "production_media_requires_at_least_one_nonblank_secret",
            &[
                ("ENVIRONMENT", "production".into()),
                ("MEDIA_ENABLED", "true".into()),
                (key, "\t ".into()),
            ],
            "MEDIA_",
        );
        run(
            "production_media_requires_at_least_one_nonblank_secret",
            &[
                ("ENVIRONMENT", "production".into()),
                ("MEDIA_ENABLED", "true".into()),
                (key, HEX.into()),
            ],
            "",
        );
    }
    run(
        "production_media_requires_at_least_one_nonblank_secret",
        &[("MEDIA_ENABLED", "true".into())],
        "",
    );
    run(
        "production_media_requires_at_least_one_nonblank_secret",
        &[
            ("ENVIRONMENT", "production".into()),
            ("MEDIA_ENABLED", "true".into()),
            ("ALLOW_INSECURE_SECRETS", "true".into()),
        ],
        "",
    );
}

#[test]
fn csrf_and_log_salt_cannot_be_only_whitespace() {
    if child() {
        check(Config::from_env_for(if value("TARGET") == "CSRF_SECRET" {
            SecretNeeds::ALL
        } else {
            SecretNeeds::MESSAGING
        }));
        return;
    }
    for bad in ["default-salt-please-change", " default-salt-please-change "] {
        run(
            "csrf_and_log_salt_cannot_be_only_whitespace",
            &[
                ("TARGET", "LOG_HASH_SALT".into()),
                ("ENVIRONMENT", "production".into()),
                ("DATABASE_URL", "postgres://fixture/fixture".into()),
                ("REDIS_URL", "redis://localhost".into()),
                ("LOG_HASH_SALT", bad.into()),
            ],
            "LOG_HASH_SALT",
        );
    }
    for key in ["CSRF_SECRET", "LOG_HASH_SALT"] {
        let mut vars = vec![("ENVIRONMENT", "production".into()), ("TARGET", key.into())];
        vars.extend(REQUIRED.iter().map(|(k, v)| (*k, (*v).into())));
        vars.retain(|(k, _)| k != &key);
        vars.push((key, " ".repeat(40)));
        run("csrf_and_log_salt_cannot_be_only_whitespace", &vars, key);
    }
}

#[test]
fn hex_loaders_preserve_slices_and_reject_malformed_configured_values() {
    if child() {
        let target = value("TARGET");
        let mut needs = SecretNeeds::GATEWAY;
        match target.as_str() {
            "USERNAME_HMAC_SECRET" => needs.username_hmac = value("REQUIRED") == "yes",
            "CONTACT_HMAC_SECRET" => needs.contact_hmac = value("REQUIRED") == "yes",
            "REQUEST_ENVELOPE_KEY" => needs.request_envelope = value("REQUIRED") == "yes",
            _ => unreachable!(),
        }
        let result = crate::SecurityConfig::from_env(needs);
        if !value("EXPECT_ERROR").is_empty() {
            check(result);
            return;
        }
        let cfg = result.unwrap();
        let got = match target.as_str() {
            "USERNAME_HMAC_SECRET" => cfg.username_hmac_secret,
            "CONTACT_HMAC_SECRET" => cfg.contact_hmac_secret,
            _ => cfg.request_envelope_key,
        };
        let want = value("BYTES");
        assert_eq!(hex::encode(got), want);
        return;
    }
    for (key, default) in [
        (
            "USERNAME_HMAC_SECRET",
            b"construct-insecure-username-hmac".as_slice(),
        ),
        (
            "CONTACT_HMAC_SECRET",
            b"construct-insecure-contact-hmac".as_slice(),
        ),
        (
            "REQUEST_ENVELOPE_KEY",
            b"construct-insecure-envelope-key!".as_slice(),
        ),
    ] {
        for environment in ["development", "production"] {
            for required in ["yes", "no"] {
                let base = vec![
                    ("TARGET", key.into()),
                    ("ENVIRONMENT", environment.into()),
                    ("REQUIRED", required.into()),
                ];
                let mut valid = base.clone();
                valid.extend([(key, HEX.into()), ("BYTES", HEX.into())]);
                run(
                    "hex_loaders_preserve_slices_and_reject_malformed_configured_values",
                    &valid,
                    "",
                );
                for bad in ["zz".repeat(32), "ab".repeat(31), "ab".repeat(33)] {
                    let mut vars = base.clone();
                    vars.extend([(key, bad), ("ALLOW_INSECURE_SECRETS", "true".into())]);
                    run(
                        "hex_loaders_preserve_slices_and_reject_malformed_configured_values",
                        &vars,
                        key,
                    );
                }
                let mut absent = base.clone();
                absent.push((
                    "BYTES",
                    if required == "yes" {
                        hex::encode(default)
                    } else {
                        String::new()
                    },
                ));
                let expected = if environment == "production" && required == "yes" {
                    key
                } else {
                    ""
                };
                run(
                    "hex_loaders_preserve_slices_and_reject_malformed_configured_values",
                    &absent,
                    expected,
                );
                absent.push(("ALLOW_INSECURE_SECRETS", "1".into()));
                run(
                    "hex_loaders_preserve_slices_and_reject_malformed_configured_values",
                    &absent,
                    "",
                );
                let mut insecure = base;
                insecure.push((key, hex::encode(default)));
                run(
                    "hex_loaders_preserve_slices_and_reject_malformed_configured_values",
                    &insecure,
                    key,
                );
                insecure.extend([
                    ("ALLOW_INSECURE_SECRETS", "true".into()),
                    ("BYTES", hex::encode(default)),
                ]);
                run(
                    "hex_loaders_preserve_slices_and_reject_malformed_configured_values",
                    &insecure,
                    if default.len() == 32 { "" } else { key },
                );
            }
        }
    }
}

#[test]
fn issuer_env_alias_precedence_remains_compatible() {
    if child() {
        assert_eq!(
            Config::from_env_for(SecretNeeds::GATEWAY)
                .unwrap()
                .token_issuer,
            value("ISSUER")
        );
        return;
    }
    for vars in [
        vec![("ISSUER", "construct-server".into())],
        vec![
            ("JWT_ISSUER", "old.example".into()),
            ("ISSUER", "old.example".into()),
        ],
        vec![
            ("JWT_ISSUER", "old.example".into()),
            ("AUTH_TOKEN_ISSUER", "current.example".into()),
            ("ISSUER", "current.example".into()),
        ],
    ] {
        run("issuer_env_alias_precedence_remains_compatible", &vars, "");
    }
}

#[test]
fn token_issuer_loader_refuses_malformed_values_without_global_hygiene() {
    if child() {
        let result = crate::load_token_issuer_key();
        if !value("EXPECT_ERROR").is_empty() {
            check(result);
            return;
        }
        let got = result.unwrap();
        let expected = value("KEY");
        let expected = match expected.as_str() {
            "" => None,
            "sequence" => Some(std::array::from_fn(|index| index as u8)),
            _ => Some([0xa1; 32]),
        };
        assert_eq!(got, expected);
        return;
    }
    run(
        "token_issuer_loader_refuses_malformed_values_without_global_hygiene",
        &[("KEY", "".into())],
        "",
    );
    for text in [
        "".to_string(),
        " \t".into(),
        HEX.into(),
        HEX.to_uppercase(),
        format!(" {HEX} "),
    ] {
        let has_key = !text.trim().is_empty();
        run(
            "token_issuer_loader_refuses_malformed_values_without_global_hygiene",
            &[
                ("TOKEN_ISSUER_KEY", text),
                ("KEY", if has_key { "key" } else { "" }.into()),
            ],
            "",
        );
    }
    run(
        "token_issuer_loader_refuses_malformed_values_without_global_hygiene",
        &[
            (
                "TOKEN_ISSUER_KEY",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
            ),
            ("KEY", "sequence".into()),
        ],
        "",
    );
    #[cfg(unix)]
    run(
        "token_issuer_loader_refuses_malformed_values_without_global_hygiene",
        &[("NON_TEXT", "TOKEN_ISSUER_KEY".into())],
        "TOKEN_ISSUER_KEY",
    );
    for bad in [
        "ab".repeat(31),
        "ab".repeat(33),
        "zz".repeat(32),
        encode(32, false),
        format!("\"{HEX}\""),
    ] {
        run(
            "token_issuer_loader_refuses_malformed_values_without_global_hygiene",
            &[
                ("TOKEN_ISSUER_KEY", bad),
                ("ALLOW_INSECURE_SECRETS", "true".into()),
            ],
            "TOKEN_ISSUER_KEY",
        );
    }
}

#[cfg(unix)]
#[test]
fn nontext_secret_values_are_not_mistaken_for_absent_values() {
    if child() {
        check(crate::secret_hygiene::validate());
        return;
    }
    for key in SENSITIVE {
        run(
            "nontext_secret_values_are_not_mistaken_for_absent_values",
            &[("NON_TEXT", (*key).into())],
            "UTF-8",
        );
    }
}

#[test]
fn dev_envelope_material_preserves_the_historical_effective_key() {
    let old = b"construct-insecure-envelope-key!!";
    assert_eq!(crate::INSECURE_ENVELOPE_KEY.len(), 32);
    assert_eq!(crate::INSECURE_ENVELOPE_KEY, &old[..32]);
}

#[test]
fn known_effective_envelope_key_is_refused_when_configured_as_hex() {
    if child() {
        check(Config::from_env_for(SecretNeeds::IDENTITY));
        return;
    }
    let mut vars = vec![("ENVIRONMENT", "production".into())];
    vars.extend(REQUIRED[..6].iter().map(|(k, v)| (*k, (*v).into())));
    vars.retain(|(k, _)| *k != "REQUEST_ENVELOPE_KEY");
    // The old 33-byte default was truncated by envelope_encrypt to these 32 bytes.
    vars.push((
        "REQUEST_ENVELOPE_KEY",
        hex::encode(b"construct-insecure-envelope-key!"),
    ));
    run(
        "known_effective_envelope_key_is_refused_when_configured_as_hex",
        &vars,
        "REQUEST_ENVELOPE_KEY",
    );
    vars.push(("ALLOW_INSECURE_SECRETS", "true".into()));
    run(
        "known_effective_envelope_key_is_refused_when_configured_as_hex",
        &vars,
        "",
    );
}
