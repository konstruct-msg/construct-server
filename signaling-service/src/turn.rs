use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;

use construct_server_shared::shared::proto::signaling::v1::TurnCredentials;

/// TURN REST credentials (coturn `use-auth-secret`): `username = "<expiry>:<label>"`,
/// `credential = base64(HMAC-SHA1(secret, username))`.
///
/// The label is random, new for every issuance — never the account. Until 2026-10-13 it was the
/// caller's `user_id`: TURN sends USERNAME in clear in its Allocate on 3478 (UDP and TCP), so an
/// observer on the path read the account of everyone placing a call, and coturn wrote it to its
/// log. coturn needs the label for nothing but the HMAC; the per-account rate limit runs in
/// `get_turn_credentials`, before this, on the authenticated caller.
pub(crate) fn generate_turn_credentials(secret: &str, ttl: u64) -> TurnCredentials {
    use hmac::{Hmac, Mac, digest::KeyInit};
    use sha1::Sha1;

    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + ttl;
    let username = format!("{}:{}", expiry, uuid::Uuid::new_v4().simple());

    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    // Support multiple TURN servers via TURN_HOSTS (comma-separated).
    // Falls back to legacy TURN_HOST for single-server setups.
    let hosts: Vec<String> = env::var("TURN_HOSTS")
        .or_else(|_| env::var("TURN_HOST"))
        .unwrap_or_else(|_| "turn.konstruct.cc".into())
        .split(',')
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .collect();

    let urls = hosts
        .iter()
        .flat_map(|host| {
            [
                format!("turn:{}:3478?transport=udp", host),
                format!("turn:{}:3478?transport=tcp", host),
                format!("turns:{}:5349?transport=tcp", host),
            ]
        })
        .collect();

    TurnCredentials {
        urls,
        username,
        credential,
        expires_at: (expiry * 1000) as i64,
    }
}

#[cfg(test)]
mod tests {
    use super::generate_turn_credentials;
    use base64::Engine;
    use hmac::{Hmac, Mac, digest::KeyInit};
    use sha1::Sha1;

    #[test]
    fn the_username_carries_no_account_and_is_new_each_time() {
        let a = generate_turn_credentials("secret", 600);
        let b = generate_turn_credentials("secret", 600);
        assert_ne!(
            a.username, b.username,
            "a label shared across issuances links the calls"
        );
        let (expiry, label) = a.username.split_once(':').expect("<expiry>:<label>");
        assert!(expiry.parse::<u64>().is_ok());
        assert_eq!(label.len(), 32);
        assert!(label.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_credential_is_what_coturn_computes_from_the_username() {
        let c = generate_turn_credentials("secret", 600);
        let mut mac = Hmac::<Sha1>::new_from_slice(b"secret").unwrap();
        mac.update(c.username.as_bytes());
        let expected =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(c.credential, expected);
    }
}
