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

    let urls = turn_urls(
        &env::var("TURN_HOSTS")
            .or_else(|_| env::var("TURN_HOST"))
            .unwrap_or_else(|_| "turn.konstruct.cc".into()),
    );

    TurnCredentials {
        urls,
        username,
        credential,
        expires_at: (expiry * 1000) as i64,
    }
}

/// `TURN_HOSTS` (comma-separated) → ICE server URLs.
///
/// A bare host is a relay in the standard shape and expands to its three listeners:
/// `turn:` UDP and TCP on 3478, `turns:` on 5349. An entry that already carries a
/// scheme (`turn:` / `turns:`) is advertised verbatim and nothing else is added for
/// it — a relay that exists only as `turns:<host>:443?transport=tcp` behind an SNI
/// demux must not be probed on ports it never opened (each dead URL costs the
/// client an ICE gathering timeout, and 3478 on a host that answers nothing else
/// says what the host is).
pub(crate) fn turn_urls(hosts: &str) -> Vec<String> {
    hosts
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .flat_map(|entry| {
            if entry.starts_with("turn:") || entry.starts_with("turns:") {
                vec![entry.to_string()]
            } else {
                vec![
                    format!("turn:{entry}:3478?transport=udp"),
                    format!("turn:{entry}:3478?transport=tcp"),
                    format!("turns:{entry}:5349?transport=tcp"),
                ]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{generate_turn_credentials, turn_urls};
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

    #[test]
    fn a_bare_host_expands_and_an_explicit_url_is_advertised_as_is() {
        let urls = turn_urls("turn.ams.konstruct.cc, turns:relay.example.org:443?transport=tcp,,");
        assert_eq!(
            urls,
            vec![
                "turn:turn.ams.konstruct.cc:3478?transport=udp",
                "turn:turn.ams.konstruct.cc:3478?transport=tcp",
                "turns:turn.ams.konstruct.cc:5349?transport=tcp",
                "turns:relay.example.org:443?transport=tcp",
            ]
        );
    }
}
