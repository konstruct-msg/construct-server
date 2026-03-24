use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;

use construct_server_shared::shared::proto::signaling::v1::TurnCredentials;

pub(crate) fn generate_turn_credentials(user_id: &str, secret: &str, ttl: u64) -> TurnCredentials {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + ttl;
    let username = format!("{}:{}", expiry, user_id);

    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let turn_host = env::var("TURN_HOST").unwrap_or_else(|_| "turn.konstruct.cc".into());

    TurnCredentials {
        urls: vec![
            format!("turn:{}:3478?transport=udp", turn_host),
            format!("turn:{}:3478?transport=tcp", turn_host),
            format!("turns:{}:5349?transport=tcp", turn_host),
        ],
        username,
        credential,
        expires_at: (expiry * 1000) as i64,
    }
}
