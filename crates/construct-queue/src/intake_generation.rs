// The generation of an account's intake key (decisions/intake-key-is-the-accounts-not-the-devices.md).
//
// Written by messaging-service (`PublishIntakeTags`), deleted by identity-service when the account
// is. Both name the key through this function, so the two cannot drift into two keyspaces.

use sha2::{Digest, Sha256};

/// Redis key holding the highest intake-key generation an account has published.
///
/// Hashed, like the tag keys, so a keyspace scan is not a user list. It has **no TTL**: the
/// generation has to be monotonic for the life of the account. If it lapsed, an account restored
/// after a quiet spell would read 0, mint generation 1, and every contact still holding 5 would
/// keep 5 (a card only replaces a key with a higher generation) — envelopes refused as stale,
/// day after day, for good. Four bytes per account that has published, removed with the account.
pub fn intake_generation_key(account_user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(account_user_id.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|generation");
    format!("intake:gen:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_per_account_normalised_and_does_not_leak_it() {
        let key = intake_generation_key("ABCDEF00-0000-0000-0000-000000000000");
        assert_eq!(
            key,
            intake_generation_key(" abcdef00-0000-0000-0000-000000000000 ")
        );
        assert_ne!(
            key,
            intake_generation_key("abcdef00-0000-0000-0000-000000000001")
        );
        assert!(!key.contains("abcdef00"));
    }
}
