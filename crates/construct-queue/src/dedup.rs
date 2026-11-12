use sha2::{Digest, Sha256};

/// Idempotency for one sender's delivery to one account/device. A client-selected message id
/// is never a reservation for other senders or for the other ciphertext copies of a message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageDedupKey(String);

impl MessageDedupKey {
    /// Hash the existing routing fields with length prefixes so field boundaries are unambiguous.
    /// Empty and absent recipient devices both mean account-wide delivery.
    pub fn new(
        sender_id: &str,
        recipient_id: &str,
        recipient_device: Option<&str>,
        message_id: &str,
    ) -> Self {
        Self(format!(
            "msg:dedup:v2:{}",
            hex::encode(Self::scope_hash(
                sender_id,
                recipient_id,
                recipient_device,
                message_id,
            ))
        ))
    }

    fn scope_hash(
        sender_id: &str,
        recipient_id: &str,
        recipient_device: Option<&str>,
        message_id: &str,
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        for field in [
            sender_id,
            recipient_id,
            recipient_device.unwrap_or(""),
            message_id,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        hash.finalize().into()
    }

    /// Redis key, without plaintext account or device identifiers.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Same scope as the Redis key, without allocating its hex/string carrier for a local merge.
    pub(crate) fn scope_for_envelope(envelope: &construct_message::MessageEnvelope) -> [u8; 32] {
        Self::scope_hash(
            &envelope.sender_id,
            &envelope.recipient_id,
            envelope.recipient_device.as_deref(),
            &envelope.message_id,
        )
    }
}

/// Whether this scoped delivery has a committed marker, without taking the mailbox mutex.
///
/// This is only a retry fast path: callers still mark the delivery after successful mailbox
/// writes. A Redis error is returned so each ingress can retain its existing fail-open policy.
pub async fn is_message_duplicate(
    conn: &mut redis::aio::ConnectionManager,
    key: &MessageDedupKey,
) -> anyhow::Result<bool> {
    Ok(redis::cmd("EXISTS")
        .arg(key.as_str())
        .query_async(conn)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_merge_scope_keeps_the_existing_redis_key_bytes() {
        let mut envelope =
            construct_message::MessageEnvelope::new_key_sync("alice".into(), "bob".into());
        envelope.message_id = "message".into();
        envelope.recipient_device = Some("device".into());
        let scope = MessageDedupKey::scope_for_envelope(&envelope);
        let expected =
            "msg:dedup:v2:974bd5b58e642c745b90e4cefcc5f6ded73447dcc4f043548dce9e4a072ad2aa";
        assert_eq!(format!("msg:dedup:v2:{}", hex::encode(scope)), expected);
        assert_eq!(
            MessageDedupKey::new("alice", "bob", Some("device"), "message").as_str(),
            expected
        );
    }

    #[test]
    fn routing_fields_and_the_message_id_each_separate_deliveries() {
        let key = MessageDedupKey::new("alice", "bob", Some("device"), "message");
        for other in [
            MessageDedupKey::new("eve", "bob", Some("device"), "message"),
            MessageDedupKey::new("alice", "carol", Some("device"), "message"),
            MessageDedupKey::new("alice", "bob", Some("sibling"), "message"),
            MessageDedupKey::new("alice", "bob", None, "message"),
            MessageDedupKey::new("alice", "bob", Some("device"), "another"),
        ] {
            assert_ne!(key, other);
        }
        assert_eq!(
            MessageDedupKey::new("a", "b", None, "m"),
            MessageDedupKey::new("a", "b", Some(""), "m")
        );
        assert_ne!(
            MessageDedupKey::new("a:b", "c", None, "m"),
            MessageDedupKey::new("a", "b:c", None, "m")
        );
        assert_ne!(
            MessageDedupKey::new("ab", "c", None, "m"),
            MessageDedupKey::new("a", "bc", None, "m")
        );
    }
}
