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
        Self(format!("msg:dedup:v2:{}", hex::encode(hash.finalize())))
    }

    /// Redis key, without plaintext account or device identifiers.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn for_envelope(envelope: &construct_message::MessageEnvelope) -> Self {
        Self::new(
            &envelope.sender_id,
            &envelope.recipient_id,
            envelope.recipient_device.as_deref(),
            &envelope.message_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
