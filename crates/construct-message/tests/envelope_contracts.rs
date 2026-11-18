use construct_message::{MessageEnvelope, MessageType, types::ProtoEnvelopeContext};
use serde::{Deserialize, Deserializer, de::Visitor};
use serde_json::json;

const CIPHERTEXT: &[u8] = b"\0\xff\x80cipher";
const SEALED: &[u8] = b"\x80\0\xfesealed";

fn proto_context(content_type: i32) -> ProtoEnvelopeContext {
    ProtoEnvelopeContext {
        message_id: "msg-1".into(),
        sender_id: "alice".into(),
        recipient_id: "bob".into(),
        encrypted_payload: CIPHERTEXT.to_vec(),
        content_type,
        recipient_device: Some("device-1".into()),
    }
}

// A dual reader would also accept str or an array. Inspect the writer with an
// independent, bin-only reader so even a compatible wire type regression fails.
#[derive(Debug, PartialEq)]
struct Bin<'a>(&'a [u8]);

impl<'de: 'a, 'a> Deserialize<'de> for Bin<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BinVisitor;

        impl<'de> Visitor<'de> for BinVisitor {
            type Value = Bin<'de>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("MessagePack bin")
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                bytes: &'de [u8],
            ) -> Result<Self::Value, E> {
                Ok(Bin(bytes))
            }
        }

        deserializer.deserialize_any(BinVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredPayloads<'a> {
    #[serde(borrow)]
    encrypted_payload: Bin<'a>,
    #[serde(borrow)]
    sealed_inner: Option<Bin<'a>>,
}

#[test]
fn mailbox_writer_uses_bin_and_does_not_duplicate_the_sealed_payload() {
    let direct = MessageEnvelope::from_proto_envelope(&proto_context(0));
    let sealed =
        MessageEnvelope::from_sealed_sender("msg-2".into(), "bob".into(), None, SEALED.to_vec());

    for (env, payload, sealed_inner) in [
        (direct, CIPHERTEXT, None),
        (sealed, b"".as_slice(), Some(SEALED)),
    ] {
        let bytes = rmp_serde::to_vec_named(&env).expect("serialize mailbox envelope");
        let fields: StoredPayloads<'_> =
            rmp_serde::from_slice(&bytes).expect("payload fields must use bin");
        assert_eq!(fields.encrypted_payload, Bin(payload));
        assert_eq!(fields.sealed_inner, sealed_inner.map(Bin));

        let restored: MessageEnvelope =
            rmp_serde::from_slice(&bytes).expect("read mailbox envelope");
        assert_eq!(restored.message_id, env.message_id);
        assert_eq!(restored.encrypted_payload, payload);
        assert_eq!(restored.sealed_inner.as_deref(), sealed_inner);
    }
}

fn json_envelope(payload: serde_json::Value) -> serde_json::Value {
    json!({
        "messageId": "old-msg",
        "senderId": "alice",
        "recipientId": "bob",
        "timestamp": 1_700_000_000,
        "messageType": "directMessage",
        "encryptedPayload": payload,
        "contentHash": "fixture"
    })
}

#[test]
fn owned_legacy_json_strings_keep_base64_bytes_and_plain_labels() {
    let mut wire = json_envelope(json!("SESSION_RESET"));
    wire["sealedInnerB64"] = json!("AP+A");

    // from_value hands off owned strings; from_str exercises the borrowed path.
    let env: MessageEnvelope = serde_json::from_value(wire).expect("legacy JSON object");
    assert_eq!(env.message_id, "old-msg");
    assert_eq!(env.encrypted_payload, b"SESSION_RESET");
    assert_eq!(env.sealed_inner.as_deref(), Some(&[0, 255, 128][..]));
}

#[test]
fn json_byte_arrays_distinguish_present_empty_and_null() {
    for (field, expected) in [
        (json!([128, 0, 254]), Some(&[128, 0, 254][..])),
        (json!([]), Some(&[][..])),
        (serde_json::Value::Null, None),
    ] {
        let mut wire = json_envelope(json!([0, 255, 128]));
        wire["sealedInner"] = field;
        let env: MessageEnvelope =
            serde_json::from_str(&wire.to_string()).expect("JSON byte fields");
        assert_eq!(env.encrypted_payload, [0, 255, 128]);
        assert_eq!(env.sealed_inner.as_deref(), expected);
    }
}

#[test]
fn empty_direct_payload_is_refused_but_no_duplicate_is_required_for_sealed() {
    let mut direct = MessageEnvelope::from_proto_envelope(&proto_context(0));
    direct.validate().expect("valid direct envelope");
    direct.encrypted_payload.clear();
    assert_eq!(
        direct
            .validate()
            .expect_err("empty direct payload")
            .to_string(),
        "encrypted_payload is required"
    );

    let mut sealed =
        MessageEnvelope::from_sealed_sender("msg-2".into(), "bob".into(), None, SEALED.to_vec());
    assert!(sealed.sender_id.is_empty());
    assert!(sealed.encrypted_payload.is_empty());
    sealed.validate().expect("opaque sealed_inner suffices");
    sealed.sealed_inner = None;
    assert_eq!(
        sealed
            .validate()
            .expect_err("missing sealed_inner")
            .to_string(),
        "sealed_inner required for SealedSender"
    );
}

#[test]
fn control_labels_do_not_turn_ciphertext_content_types_into_controls() {
    // Values are from construct-protos/core/envelope.proto. Retired types are
    // checked for compatibility, not reintroduced as new sends.
    for (content_type, message_type, payload) in [
        (21, MessageType::ControlMessage, b"SESSION_RESET".as_slice()),
        (22, MessageType::ControlMessage, b"KEY_SYNC".as_slice()),
        (23, MessageType::DirectMessage, CIPHERTEXT), // SENDER_SYNC
        (24, MessageType::DirectMessage, CIPHERTEXT), // SESSION_RESET_INIT
    ] {
        let env = MessageEnvelope::from_proto_envelope(&proto_context(content_type));
        assert_eq!(
            env.message_type, message_type,
            "content_type {content_type}"
        );
        assert_eq!(
            env.encrypted_payload, payload,
            "content_type {content_type}"
        );
        let stored = rmp_serde::to_vec_named(&env).expect("serialize mailbox envelope");
        let restored: MessageEnvelope =
            rmp_serde::from_slice(&stored).expect("read mailbox envelope");
        assert_eq!(restored.message_type, message_type);
        assert_eq!(restored.proto_content_type, Some(content_type));
        assert_eq!(restored.encrypted_payload, payload);
        assert_eq!(restored.recipient_device.as_deref(), Some("device-1"));
    }
}
