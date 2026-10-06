use construct_server_shared::shared::proto::services::v1 as proto;

// The server no longer relays a plaintext `DirectReceipt` from the message stream, and no longer
// keeps the `message → sender` map that relay needed. No client sends one: delivery receipts
// travel end-to-end inside the ciphertext (content type 14), where the server cannot read whom
// they answer. With no sender, the map was data the server held for 30 days after delivery
// and nothing read.
//
// Receipt-type envelopes already in a mailbox when this shipped are still converted below,
// so a reader of the stream does not stall on them; nothing writes new ones.

/// Build a MessageStreamResponse::Receipt from a Receipt-type MessageEnvelope.
pub(crate) fn build_receipt_response(
    envelope: &construct_server_shared::message::types::MessageEnvelope,
) -> anyhow::Result<proto::MessageStreamResponse> {
    use construct_server_shared::shared::proto::signaling::v1 as signaling;

    #[derive(serde::Deserialize)]
    struct ReceiptPayload {
        message_ids: Vec<String>,
        status: String,
        timestamp: i64,
    }

    let payload: ReceiptPayload = serde_json::from_slice(&envelope.encrypted_payload)
        .map_err(|e| anyhow::anyhow!("Invalid receipt payload: {}", e))?;

    let status = match payload.status.as_str() {
        "read" => 2i32,
        "failed" => 3i32,
        _ => 1i32, // delivered
    };

    let direct = signaling::DirectReceipt {
        message_ids: payload.message_ids,
        status,
        timestamp: payload.timestamp,
        sender_device_id: String::new(),
        // envelope.sender_id = who sent the receipt (device 1).
        // The original sender (device 2) needs this to know which contact
        // acknowledged their message.
        recipient_user_id: envelope.sender_id.clone(),
    };

    let receipt = signaling::DeliveryReceipt {
        receipt_type: Some(signaling::delivery_receipt::ReceiptType::Direct(direct)),
    };

    Ok(proto::MessageStreamResponse {
        response: Some(proto::message_stream_response::Response::Receipt(receipt)),
        response_id: None,
        stream_cursor: None,
        rate_limit_challenge: None,
        attempt_id: None,
    })
}
