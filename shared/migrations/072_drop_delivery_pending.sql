-- `delivery_pending` mapped a message (by HMAC of its id) to its sender for 30 days, so a
-- plaintext receipt sent on the message stream could be routed back. The server no longer relays
-- those: delivery receipts travel end-to-end inside the ciphertext, and no client sends the
-- plaintext kind. With no reader, the table held a sender id per message for nothing.
--
-- Its Redis twin (`receipt:sender:{message_id}`, 30-day TTL) is no longer written and expires on
-- its own.

DROP TABLE IF EXISTS delivery_pending;
