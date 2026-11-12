// ============================================================================
// Message Delivery Operations
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis for clean architecture

use anyhow::{Context, Result};
use construct_config::{Config, SECONDS_PER_DAY};
use construct_redis::{RedisClient, StreamReadOptions};
use std::{borrow::Cow, collections::HashMap};

type MailboxEntries = Vec<(String, Option<construct_message::types::MessageEnvelope>)>;

/// What one fan-out actually wrote, and whether the recipient was live when it ran.
///
/// Counts are of writes that **landed**, not of writes attempted: the caller's "nowhere to land"
/// decision (no user stream, no device stream) turns on at least one mailbox holding the message,
/// and a count of attempts would call a refused write a delivery.
pub struct MailboxWrites {
    /// The legacy user-stream write, when it was made at all.
    pub user_stream: Option<bool>,
    /// Device-stream writes that landed.
    pub device_streams: usize,
    /// Whether a `MessageStream` held this user when the fan-out ran. Read in the same pipeline, so
    /// it is observed after the writes rather than racing them.
    pub recipient_online: bool,
}

struct MailboxWriteKeys<'a> {
    user: &'a str,
    presence: &'a str,
    wakeup: &'a str,
}

/// The same RESP commands, with capacity derived from their actual bytes. Each XADD must own
/// its wire arguments, but temporary key buffers need not be retained per destination.
fn mailbox_write_pipeline(
    keys: MailboxWriteKeys<'_>,
    device_ids: &[String],
    write_user: bool,
    max_len: i64,
    message_id: &str,
    payload: &[u8],
) -> redis::Pipeline {
    let mut pipe = redis::Pipeline::with_capacity(usize::from(write_user) + device_ids.len() + 2);
    pipe.ignore_errors();
    let xadd = |pipe: &mut redis::Pipeline, key: &str| {
        // Ten arguments: 29 fixed bytes plus at most 20 bytes for an i64 MAXLEN.
        let mut cmd =
            redis::Cmd::with_capacity(10, key.len() + message_id.len() + payload.len() + 49);
        cmd.arg("XADD")
            .arg(key)
            .arg("MAXLEN")
            .arg("~")
            .arg(max_len)
            .arg("*")
            .arg("message_id")
            .arg(message_id)
            .arg("payload")
            .arg(payload);
        pipe.add_command(cmd);
    };
    if write_user {
        xadd(&mut pipe, keys.user);
    }
    if let Some(max_device_len) = device_ids.iter().map(String::len).max() {
        let mut device_key = String::with_capacity(keys.user.len() + 1 + max_device_len);
        device_key.push_str(keys.user);
        device_key.push(':');
        let base_len = device_key.len();
        for device in device_ids {
            device_key.truncate(base_len);
            device_key.push_str(device);
            xadd(&mut pipe, &device_key);
        }
    }
    pipe.cmd("GET").arg(keys.presence);
    pipe.cmd("PUBLISH").arg(keys.wakeup).arg("1");
    pipe
}

pub(crate) struct DeliveryManager<'a> {
    client: &'a mut RedisClient,
    config: &'a Config,
    delivery_queue_prefix: &'a str,
}

impl<'a> DeliveryManager<'a> {
    pub(crate) fn new(
        client: &'a mut RedisClient,
        config: &'a Config,
        delivery_queue_prefix: &'a str,
    ) -> Self {
        Self {
            client,
            config,
            delivery_queue_prefix,
        }
    }

    /// Approximate MAXLEN for every mailbox XADD. Server retention, not a
    /// per-sender quota — Redis cannot trim "this sender's entries".
    fn mailbox_maxlen(&self) -> i64 {
        self.config.messaging.queue_maxlen_standard.max(1)
    }

    /// Read messages from Redis Stream for a user
    ///
    /// Reads from user-based stream: {delivery_queue_prefix}:offline:{user_id}
    ///
    /// Legacy carrier for device-less readers and the dual-read merge. The stream
    /// belongs to the account; its address does not depend on a server instance.
    pub(crate) async fn read_user_messages_from_stream(
        &mut self,
        user_id: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        // Always read from user-based stream
        let stream_key = format!("{}:offline:{}", self.delivery_queue_prefix, user_id);

        let messages = self
            .read_stream_messages(&stream_key, since_id, count)
            .await?;

        Ok(Self::parse_stream_entries(messages, user_id, None))
    }

    /// Read messages from a Redis Stream using XREAD
    async fn read_stream_messages(
        &mut self,
        stream_key: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, HashMap<String, Vec<u8>>)>> {
        let start_id = Self::stream_start_id(stream_key, since_id);

        // Use construct-redis xread_binary for binary data (MessagePack)
        let options = StreamReadOptions {
            block: None,
            count: Some(count as u64),
        };

        let entries = match self
            .client
            .xread_binary(&[(stream_key, start_id.as_ref())], options)
            .await
        {
            Ok(entries) => entries,
            Err(e) => {
                // Check if it's a "stream doesn't exist" error
                if Self::empty_stream_error(&e) {
                    // Stream doesn't exist or is empty
                    return Ok(vec![]);
                } else {
                    return Err(anyhow::anyhow!("Failed to read stream: {}", e));
                }
            }
        };

        // NOTE: reads are intentionally side-effect free. Mailbox deletion is retention
        // only (XADD MAXLEN ~ + age sweep) — never by the server's read/send position
        // and never by a client-asserted since_cursor (silent-loss class; see
        // construct-docs decisions/minimal-server-delivery.md).

        if entries.is_empty() {
            return Ok(vec![]);
        }

        // Convert StreamEntryBinary to Vec<(String, HashMap<String, Vec<u8>>)>
        let messages: Vec<(String, HashMap<String, Vec<u8>>)> = entries
            .into_iter()
            .map(|entry| (entry.id, entry.fields))
            .collect();

        Ok(messages)
    }

    // `trim_offline_stream` (XTRIM MINID from a client-asserted cursor) was deleted with
    // minimal-server-delivery step 2. It is not "kept for ops": it is the exact operation
    // that produced the 2026-08-18 offline loss, and an unreachable copy of it is a
    // loaded gun that the next reader will assume is safe because it compiles. Mailbox
    // deletion is retention only — `MAXLEN ~` on XADD plus `trim_streams_by_age`.

    /// Validate Redis Stream ID format: {timestamp}-{sequence}
    /// Examples: "0", "1707584371151-0", "1707584371151-42"
    fn is_valid_stream_id(id: &str) -> bool {
        // Special IDs
        if id == "0" || id == "$" || id == "*" {
            return true;
        }

        // Check format: {timestamp}-{sequence}
        let Some((timestamp, sequence)) = id.split_once('-') else {
            return false;
        };
        timestamp.parse::<u64>().is_ok() && sequence.parse::<u64>().is_ok()
    }

    /// Keep the existing cursor normalization, borrowing already-valid offsets.
    pub(crate) fn stream_start_id<'s>(stream_key: &str, since_id: Option<&'s str>) -> Cow<'s, str> {
        let Some(id) = since_id else {
            return Cow::Borrowed("0");
        };
        if Self::is_valid_stream_id(id) {
            return Cow::Borrowed(id);
        }
        if id.parse::<u64>().is_ok() {
            return Cow::Owned(format!("{id}-0"));
        }
        tracing::warn!(
            stream_key = %stream_key, invalid_id = %id,
            "Invalid Redis Stream ID format - expected '{{timestamp}}-{{sequence}}', resetting to '0'"
        );
        Cow::Borrowed("0")
    }

    fn empty_stream_error(error: &redis::RedisError) -> bool {
        let text = error.to_string();
        text.contains("no such key") || text.contains("WRONGTYPE")
    }

    /// Preserve source identity and independent offsets in one nonblocking XREAD. A wrong-type
    /// source used to be empty without hiding the healthy source, so retry separately on that
    /// exceptional path; a multi-stream XREAD cannot report per-source errors.
    pub(crate) async fn read_mailbox_streams(
        &mut self,
        user_id: &str,
        device_id: &str,
        since_id: Option<&str>,
        user_since_id: Option<&str>,
        count: usize,
    ) -> Result<(MailboxEntries, MailboxEntries)> {
        let user_key = format!("{}:offline:{user_id}", self.delivery_queue_prefix);
        let device_key = format!("{user_key}:{device_id}");
        let device_start = Self::stream_start_id(&device_key, since_id);
        let user_start = Self::stream_start_id(&user_key, user_since_id);
        let reply = self
            .client
            .xread_binary_grouped(
                &[
                    (&device_key, device_start.as_ref()),
                    (&user_key, user_start.as_ref()),
                ],
                StreamReadOptions {
                    block: None,
                    count: Some(count as u64),
                },
            )
            .await;
        let streams = match reply {
            Ok(streams) => streams,
            Err(e) if Self::empty_stream_error(&e) => {
                let device = self
                    .read_device_messages_from_stream(
                        user_id,
                        device_id,
                        Some(device_start.as_ref()),
                        count,
                    )
                    .await?;
                let user = self
                    .read_user_messages_from_stream(user_id, Some(user_start.as_ref()), count)
                    .await?;
                return Ok((device, user));
            }
            Err(e) => anyhow::bail!("Failed to read stream: {e}"),
        };
        let (mut device, mut user) = (Vec::new(), Vec::new());
        for stream in streams {
            let (target, device_id) = if stream.key == device_key {
                (&mut device, Some(device_id))
            } else if stream.key == user_key {
                (&mut user, None)
            } else {
                anyhow::bail!("Unexpected source in mailbox XREAD reply");
            };
            *target = Self::parse_stream_entries(
                stream.entries.into_iter().map(|e| (e.id, e.fields)),
                user_id,
                device_id,
            );
        }
        Ok((device, user))
    }

    fn parse_stream_entries(
        entries: impl IntoIterator<Item = (String, HashMap<String, Vec<u8>>)>,
        user_id: &str,
        device_id: Option<&str>,
    ) -> MailboxEntries {
        entries.into_iter().map(|(id, fields)| {
            let envelope = match Self::parse_stream_message(fields, user_id) {
                Ok(envelope) => envelope,
                Err(e) => {
                    if let Some(device_id) = device_id {
                        tracing::debug!(stream_id = %id, user_id, device_id, error = %e,
                            "Skipping unparseable entry in device stream");
                    } else {
                        tracing::warn!(stream_id = %id, user_id, error = %e,
                            "Skipping unparseable Redis stream entry (re-send message or DEL stream if written with broken to_vec)");
                    }
                    None
                }
            };
            (id, envelope)
        }).collect()
    }

    /// Parse stream message fields into MessageEnvelope
    /// Filters by recipient_id to ensure user only gets their messages
    fn parse_stream_message(
        fields: HashMap<String, Vec<u8>>,
        user_id: &str,
    ) -> Result<Option<construct_message::types::MessageEnvelope>> {
        // Extract message_id and payload from fields
        let message_id_bytes = fields
            .get("message_id")
            .ok_or_else(|| anyhow::anyhow!("Missing message_id in stream message"))?;
        std::str::from_utf8(message_id_bytes).context("Invalid UTF-8 in message_id")?;

        let payload = fields
            .get("payload")
            .ok_or_else(|| anyhow::anyhow!("Missing payload in stream message"))?;

        // Deserialize MessageEnvelope from MessagePack
        let envelope: construct_message::types::MessageEnvelope = rmp_serde::from_slice(payload)
            .context("Failed to deserialize MessageEnvelope from stream")?;

        // SECURITY: Filter by recipient_id - only return messages for this user
        if envelope.recipient_id != user_id {
            return Ok(None);
        }

        Ok(Some(envelope))
    }

    /// Record which messaging instance owns this user's live MessageStream.
    /// Read back via `GET user:{user}:server_instance_id` (wake-push skip, not
    /// a delivery-worker hop — that worker is gone).
    pub(crate) async fn track_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<()> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        // Set with TTL matching session TTL from config
        let ttl_seconds = self.config.session_ttl_days * SECONDS_PER_DAY;

        self.client
            .set_ex(&key, server_instance_id, ttl_seconds as u64)
            .await?;

        tracing::debug!(
            user_id = %user_id,
            server_instance_id = %server_instance_id,
            "Tracked user online status"
        );

        Ok(())
    }

    /// Phase 5: Remove user online tracking when they disconnect
    pub(crate) async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        self.client.del(&key).await?;

        tracing::debug!(
            user_id = %user_id,
            "Removed user online tracking"
        );

        Ok(())
    }

    /// Phase 5: Get server instance ID for an online user
    pub(crate) async fn get_user_server_instance(
        &mut self,
        user_id: &str,
    ) -> Result<Option<String>> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        let result: Option<String> = self.client.get(&key).await?;
        Ok(result)
    }

    /// Write one envelope to every mailbox the recipient has, in one round trip.
    ///
    /// ── Why one round trip ──────────────────────────────────────────────────────────
    /// The mailbox fan-out is the last thing a send does before it answers, and it used to be
    /// 1 + d commands, each awaited: one per device, one for the legacy user stream, then a `GET`
    /// for presence and a `PUBLISH` for the wakeup. On a three-device account that is five round
    /// trips on the send path; every one of them is pushed into a pipeline here, so the client
    /// makes one.
    ///
    /// The payload is encoded **once**. It is the same bytes in every mailbox, and encoding it per
    /// stream was the same envelope serialized 1 + d times for one message.
    ///
    /// ── What must not change ────────────────────────────────────────────────────────
    /// - **Order.** Redis executes a pipeline in the order it was sent, so every `XADD` still
    ///   lands before the `inbox:wakeup` publish. That ordering is the whole point of the wakeup:
    ///   publishing first let a live `MessageStream` poll an empty mailbox (2026-09-18).
    /// - **One device's failure is that device's loss.** `ignore_errors` turns each command's
    ///   error into a value instead of failing the batch, so a stream key of the wrong type costs
    ///   its own copy and nothing else — the other mailboxes still get theirs, and the caller gets
    ///   the count of writes that landed to make its "nowhere to land" decision on.
    /// - **Presence is read after the writes, as before**, from the same pipeline: the flag a live
    ///   stream sets is what the push decision turns on, and it is no longer a separate trip.
    ///
    /// The count of landed writes, not of attempted ones: see [`MailboxWrites`].
    pub(crate) async fn write_message_to_mailboxes(
        &mut self,
        user_id: &str,
        device_ids: &[String],
        write_user: bool,
        envelope: &construct_message::types::MessageEnvelope,
    ) -> Result<MailboxWrites> {
        // Serialize once: must match the XREAD path (`to_vec_named`). `rmp_serde::to_vec` uses a
        // legacy serializer that `from_slice` cannot read back ("wrong msgpack marker Str8") —
        // messages would be written but never delivered.
        let payload = rmp_serde::encode::to_vec_named(envelope)
            .context("Failed to serialize MessageEnvelope to MessagePack")?;

        // Recipient-stream retention — one cap for every writer. Sender trust must never feed
        // MAXLEN: Redis trims the whole inbox, not "this sender's entries". New-account volume is
        // hourly_limit_*, not a smaller MAXLEN on someone else's mailbox.
        let max_len = self.mailbox_maxlen();
        let user_stream_key = format!("{}:offline:{}", self.delivery_queue_prefix, user_id);
        let presence_key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        let wakeup_channel = format!("inbox:wakeup:{}", user_id);

        let pipe = mailbox_write_pipeline(
            MailboxWriteKeys {
                user: &user_stream_key,
                presence: &presence_key,
                wakeup: &wakeup_channel,
            },
            device_ids,
            write_user,
            max_len,
            &envelope.message_id,
            &payload,
        );
        // Cmd owns its argument bytes; the serialized source is no longer needed across await.
        drop(payload);
        // User first when enabled, then devices in caller order, then presence and wakeup.
        let user_slot = write_user.then_some(0usize);
        let first_device_slot = usize::from(write_user);
        let presence_slot = first_device_slot + device_ids.len();

        let replies: Vec<redis::Value> = pipe
            .query_async(self.client.connection_mut())
            .await
            .context("Failed to write the message to its mailboxes")?;

        // A reply that is an error, or is missing, is a write that did not land.
        let landed = |slot: usize| match replies.get(slot) {
            Some(redis::Value::ServerError(e)) => {
                // Reconstruct a mailbox name only on failure, not into a retained Vec per send.
                let stream_key = if user_slot == Some(slot) {
                    Cow::Borrowed(user_stream_key.as_str())
                } else if let Some(device) = slot
                    .checked_sub(first_device_slot)
                    .and_then(|i| device_ids.get(i))
                {
                    Cow::Owned(format!("{user_stream_key}:{device}"))
                } else {
                    Cow::Borrowed("")
                };
                tracing::warn!(
                    error = %e,
                    user_id = %user_id,
                    stream_key = %stream_key,
                    "Failed to write to a mailbox stream — the other copies are unaffected"
                );
                false
            }
            Some(_) => true,
            None => false,
        };

        let user_stream = user_slot.map(landed);
        let device_streams = (first_device_slot..presence_slot)
            .filter(|slot| landed(*slot))
            .count();

        // Presence: any answer that is not nil and not an error means a stream holds this user.
        // A failed read is offline, as it was before — fail-open, the wake push is still sent.
        let recipient_online = match replies.get(presence_slot) {
            Some(redis::Value::Nil) | None => false,
            Some(redis::Value::ServerError(e)) => {
                tracing::debug!(
                    error = %e,
                    user_id = %user_id,
                    "Failed to check recipient online status — will send wake push"
                );
                false
            }
            Some(_) => true,
        };

        // The stream id of the user-stream write is the only thing that ties a dispatched message
        // to a position a later read can be checked against (2026-08-18: two messages were
        // "dispatched", no entry could be found eleven seconds later, and deciding whether they had
        // ever been written took hours because this line had been filtered out in production).
        if let Some(redis::Value::BulkString(id)) = user_slot.and_then(|slot| replies.get(slot)) {
            tracing::info!(
                stream_key = %user_stream_key,
                message_id = %envelope.message_id,
                stream_id = %String::from_utf8_lossy(id),
                "Wrote message to offline stream"
            );
        }
        tracing::debug!(
            user_id = %user_id,
            message_id = %envelope.message_id,
            device_streams,
            devices = device_ids.len(),
            "Wrote message to per-device streams"
        );

        Ok(MailboxWrites {
            user_stream,
            device_streams,
            recipient_online,
        })
    }

    /// Read messages from a per-device Redis stream.
    ///
    /// Reads from: {delivery_queue_prefix}:offline:{user_id}:{device_id}
    /// Used by multi-device-aware clients that pass `x-device-id`.
    pub(crate) async fn read_device_messages_from_stream(
        &mut self,
        user_id: &str,
        device_id: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        let stream_key = format!(
            "{}:offline:{}:{}",
            self.delivery_queue_prefix, user_id, device_id
        );

        let messages = self
            .read_stream_messages(&stream_key, since_id, count)
            .await?;

        Ok(Self::parse_stream_entries(
            messages,
            user_id,
            Some(device_id),
        ))
    }

    // ── Message deduplication ────────────────────────────────────────────────

    /// Mark the scoped delivery as dispatched to prevent duplicate delivery.
    /// TTL 24h — covers any realistic client retry window.
    pub(crate) async fn mark_message_dispatched(
        &mut self,
        key: &crate::MessageDedupKey,
    ) -> Result<()> {
        const TTL_SECS: u64 = 24 * 60 * 60;
        self.client
            .set_ex(key.as_str(), "1", TTL_SECS)
            .await
            .context("Failed to mark message as dispatched")?;
        Ok(())
    }

    /// Delete `user_id`'s user stream and every `{user_id}:{device}` stream.
    /// Returns the number of keys removed.
    pub(crate) async fn delete_mailbox(&mut self, user_id: &str) -> Result<u64> {
        let mut keys = vec![format!(
            "{}:offline:{}",
            self.delivery_queue_prefix, user_id
        )];
        let pattern = format!("{}:offline:{}:*", self.delivery_queue_prefix, user_id);
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, found): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(self.client.connection_mut())
                .await
                .context("SCAN failed during delete_mailbox")?;
            keys.extend(found);
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        let deleted: u64 = redis::cmd("DEL")
            .arg(&keys)
            .query_async(self.client.connection_mut())
            .await
            .context("DEL failed during delete_mailbox")?;
        Ok(deleted)
    }

    /// Trim all offline message streams to remove entries older than `max_age_seconds`.
    ///
    /// Uses Redis SCAN to find all stream keys matching the offline queue pattern,
    /// then applies XTRIM MINID for time-based expiry.
    /// This is O(N) over total message count — run periodically (e.g., every 1 hour).
    pub(crate) async fn trim_streams_by_age(&mut self, max_age_seconds: u64) -> Result<u64> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let cutoff_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_millis()
            .saturating_sub(max_age_seconds as u128 * 1000) as u64;

        // MINID format: "{milliseconds_timestamp}-0"
        let minid = format!("{}-0", cutoff_ms);
        let pattern = format!("{}:offline:*", self.delivery_queue_prefix);

        let mut cursor: u64 = 0;
        let mut total_trimmed: u64 = 0;

        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(self.client.connection_mut())
                .await
                .context("SCAN failed")?;

            for key in keys {
                // The newest entry this trim removes, read first: XTRIM does not move the
                // stream's `max-deleted-entry-id` (only XDEL does), and that mark is how a
                // reader learns it lost messages (`mailbox_gap`).
                let newest_removed: Option<String> = redis::cmd("XREVRANGE")
                    .arg(&key)
                    .arg(format!("({minid}"))
                    .arg("-")
                    .arg("COUNT")
                    .arg(1u64)
                    .query_async::<redis::Value>(self.client.connection_mut())
                    .await
                    .ok()
                    .and_then(|v| crate::gap::first_entry_id(&v));
                let trimmed: i64 = redis::cmd("XTRIM")
                    .arg(&key)
                    .arg("MINID")
                    .arg(&minid)
                    .query_async(self.client.connection_mut())
                    .await
                    .unwrap_or(0);
                total_trimmed += trimmed as u64;
                if trimmed > 0
                    && let Some(removed) = newest_removed
                    && let Err(e) = self.record_deleted(&key, &removed).await
                {
                    tracing::warn!(error = %e, "mailbox trim not recorded — a gap there goes unreported");
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(total_trimmed)
    }

    /// Raise the stream's `max-deleted-entry-id` to `removed` (never lower it) with `XSETID`,
    /// which needs the current last id: read just before, retried once if an XADD landed between.
    async fn record_deleted(&mut self, key: &str, removed: &str) -> Result<()> {
        for _ in 0..2 {
            let info: redis::Value = redis::cmd("XINFO")
                .arg("STREAM")
                .arg(key)
                .query_async(self.client.connection_mut())
                .await
                .context("XINFO STREAM failed")?;
            let stream = crate::gap::parse_xinfo_stream(&info);
            let Some(last) = stream.last_generated else {
                return Ok(());
            };
            let already = stream
                .max_deleted
                .as_deref()
                .and_then(crate::gap::stream_id);
            if already >= crate::gap::stream_id(removed) {
                return Ok(());
            }
            let set: redis::RedisResult<()> = redis::cmd("XSETID")
                .arg(key)
                .arg(&last)
                .arg("MAXDELETEDID")
                .arg(removed)
                .query_async(self.client.connection_mut())
                .await;
            if set.is_ok() {
                return Ok(());
            }
        }
        anyhow::bail!("XSETID did not take")
    }

    /// Purge all messages from `sender_id` out of `recipient_id`'s Redis streams.
    ///
    /// Scans the user-level stream and all per-device streams for `recipient_id`,
    /// deserialises each MessagePack payload, and XDEL entries where the envelope
    /// `sender_id` matches.  Sealed-sender entries (empty `sender_id`) are skipped.
    ///
    /// Returns the total number of entries deleted.
    pub(crate) async fn purge_messages_from_sender(
        &mut self,
        recipient_id: &str,
        sender_id: &str,
    ) -> Result<u64> {
        let mut total: u64 = 0;

        // 1. User-level stream: {prefix}:offline:{recipient_id}
        let user_key = format!("{}:offline:{}", self.delivery_queue_prefix, recipient_id);
        total += self
            .purge_sender_from_one_stream(&user_key, sender_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(stream_key = %user_key, error = %e, "purge_messages_from_sender: failed on user stream");
                0
            });

        // 2. Per-device streams: {prefix}:offline:{recipient_id}:*
        let pattern = format!("{}:offline:{}:*", self.delivery_queue_prefix, recipient_id);
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(self.client.connection_mut())
                .await
                .context("SCAN failed during purge_messages_from_sender")?;

            for key in keys {
                total += self
                    .purge_sender_from_one_stream(&key, sender_id)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::warn!(stream_key = %key, error = %e, "purge_messages_from_sender: failed on device stream");
                        0
                    });
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(total)
    }

    /// Scan a single stream and XDEL all entries whose `payload` decodes to an
    /// envelope with `sender_id` matching `target_sender_id`.
    async fn purge_sender_from_one_stream(
        &mut self,
        stream_key: &str,
        target_sender_id: &str,
    ) -> Result<u64> {
        use construct_message::types::MessageEnvelope;

        let entries = self
            .client
            .xrange_binary(stream_key, "-", "+")
            .await
            .context("XRANGE failed")?;

        if entries.is_empty() {
            return Ok(0);
        }

        let ids_to_delete: Vec<String> = entries
            .into_iter()
            .filter_map(|entry| {
                let payload = entry.fields.get("payload")?;
                let envelope: MessageEnvelope = rmp_serde::from_slice(payload).ok()?;
                // Skip sealed-sender entries — sender is intentionally hidden.
                if envelope.is_sealed_sender || envelope.sender_id.is_empty() {
                    return None;
                }
                if envelope.sender_id == target_sender_id {
                    Some(entry.id)
                } else {
                    None
                }
            })
            .collect();

        if ids_to_delete.is_empty() {
            return Ok(0);
        }

        let count = ids_to_delete.len() as u64;
        let mut cmd = redis::cmd("XDEL");
        cmd.arg(stream_key);
        for id in &ids_to_delete {
            cmd.arg(id.as_str());
        }
        let _: i64 = cmd
            .query_async(self.client.connection_mut())
            .await
            .context("XDEL failed")?;

        tracing::info!(
            stream_key = %stream_key,
            sender_id = %target_sender_id,
            deleted = count,
            "Purged queued messages from blocked sender"
        );
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_message::MessageEnvelope;

    #[test]
    fn reserved_mailbox_pipeline_keeps_the_legacy_resp_bytes() {
        for devices in [
            Vec::<String>::new(),
            vec!["one".into()],
            vec![
                "first".into(),
                "".into(),
                "a-much-longer-device-id".into(),
                "设备".into(),
            ],
        ] {
            for write_user in [true, false] {
                for maxlen in [1, 10_000, i64::MAX] {
                    for payload in [Vec::new(), vec![0, 255, 128], vec![255; 65_536]] {
                        let keys = MailboxWriteKeys {
                            user: "custom:queue:offline:account",
                            presence: "custom:presence:account",
                            wakeup: "inbox:wakeup:account",
                        };
                        let id = "méssage:\0id";
                        let mut legacy = redis::pipe();
                        legacy.ignore_errors();
                        let mut names = Vec::new();
                        if write_user {
                            names.push(keys.user.to_string());
                        }
                        names.extend(
                            devices
                                .iter()
                                .map(|device| format!("{}:{device}", keys.user)),
                        );
                        for name in names {
                            legacy
                                .cmd("XADD")
                                .arg(name)
                                .arg("MAXLEN")
                                .arg("~")
                                .arg(maxlen)
                                .arg("*")
                                .arg("message_id")
                                .arg(id)
                                .arg("payload")
                                .arg(&payload);
                        }
                        legacy.cmd("GET").arg(keys.presence);
                        legacy.cmd("PUBLISH").arg(keys.wakeup).arg("1");
                        let payload_len = payload.len();
                        let planned = mailbox_write_pipeline(
                            keys, &devices, write_user, maxlen, id, &payload,
                        );
                        drop(payload); // The pipeline must own the bytes before the source is freed.
                        assert_eq!(planned.len(), usize::from(write_user) + devices.len() + 2);
                        assert_eq!(
                            planned.get_packed_pipeline(),
                            legacy.get_packed_pipeline(),
                            "user={write_user}, devices={}, payload={}, maxlen={maxlen}",
                            devices.len(),
                            payload_len
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn borrowed_message_id_validation_keeps_the_parser_contract() {
        let mut envelope = MessageEnvelope::new_key_sync("alice".into(), "bob".into());
        envelope.message_id = "envelope-id".into();
        envelope.encrypted_payload = vec![0, 255, 128];
        let payload = rmp_serde::encode::to_vec_named(&envelope).unwrap();
        let fields = |id: &[u8]| {
            HashMap::from([
                ("message_id".into(), id.to_vec()),
                ("payload".into(), payload.clone()),
            ])
        };
        // This field was validated, not used as the E2E/envelope identity. Empty UTF-8 stays valid.
        for id in [b"different-transport-id".as_slice(), b""] {
            let parsed = DeliveryManager::parse_stream_message(fields(id), "bob")
                .unwrap()
                .unwrap();
            assert_eq!(parsed.message_id, "envelope-id");
            assert_eq!(parsed.encrypted_payload, [0, 255, 128]);
        }
        assert!(DeliveryManager::parse_stream_message(fields(&[255]), "bob").is_err());
        assert!(DeliveryManager::parse_stream_message(HashMap::new(), "bob").is_err());
        assert!(
            DeliveryManager::parse_stream_message(
                HashMap::from([("message_id".into(), b"id".to_vec()),]),
                "bob"
            )
            .is_err()
        );
        assert!(
            DeliveryManager::parse_stream_message(
                HashMap::from([
                    ("message_id".into(), b"id".to_vec()),
                    ("payload".into(), vec![255]),
                ]),
                "bob"
            )
            .is_err()
        );
        assert!(
            DeliveryManager::parse_stream_message(fields(b"id"), "someone-else")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn normalized_read_offsets_keep_special_and_invalid_id_behavior() {
        for id in ["0", "$", "*", "100-0", "100-42"] {
            let normalized = DeliveryManager::stream_start_id("mailbox", Some(id));
            assert_eq!(normalized, id);
            assert!(matches!(normalized, Cow::Borrowed(_)));
        }
        assert_eq!(
            DeliveryManager::stream_start_id("mailbox", Some("100")),
            "100-0"
        );
        for invalid in ["", "not-an-id", "1-2-3", "-1", "1-", "18446744073709551616"] {
            assert_eq!(
                DeliveryManager::stream_start_id("mailbox", Some(invalid)),
                "0"
            );
        }
        assert_eq!(DeliveryManager::stream_start_id("mailbox", None), "0");
    }
}
