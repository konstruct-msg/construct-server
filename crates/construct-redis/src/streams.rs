//! Redis Streams support

use crate::{RedisClient, Result};
use redis::{AsyncCommands, Value, streams::StreamReadReply};
use std::collections::HashMap;

/// Entry in a Redis Stream (string values)
#[derive(Debug, Clone)]
pub struct StreamEntry {
    pub id: String,
    pub fields: HashMap<String, String>,
}

/// Entry in a Redis Stream (binary values)
/// Used for MessagePack and other binary serialization formats
#[derive(Debug, Clone)]
pub struct StreamEntryBinary {
    pub id: String,
    pub fields: HashMap<String, Vec<u8>>,
}

/// One source in a binary XREAD reply. Redis omits sources with no entries, so callers
/// merging multiple streams must use `key`, never the position in the reply.
#[derive(Debug, Clone)]
pub struct StreamReadBinary {
    pub key: String,
    pub entries: Vec<StreamEntryBinary>,
}

fn binary_stream_reply(reply: StreamReadReply) -> Vec<StreamReadBinary> {
    reply
        .keys
        .into_iter()
        .map(|stream| StreamReadBinary {
            key: stream.key,
            entries: stream
                .ids
                .into_iter()
                .map(|entry| StreamEntryBinary {
                    id: entry.id,
                    fields: entry
                        .map
                        .into_iter()
                        .filter_map(|(key, value)| {
                            let bytes = match value {
                                Value::BulkString(bytes) => bytes,
                                Value::SimpleString(s) => s.into_bytes(),
                                Value::Int(i) => i.to_string().into_bytes(),
                                _ => return None,
                            };
                            Some((key, bytes))
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect()
}

/// Options for XREAD command
#[derive(Debug, Clone, Default)]
pub struct StreamReadOptions {
    /// Block for N milliseconds (None = no blocking)
    pub block: Option<u64>,
    /// Maximum number of entries to return per stream
    pub count: Option<u64>,
}

impl RedisClient {
    // ============================================================================
    // Stream Operations
    // ============================================================================

    /// XADD - Add entry to stream
    ///
    /// Returns the generated ID
    pub async fn xadd<K, F>(&mut self, stream_key: K, id: &str, fields: &[(F, F)]) -> Result<String>
    where
        K: redis::ToRedisArgs + Send + Sync,
        F: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xadd(stream_key, id, fields).await
    }

    /// XREAD - Read from one or more streams (string values)
    ///
    /// `streams` is a list of (key, id) pairs
    pub async fn xread(
        &mut self,
        streams: &[(&str, &str)],
        options: StreamReadOptions,
    ) -> Result<Vec<StreamEntry>> {
        let mut cmd = redis::cmd("XREAD");

        // Add options
        if let Some(count) = options.count {
            cmd.arg("COUNT").arg(count);
        }
        if let Some(block_ms) = options.block {
            cmd.arg("BLOCK").arg(block_ms);
        }

        // Add STREAMS keyword
        cmd.arg("STREAMS");

        // Add stream keys
        for (key, _) in streams {
            cmd.arg(*key);
        }

        // Add IDs
        for (_, id) in streams {
            cmd.arg(*id);
        }

        // Execute
        let reply: StreamReadReply = cmd.query_async(self.connection_mut()).await?;

        // Convert to simplified format
        let mut entries = Vec::new();
        for stream_key in reply.keys {
            for stream_id in stream_key.ids {
                let mut fields = HashMap::new();

                // Parse field map
                for (key, value) in stream_id.map.iter() {
                    // Keys are Strings, values are redis::Value
                    let value_str = match value {
                        Value::BulkString(bytes) => String::from_utf8_lossy(bytes).to_string(),
                        Value::SimpleString(s) => s.clone(),
                        Value::Int(i) => i.to_string(),
                        _ => continue, // Skip unsupported types
                    };
                    fields.insert(key.clone(), value_str);
                }

                entries.push(StreamEntry {
                    id: stream_id.id,
                    fields,
                });
            }
        }

        Ok(entries)
    }

    /// XREAD - Read from one or more streams (binary values)
    ///
    /// Returns raw bytes for each field value. Use this for MessagePack and other binary formats.
    ///
    /// `streams` is a list of (key, id) pairs
    pub async fn xread_binary(
        &mut self,
        streams: &[(&str, &str)],
        options: StreamReadOptions,
    ) -> Result<Vec<StreamEntryBinary>> {
        Ok(self
            .xread_binary_grouped(streams, options)
            .await?
            .into_iter()
            .flat_map(|stream| stream.entries)
            .collect())
    }

    /// XREAD with binary fields, retaining the source key and per-source entry order.
    ///
    /// Uses one command with independent offsets and a per-stream COUNT. An empty source
    /// is omitted by Redis; any command error fails the entire read (including WRONGTYPE).
    pub async fn xread_binary_grouped(
        &mut self,
        streams: &[(&str, &str)],
        options: StreamReadOptions,
    ) -> Result<Vec<StreamReadBinary>> {
        let mut cmd = redis::cmd("XREAD");

        // Add options
        if let Some(count) = options.count {
            cmd.arg("COUNT").arg(count);
        }
        if let Some(block_ms) = options.block {
            cmd.arg("BLOCK").arg(block_ms);
        }

        // Add STREAMS keyword
        cmd.arg("STREAMS");

        // Add stream keys
        for (key, _) in streams {
            cmd.arg(*key);
        }

        // Add IDs
        for (_, id) in streams {
            cmd.arg(*id);
        }

        // Execute
        let reply: StreamReadReply = cmd.query_async(self.connection_mut()).await?;

        // Consume the decoded reply: binary payloads already own their buffers.
        Ok(binary_stream_reply(reply))
    }

    /// XRANGE - Read a range of entries from a stream (binary values).
    ///
    /// Use `start = "-"` and `end = "+"` to read all entries.
    /// Returns raw bytes for each field value.
    pub async fn xrange_binary(
        &mut self,
        stream_key: &str,
        start: &str,
        end: &str,
    ) -> Result<Vec<StreamEntryBinary>> {
        use redis::streams::StreamRangeReply;

        let reply: StreamRangeReply = redis::cmd("XRANGE")
            .arg(stream_key)
            .arg(start)
            .arg(end)
            .query_async(self.connection_mut())
            .await?;

        let mut entries = Vec::new();
        for stream_id in reply.ids {
            let mut fields = HashMap::new();
            for (key, value) in stream_id.map.iter() {
                let value_bytes = match value {
                    Value::BulkString(bytes) => bytes.clone(),
                    Value::SimpleString(s) => s.as_bytes().to_vec(),
                    Value::Int(i) => i.to_string().into_bytes(),
                    _ => continue,
                };
                fields.insert(key.clone(), value_bytes);
            }
            entries.push(StreamEntryBinary {
                id: stream_id.id,
                fields,
            });
        }
        Ok(entries)
    }

    /// XDEL - Delete stream entries
    pub async fn xdel<K, ID>(&mut self, stream_key: K, ids: &[ID]) -> Result<i64>
    where
        K: redis::ToRedisArgs + redis::ToSingleRedisArg + Send + Sync,
        ID: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xdel(stream_key, ids).await
    }

    /// XLEN - Get stream length
    pub async fn xlen<K>(&mut self, stream_key: K) -> Result<i64>
    where
        K: redis::ToRedisArgs + Send + Sync,
    {
        self.connection_mut().xlen(stream_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_binary_reply_retains_sources_and_moves_payload_buffers() {
        use redis::streams::{StreamId, StreamKey};
        let bytes = vec![0, 255, 128, 7];
        let ptr = bytes.as_ptr();
        let reply = StreamReadReply {
            keys: vec![
                StreamKey {
                    key: "second-source".into(),
                    ids: vec![StreamId {
                        id: "100-0".into(),
                        map: HashMap::from([
                            ("payload".into(), Value::BulkString(bytes)),
                            ("simple".into(), Value::SimpleString("hello".into())),
                            ("integer".into(), Value::Int(42)),
                            ("unsupported".into(), Value::Nil),
                        ]),
                        ..Default::default()
                    }],
                },
                StreamKey {
                    key: "first-source".into(),
                    ids: Vec::new(),
                },
            ],
        };
        let grouped = binary_stream_reply(reply);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].key, "second-source");
        assert_eq!(grouped[1].key, "first-source");
        assert!(grouped[1].entries.is_empty());
        let fields = &grouped[0].entries[0].fields;
        assert_eq!(fields["payload"], [0, 255, 128, 7]);
        assert_eq!(
            fields["payload"].as_ptr(),
            ptr,
            "decoded payload must move, not clone"
        );
        assert_eq!(fields["simple"], b"hello");
        assert_eq!(fields["integer"], b"42");
        assert!(!fields.contains_key("unsupported"));
        assert!(binary_stream_reply(StreamReadReply { keys: Vec::new() }).is_empty());
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn grouped_binary_read_keeps_independent_offsets_and_per_source_count() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;
        let keys: Vec<_> = (0..3)
            .map(|i| format!("test_binary_grouped_{}:{i}", std::process::id()))
            .collect();
        client.del(&keys).await?;
        for key in &keys[..2] {
            for id in ["100-0", "200-0", "300-0"] {
                let _: String = client
                    .connection_mut()
                    .xadd(key, id, &[("payload", &[0u8, 255, 128][..])])
                    .await?;
            }
        }
        let requested = [
            (&keys[2][..], "0"),
            (&keys[1][..], "200-0"),
            (&keys[0][..], "100-0"),
        ];
        let grouped = client
            .xread_binary_grouped(
                &requested,
                StreamReadOptions {
                    block: None,
                    count: Some(1),
                },
            )
            .await?;
        assert_eq!(grouped.len(), 2, "missing source is omitted");
        assert_eq!(grouped[0].key, keys[1]);
        assert_eq!(grouped[0].entries[0].id, "300-0");
        assert_eq!(grouped[1].key, keys[0]);
        assert_eq!(grouped[1].entries[0].id, "200-0");
        for group in &grouped {
            assert_eq!(group.entries.len(), 1, "COUNT applies to each source");
            assert_eq!(group.entries[0].fields["payload"], [0, 255, 128]);
        }
        let flattened = client
            .xread_binary(
                &requested,
                StreamReadOptions {
                    block: None,
                    count: Some(1),
                },
            )
            .await?;
        assert_eq!(
            flattened.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["300-0", "200-0"]
        );
        client.del(&keys).await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_stream_operations() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;

        let stream_key = "test_stream";

        // XADD
        let id1 = client
            .xadd(
                stream_key,
                "*",
                &[("field1", "value1"), ("field2", "value2")],
            )
            .await?;
        assert!(!id1.is_empty());

        // XLEN
        let len = client.xlen(stream_key).await?;
        assert_eq!(len, 1);

        // XREAD
        let entries = client
            .xread(&[(stream_key, "0")], StreamReadOptions::default())
            .await?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fields.get("field1"), Some(&"value1".to_string()));

        // XDEL
        client.xdel(stream_key, &[&id1]).await?;

        // Clean up
        client.del(stream_key).await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_binary_stream_operations() -> Result<()> {
        use redis::AsyncCommands;

        let mut client = RedisClient::connect("redis://localhost:6379").await?;

        let stream_key = "test_binary_stream";

        // Add binary data using low-level xadd (need to use connection_mut for binary)
        let binary_data = vec![0x01, 0x02, 0x03, 0xDE, 0xAD, 0xBE, 0xEF];
        let id1: String = client
            .connection_mut()
            .xadd(stream_key, "*", &[("data", binary_data.as_slice())])
            .await?;
        assert!(!id1.is_empty());

        // Read as binary
        let entries = client
            .xread_binary(&[(stream_key, "0")], StreamReadOptions::default())
            .await?;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fields.get("data"), Some(&binary_data));

        // Clean up
        client.del(stream_key).await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_binary_messagepack() -> Result<()> {
        use redis::AsyncCommands;
        use rmp_serde;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestMessage {
            user_id: String,
            content: String,
            timestamp: u64,
        }

        let mut client = RedisClient::connect("redis://localhost:6379").await?;
        let stream_key = "test_msgpack_stream";

        // Serialize with MessagePack
        let msg = TestMessage {
            user_id: "user123".to_string(),
            content: "Hello, World!".to_string(),
            timestamp: 1234567890,
        };
        let packed = rmp_serde::to_vec(&msg).expect("MessagePack serialize failed");

        // Add to stream using connection_mut for binary data
        let id: String = client
            .connection_mut()
            .xadd(stream_key, "*", &[("message", packed.as_slice())])
            .await?;
        assert!(!id.is_empty());

        // Read as binary
        let entries = client
            .xread_binary(&[(stream_key, "0")], StreamReadOptions::default())
            .await?;

        assert_eq!(entries.len(), 1);
        let received_data = entries[0].fields.get("message").expect("No message field");

        // Deserialize
        let received_msg: TestMessage =
            rmp_serde::from_slice(received_data).expect("MessagePack deserialize failed");

        assert_eq!(received_msg, msg);

        // Clean up
        client.del(stream_key).await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_stream_blocking_read() -> Result<()> {
        let mut client = RedisClient::connect("redis://localhost:6379").await?;
        let stream_key = "test_blocking_stream";

        // Add entry
        client.xadd(stream_key, "*", &[("field", "value")]).await?;

        // Blocking read with timeout
        let entries = client
            .xread(
                &[(stream_key, "0")],
                StreamReadOptions {
                    block: Some(1000), // 1 second
                    count: Some(10),
                },
            )
            .await?;

        assert_eq!(entries.len(), 1);

        // Clean up
        client.del(stream_key).await?;

        Ok(())
    }
}
