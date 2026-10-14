//! Whether a device's mailbox lost messages it never delivered (construct-docs
//! `decisions/mailbox-gap-is-reported.md`, TODO 79).
//!
//! The queue keeps a mailbox for `MAILBOX_MAX_AGE_DAYS` and up to a count; what it trims after the
//! cursor a client reads from is gone, and until this nothing said so. Redis 7 keeps, per stream,
//! the largest id it ever deleted (`XINFO STREAM` → `max-deleted-entry-id`): when that is newer
//! than the cursor, something after the cursor was removed undelivered.
//!
//! "The cursor is older than the first entry" is not the test: it is true whenever nothing at all
//! arrived after the cursor. Deletions other than trimming (a blocked sender's messages purged)
//! move the mark too — an over-report, never a gap hidden.

/// The interval a mailbox can no longer deliver: from `after_cursor` up to `resumes_at`, the
/// oldest entry still held (empty when none is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxGap {
    pub after_cursor: String,
    pub resumes_at: String,
}

/// A Redis stream id `ms-seq` as a comparable pair; `None` for anything else.
pub fn stream_id(id: &str) -> Option<(u64, u64)> {
    let (ms, seq) = id.split_once('-').unwrap_or((id, "0"));
    Some((ms.parse().ok()?, seq.parse().ok()?))
}

/// The rule, on what `XINFO STREAM` said and the mailbox cap.
///
/// - The largest deleted id is newer than the cursor: the age sweep records what it trims there
///   (`record_deleted`), XDEL moves it itself.
/// - `MAXLEN ~` on XADD trims a full mailbox and records nothing. So a stream at its cap that has
///   lost entries, read from a cursor older than everything it holds, is reported too: it may be
///   an over-report, never a gap hidden.
pub fn mailbox_gap(after: &str, stream: &StreamInfo, cap: u64) -> Option<MailboxGap> {
    let after_id = stream_id(after)?;
    let gap = MailboxGap {
        after_cursor: after.to_string(),
        resumes_at: stream.first_entry.clone().unwrap_or_default(),
    };
    if let Some(deleted) = stream.max_deleted.as_deref().and_then(stream_id)
        && deleted != (0, 0)
        && deleted > after_id
    {
        return Some(gap);
    }
    let lost_some = stream.entries_added > stream.length;
    let at_cap = cap > 0 && stream.length >= cap.saturating_mul(9) / 10;
    let before_all = stream
        .first_entry
        .as_deref()
        .and_then(stream_id)
        .is_none_or(|first| first > after_id);
    (lost_some && at_cap && before_all).then_some(gap)
}

/// What `XINFO STREAM` says that the rule reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    pub max_deleted: Option<String>,
    pub first_entry: Option<String>,
    pub last_generated: Option<String>,
    pub length: u64,
    pub entries_added: u64,
}

/// From an `XINFO STREAM` reply, in either protocol's shape (a flat field/value array in RESP2, a
/// map in RESP3).
pub fn parse_xinfo_stream(reply: &redis::Value) -> StreamInfo {
    let pairs: Vec<(&redis::Value, &redis::Value)> = match reply {
        redis::Value::Array(items) => items
            .chunks(2)
            .filter_map(|p| Some((p.first()?, p.get(1)?)))
            .collect(),
        redis::Value::Map(items) => items.iter().map(|(k, v)| (k, v)).collect(),
        _ => Vec::new(),
    };
    let mut info = StreamInfo::default();
    for (key, value) in pairs {
        match text(key).as_deref() {
            Some("max-deleted-entry-id") => info.max_deleted = text(value),
            Some("last-generated-id") => info.last_generated = text(value),
            Some("length") => info.length = int(value),
            Some("entries-added") => info.entries_added = int(value),
            Some("first-entry") => {
                if let redis::Value::Array(entry) = value {
                    info.first_entry = entry.first().and_then(text);
                }
            }
            _ => {}
        }
    }
    info
}

/// The id of the first entry of an `XRANGE`/`XREVRANGE` reply.
pub fn first_entry_id(reply: &redis::Value) -> Option<String> {
    match reply {
        redis::Value::Array(entries) => match entries.first()? {
            redis::Value::Array(entry) => entry.first().and_then(text),
            _ => None,
        },
        _ => None,
    }
}

fn int(value: &redis::Value) -> u64 {
    match value {
        redis::Value::Int(n) => (*n).max(0) as u64,
        other => text(other).and_then(|s| s.parse().ok()).unwrap_or(0),
    }
}

fn text(value: &redis::Value) -> Option<String> {
    match value {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes.clone()).ok(),
        redis::Value::SimpleString(s) => Some(s.clone()),
        redis::Value::VerbatimString { text, .. } => Some(text.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(max_deleted: Option<&str>, first: Option<&str>) -> StreamInfo {
        StreamInfo {
            max_deleted: max_deleted.map(str::to_string),
            first_entry: first.map(str::to_string),
            last_generated: None,
            length: 3,
            entries_added: 3,
        }
    }

    #[test]
    fn a_deletion_after_the_cursor_is_a_gap() {
        let gap = mailbox_gap(
            "1700000000000-0",
            &info(Some("1700000500000-3"), Some("1700000600000-0")),
            10_000,
        );
        assert_eq!(
            gap,
            Some(MailboxGap {
                after_cursor: "1700000000000-0".into(),
                resumes_at: "1700000600000-0".into(),
            })
        );
    }

    /// Nothing arrived after the cursor, or only what was read was removed: no gap, though the
    /// first entry is newer than the cursor.
    #[test]
    fn deletions_up_to_the_cursor_are_not_a_gap() {
        assert_eq!(
            mailbox_gap(
                "1700000500000-3",
                &info(Some("1700000500000-3"), Some("1700000600000-0")),
                10_000
            ),
            None
        );
        assert_eq!(
            mailbox_gap(
                "1700000000000-0",
                &info(Some("0-0"), Some("1700000600000-0")),
                10_000
            ),
            None
        );
        assert_eq!(
            mailbox_gap(
                "1700000000000-0",
                &info(None, Some("1700000600000-0")),
                10_000
            ),
            None
        );
    }

    #[test]
    fn the_sequence_part_decides_within_a_millisecond() {
        assert!(
            mailbox_gap(
                "1700000000000-1",
                &info(Some("1700000000000-2"), None),
                10_000
            )
            .is_some()
        );
        assert!(
            mailbox_gap(
                "1700000000000-2",
                &info(Some("1700000000000-1"), None),
                10_000
            )
            .is_none()
        );
    }

    /// A full mailbox trimmed by `MAXLEN ~`, which records nothing: reported when read from
    /// before everything it holds, not when it never lost anything or is far from its cap.
    #[test]
    fn a_full_mailbox_that_lost_entries_is_reported() {
        let full = StreamInfo {
            length: 9_500,
            entries_added: 12_000,
            first_entry: Some("1700000600000-0".into()),
            ..Default::default()
        };
        assert!(mailbox_gap("1700000000000-0", &full, 10_000).is_some());
        assert!(
            mailbox_gap("1700000700000-0", &full, 10_000).is_none(),
            "read past the first entry: nothing lost"
        );
        let small = StreamInfo {
            length: 40,
            entries_added: 60,
            ..full.clone()
        };
        assert!(mailbox_gap("1700000000000-0", &small, 10_000).is_none());
        let intact = StreamInfo {
            entries_added: 9_500,
            ..full
        };
        assert!(mailbox_gap("1700000000000-0", &intact, 10_000).is_none());
    }

    #[test]
    fn an_unreadable_cursor_says_nothing() {
        assert_eq!(
            mailbox_gap("not-a-cursor", &info(Some("1700000500000-0"), None), 10_000),
            None
        );
    }

    #[test]
    fn both_reply_shapes_are_read() {
        let bulk = |s: &str| redis::Value::BulkString(s.as_bytes().to_vec());
        let resp2 = redis::Value::Array(vec![
            bulk("length"),
            redis::Value::Int(2),
            bulk("last-generated-id"),
            bulk("9-0"),
            bulk("max-deleted-entry-id"),
            bulk("5-1"),
            bulk("entries-added"),
            redis::Value::Int(4),
            bulk("first-entry"),
            redis::Value::Array(vec![bulk("7-0"), redis::Value::Array(vec![])]),
        ]);
        assert_eq!(
            parse_xinfo_stream(&resp2),
            StreamInfo {
                max_deleted: Some("5-1".into()),
                first_entry: Some("7-0".into()),
                last_generated: Some("9-0".into()),
                length: 2,
                entries_added: 4,
            }
        );
        let resp3 = redis::Value::Map(vec![
            (bulk("max-deleted-entry-id"), bulk("5-1")),
            (bulk("first-entry"), redis::Value::Nil),
        ]);
        assert_eq!(parse_xinfo_stream(&resp3).max_deleted, Some("5-1".into()));
    }
}
