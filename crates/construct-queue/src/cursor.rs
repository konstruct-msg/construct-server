//! Stateless positions in the two independent mailbox sources. Wire tokens are opaque to
//! clients; neither a cursor nor a component authorizes deletion or selects a mailbox.

use std::{
    fmt::{self, Write},
    str::FromStr,
};

const WIRE_LEN: usize = 87;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StreamPosition(pub u64, pub u64);

impl FromStr for StreamPosition {
    type Err = InvalidMailboxCursor;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (ms, seq) = raw.split_once('-').unwrap_or((raw, "0"));
        let number = |s: &str| {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InvalidMailboxCursor);
            }
            s.parse().map_err(|_| InvalidMailboxCursor)
        };
        Ok(Self(number(ms)?, number(seq)?))
    }
}

impl fmt::Display for StreamPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.0, self.1)
    }
}

/// A complete exclusive resume position, scoped by the authenticated mailbox, not by this token.
/// Legacy numeric IDs initialize both components. New tokens always carry both positions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MailboxCursor {
    pub(crate) device: StreamPosition,
    pub(crate) user: StreamPosition,
}

impl MailboxCursor {
    /// Encode the opaque wire token with exactly one allocation, including zero padding.
    /// Delegates to Display so allocation control does not become a second format authority.
    pub fn encode(self) -> String {
        let mut output = String::with_capacity(WIRE_LEN);
        write!(&mut output, "{self}").expect("formatting a cursor into String cannot fail");
        output
    }

    /// Componentwise forward progress, including an out-of-order Subscribe. One source must
    /// never drag the other backwards (nor advance it to an unrelated source's watermark).
    pub fn join(self, other: Self) -> Self {
        Self {
            device: self.device.max(other.device),
            user: self.user.max(other.user),
        }
    }
}

/// A malformed or unsupported cursor. No unbounded token allocation is needed to reject it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMailboxCursor;

impl fmt::Display for InvalidMailboxCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid mailbox cursor")
    }
}

impl std::error::Error for InvalidMailboxCursor {}

impl FromStr for MailboxCursor {
    type Err = InvalidMailboxCursor;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.starts_with("mc") {
            if raw.len() != WIRE_LEN || !raw.is_ascii() {
                return Err(InvalidMailboxCursor);
            }
            let mut parts = raw.split(':');
            if parts.next() != Some("mc1") {
                return Err(InvalidMailboxCursor);
            }
            let component = |s: Option<&str>| {
                let s = s.ok_or(InvalidMailboxCursor)?;
                if s.len() != 41 || s.as_bytes()[20] != b'-' {
                    return Err(InvalidMailboxCursor);
                }
                s.parse::<StreamPosition>()
            };
            let device = component(parts.next())?;
            let user = component(parts.next())?;
            if parts.next().is_some() {
                return Err(InvalidMailboxCursor);
            }
            return Ok(Self { device, user });
        }
        if raw.len() > 41 {
            return Err(InvalidMailboxCursor);
        }
        let position = raw.parse()?;
        Ok(Self {
            device: position,
            user: position,
        })
    }
}

impl fmt::Display for MailboxCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Width is part of compatibility: construct-client's existing numeric parser falls
        // back to lexical order for opaque tokens. 'm' sorts after every legacy numeric ID;
        // fixed-width u64s keep every componentwise-forward chain lexically increasing.
        write!(
            f,
            "mc1:{:020}-{:020}:{:020}-{:020}",
            self.device.0, self.device.1, self.user.0, self.user.1
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_positions_seed_both_sources_without_truncating_u64() {
        for (raw, expected) in [
            ("0", (0, 0)),
            ("12", (12, 0)),
            ("12-34", (12, 34)),
            (
                "18446744073709551615-18446744073709551615",
                (u64::MAX, u64::MAX),
            ),
        ] {
            let cursor: MailboxCursor = raw.parse().unwrap();
            assert_eq!(cursor.device, StreamPosition(expected.0, expected.1));
            assert_eq!(cursor.user, cursor.device);
            assert_eq!(cursor.to_string().len(), 87);
            assert_eq!(cursor.to_string().parse(), Ok(cursor));
            assert_eq!(cursor.encode(), cursor.to_string());
            assert_eq!(cursor.encode().parse(), Ok(cursor));
        }
    }

    #[test]
    fn malformed_tokens_are_not_partially_accepted_as_legacy() {
        let good = MailboxCursor::default().to_string();
        for raw in [
            "",
            "$",
            "*",
            "+1-0",
            "1-+0",
            "-1-0",
            "1-2-3",
            "1-",
            "garbage",
            "18446744073709551616-0",
            "mc2:0-0:0-0",
            "mc1:0-0:0-0",
        ] {
            assert!(raw.parse::<MailboxCursor>().is_err(), "{raw}");
        }
        for bad in [
            good.replace("mc1", "mc2"),
            format!("{good}:extra"),
            good.replacen('0', "é", 1),
            good.replacen("00000000000000000000", "18446744073709551616", 1),
        ] {
            assert!(bad.parse::<MailboxCursor>().is_err(), "{bad}");
        }
    }

    #[test]
    fn opaque_tokens_remain_ordered_for_the_existing_rust_client_storage_fallback() {
        // LocalStore::cursor_after parses ms-seq, otherwise compares strings. These are
        // real width transitions, not same-width samples that would pass without padding.
        for base in [0, 9, 99, 999, 9_999_999_999_999_999_999, u64::MAX - 1] {
            for component in 0..4 {
                let make = |n| {
                    let mut fields = [base; 4];
                    fields[component] = n;
                    MailboxCursor {
                        device: StreamPosition(fields[0], fields[1]),
                        user: StreamPosition(fields[2], fields[3]),
                    }
                };
                let old = make(base);
                let new = make(base + 1);
                assert!(
                    new.to_string() > old.to_string(),
                    "component={component}, base={base}"
                );
                assert!(
                    new.to_string() > format!("{base}-{base}"),
                    "legacy migration"
                );
            }
        }
    }

    #[test]
    fn joining_a_subscribe_preserves_both_source_prefixes() {
        let a = MailboxCursor {
            device: StreamPosition(200, 0),
            user: StreamPosition(100, 9),
        };
        let b = MailboxCursor {
            device: StreamPosition(100, 9),
            user: StreamPosition(200, 0),
        };
        let joined = a.join(b);
        assert_eq!(joined.device, StreamPosition(200, 0));
        assert_eq!(joined.user, StreamPosition(200, 0));
        assert_eq!(a.join(a), a);
        assert_eq!(a.join(b), b.join(a));
    }
}
