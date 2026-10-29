//! Intake credentials — what a sealed envelope carries instead of a Privacy Pass token.
//!
//! Measured on two devices 2026-09-11, in one ordinary conversation, delivery receipts alone were
//! 36–38% of all token spend — and they are spent by the person who was *written to*. A token per
//! sealed envelope charges the same for a stranger's first contact and for the four-hundredth
//! message between two people who have been talking for a year.
//!
//! This server cannot be told which envelopes to exempt: `content_type` lives inside the seal on
//! purpose, so waiving a token for a receipt would put message kind back on the outer envelope.
//! So an envelope that owes nothing says so by carrying a credential the *recipient* issued:
//!
//! ```text
//! intake_tag = HMAC-SHA256(intake_key,
//!                          "knst-intake-v1" ‖ 0x00 ‖ recipient_account_id ‖ 0x00 ‖ epoch_be64)
//!              [0..16]
//! ```
//!
//! derived in `construct-core::intake` and nowhere else. **This service never computes a tag.** It
//! stores what the recipient published and compares. That is deliberate: holding `intake_key`
//! would make a database dump free sending to every account, where holding only tags limits a dump
//! to the epochs it happens to contain.
//!
//! Design: `construct-docs/decisions/contact-traffic-is-vouched-not-purchased.md`.

use construct_crypto::privacy_pass::open_sealed_token_bytes;
use construct_server_shared::shared::proto::services::v1::IntakeVerdict;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of a tag, matching `construct-core::intake::INTAKE_TAG_LEN`.
pub(crate) const INTAKE_TAG_LEN: usize = 16;

/// Seconds per epoch — one UTC day. Must match `construct-core::intake::INTAKE_EPOCH_SECONDS`.
pub(crate) const INTAKE_EPOCH_SECONDS: u64 = 86_400;

/// How long a published tag is kept past the end of its own epoch.
///
/// The previous epoch stays acceptable so a send that crosses midnight — or a client whose clock
/// is a few minutes behind — is not charged for the calendar. One extra epoch, not more: every
/// epoch kept alive is an epoch a leaked tag remains usable in.
pub(crate) const INTAKE_TAG_GRACE_EPOCHS: u64 = 1;

/// Most epochs one `PublishIntakeTags` call may carry.
///
/// A recipient publishes ahead so a device that has been offline for a day does not break its own
/// incoming traffic. Two weeks is generous for that and still bounds what one call can write.
pub(crate) const MAX_PUBLISHED_EPOCHS: usize = 14;

/// What the credential on an envelope amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntakeCheck {
    /// A valid credential for this recipient and a live epoch. No token is owed.
    Vouched,
    /// No credential on the envelope. The token path applies, exactly as before.
    Absent,
    /// A credential that did not open, was the wrong size, or matched nothing.
    ///
    /// Deliberately indistinguishable from `Absent` in consequence: the envelope falls back to the
    /// token path and delivery is unaffected. A wrong tag must never be a delivery failure on its
    /// own, or a clock an hour behind would drop messages rather than charge for them.
    Unrecognised(UnrecognisedReason),
    /// The credential could not be *checked* — Redis did not answer the lookup.
    ///
    /// Same consequence as `Unrecognised` (fall back to the token path), and split from it only so
    /// the two can be told apart from outside. They have opposite causes: `Unrecognised` means the
    /// sender and this server disagree about which tags are live, which is a bug or an epoch
    /// boundary and is worth waking someone for; `Unavailable` means the store is down, which the
    /// Redis alerts already say. Counted as one label, an outage reads as a credential failure and
    /// sends the operator looking in the wrong place.
    Unavailable,
}

/// Which of the ways to be `Unrecognised` an envelope took.
///
/// One `unrecognised` count stood for five causes owned by three different parties, and on
/// 2026-10-29 (30% of a day's sealed envelopes) nobody could say whose bug it was. Each reason
/// names its owner:
///
/// - `no_server_key`, `unseal_failed` — this server's token key, or a sender sealing to a stale
///   copy of it. `unseal_failed` should move with `decrypt_failed` on the token check.
/// - `wrong_length` — a sender that put something other than a tag in the field.
/// - `nothing_published` — the recipient has no live tags at all: every device of theirs let its
///   published window lapse, or never published. The recipient's client is the one to look at.
/// - `no_match` — the recipient has live tags and this is none of them: the sender holds a key the
///   recipient no longer publishes for (another device's, or one since re-minted). The sender's
///   client is the one to look at.
///
/// Nothing here is learned that the check did not already learn: the set it reads to compare is
/// the same set whose emptiness splits the last two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnrecognisedReason {
    NoServerKey,
    UnsealFailed,
    WrongLength,
    NothingPublished,
    NoMatch,
}

impl UnrecognisedReason {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 5] = [
        Self::NoServerKey,
        Self::UnsealFailed,
        Self::WrongLength,
        Self::NothingPublished,
        Self::NoMatch,
    ];

    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::NoServerKey => "no_server_key",
            Self::UnsealFailed => "unseal_failed",
            Self::WrongLength => "wrong_length",
            Self::NothingPublished => "nothing_published",
            Self::NoMatch => "no_match",
        }
    }
}

impl IntakeCheck {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Vouched => "vouched",
            Self::Absent => "absent",
            Self::Unrecognised(_) => "unrecognised",
            Self::Unavailable => "unavailable",
        }
    }

    /// What the sender is told about its tag (`SendMessageResponse.intake_verdict`).
    ///
    /// Only `NotAccepted` makes a client stop presenting its key, so only a statement about the
    /// *key* may map there: no match, nothing published, not a tag. A tag that did not open with
    /// this server's token key, a server with no token key, and an unreachable store all say
    /// something about the server — `Unchecked`, and the sender keeps a key that may be fine.
    /// construct-docs `decisions/intake-key-is-the-accounts-not-the-devices.md`, point 1.
    pub(crate) fn verdict(self) -> IntakeVerdict {
        match self {
            Self::Vouched => IntakeVerdict::Accepted,
            Self::Absent => IntakeVerdict::None,
            Self::Unrecognised(
                UnrecognisedReason::NoMatch
                | UnrecognisedReason::NothingPublished
                | UnrecognisedReason::WrongLength,
            ) => IntakeVerdict::NotAccepted,
            Self::Unrecognised(
                UnrecognisedReason::NoServerKey | UnrecognisedReason::UnsealFailed,
            )
            | Self::Unavailable => IntakeVerdict::Unchecked,
        }
    }

    /// Why an `Unrecognised` credential was not honoured; `None` for every other outcome.
    pub(crate) fn unrecognised_reason(self) -> Option<UnrecognisedReason> {
        match self {
            Self::Unrecognised(reason) => Some(reason),
            _ => None,
        }
    }

    /// Does this envelope still owe a Privacy Pass token?
    ///
    /// Everything that is not a confirmed match owes one, `Unavailable` included: a credential we
    /// could not check is not a credential.
    pub(crate) fn owes_token(self) -> bool {
        self != Self::Vouched
    }
}

/// The epoch containing `unix_seconds`.
pub(crate) fn intake_epoch(unix_seconds: u64) -> u64 {
    unix_seconds / INTAKE_EPOCH_SECONDS
}

/// Most tags one account may have live for one epoch.
///
/// A set, not a single value, since 2026-09-29, when each device minted its own key. Since
/// generations (`decisions/intake-key-is-the-accounts-not-the-devices.md`) the key is the
/// account's and a set holds one generation's tags — normally one, more only while devices that
/// rotated at the same moment converge, and old builds' per-device tags until they update. The cap
/// bounds what one account can make this store hold.
pub(crate) const MAX_TAGS_PER_EPOCH: usize = 32;

/// Redis key for the set of one account's tags in one epoch.
///
/// The account id is hashed rather than embedded. A Redis keyspace scan would otherwise enumerate
/// every account that has published, which is a user list this service has no reason to hand out —
/// the same reasoning that has `pp:unit:` hash its inputs instead of concatenating them.
pub(crate) fn tag_key(recipient_user_id: &str, epoch: u64) -> String {
    format!(
        "intake:v2:{}",
        account_epoch_digest(recipient_user_id, epoch)
    )
}

/// The single-tag string key used before 2026-09-29. Read, never written: a tag published under it
/// stays acceptable until it expires (at most `MAX_PUBLISHED_EPOCHS` + grace), so a deploy does not
/// charge a day of contact traffic that was already vouched. Remove once those keys are gone.
pub(crate) fn legacy_tag_key(recipient_user_id: &str, epoch: u64) -> String {
    format!("intake:{}", account_epoch_digest(recipient_user_id, epoch))
}

fn account_epoch_digest(recipient_user_id: &str, epoch: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(recipient_user_id.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(epoch.to_be_bytes());
    hex::encode(hasher.finalize())
}

/// Seconds a tag published for `epoch` should live, given `now_epoch`.
///
/// Returns `None` for an epoch already past its grace — nothing to store, and a caller that stored
/// it anyway would be writing a key that can never be read.
pub(crate) fn tag_ttl_seconds(epoch: u64, now_epoch: u64) -> Option<u64> {
    let last_live_epoch = epoch + INTAKE_TAG_GRACE_EPOCHS;
    if last_live_epoch < now_epoch {
        return None;
    }
    // Live until the end of the last epoch that still accepts it, counted from the start of now.
    Some((last_live_epoch + 1 - now_epoch) * INTAKE_EPOCH_SECONDS)
}

/// Which epochs an envelope arriving in `now_epoch` may present a tag for.
pub(crate) fn acceptable_epochs(now_epoch: u64) -> Vec<u64> {
    let mut epochs = vec![now_epoch];
    for back in 1..=INTAKE_TAG_GRACE_EPOCHS {
        if let Some(e) = now_epoch.checked_sub(back) {
            epochs.push(e);
        }
    }
    epochs
}

/// Does `presented` match `stored`?
///
/// Constant time, and not as decoration. The server answers accept/reject on a 16-byte secret; a
/// comparison that returns early on the first differing byte turns a 2^-128 forgery into roughly
/// 16 × 256 measured requests.
pub(crate) fn tag_matches(presented: &[u8], stored: &[u8]) -> bool {
    // `subtle` already returns false for slices of different lengths, so this is not the guard
    // against a 32-byte token presented here. What it does catch is the case `subtle` cannot: two
    // values that are equal to each other and both the wrong size — a truncated or corrupted entry
    // in Redis, matchable by presenting the same truncation. `publishable_tags` refuses to store
    // one, and "cannot be written" is not a property a credential check should lean on.
    if presented.len() != INTAKE_TAG_LEN || stored.len() != INTAKE_TAG_LEN {
        return false;
    }
    presented.ct_eq(stored).into()
}

/// Does this envelope carry a credential the recipient issued?
///
/// Reuses `open_sealed_token_bytes` — the same X25519 seal `token_bytes` uses, with the same HKDF
/// info. A second seal primitive differing only in a constant would be a second carrier of one
/// meaning, and the client would then hold two ways to seal sixteen bytes. Moving a blob between
/// the two fields fails closed in both directions anyway: a 32-byte token presented here is the
/// wrong length for a tag, and a 16-byte tag presented as a token fails the `[u8; 32]` conversion.
///
/// Every failure falls back to the token path — `Unrecognised` when the credential is wrong,
/// `Unavailable` when Redis could not be asked. That is the conservative direction: an envelope
/// that cannot be shown to be vouched pays, which is what it did before this existed. The opposite
/// default — trusting a credential we could not check — would turn one unreachable Redis into free
/// sending to everybody.
///
/// The two failures are one outcome here and two labels outside, because what an operator should
/// do about them differs completely. What must NOT follow from `Unavailable` is a refusal: the
/// token path it falls back to degrades rather than rejects when Redis is the reason (see
/// `envelope.rs`), so an outage costs tokens their check, not messages their delivery.
pub(crate) async fn check_intake_credential(
    conn: &mut redis::aio::ConnectionManager,
    server_secret: Option<&x25519_dalek::StaticSecret>,
    intake_tag_sealed: &[u8],
    recipient_user_id: &str,
    now_unix: u64,
) -> IntakeCheck {
    if intake_tag_sealed.is_empty() {
        return IntakeCheck::Absent;
    }
    let Some(secret) = server_secret else {
        // No key to open it with — the same state in which tokens cannot be redeemed either.
        return IntakeCheck::Unrecognised(UnrecognisedReason::NoServerKey);
    };
    let Ok(presented) = open_sealed_token_bytes(intake_tag_sealed, secret) else {
        return IntakeCheck::Unrecognised(UnrecognisedReason::UnsealFailed);
    };
    if presented.len() != INTAKE_TAG_LEN {
        return IntakeCheck::Unrecognised(UnrecognisedReason::WrongLength);
    }

    let mut any_published = false;
    for epoch in acceptable_epochs(intake_epoch(now_unix)) {
        let members: redis::RedisResult<Vec<Vec<u8>>> = redis::cmd("SMEMBERS")
            .arg(tag_key(recipient_user_id, epoch))
            .query_async(conn)
            .await;
        let legacy: redis::RedisResult<Option<Vec<u8>>> = redis::cmd("GET")
            .arg(legacy_tag_key(recipient_user_id, epoch))
            .query_async(conn)
            .await;
        match (members, legacy) {
            (Ok(members), Ok(legacy)) => {
                any_published |= !members.is_empty() || legacy.is_some();
                if any_tag_matches(&presented, members.iter().chain(legacy.iter())) {
                    return IntakeCheck::Vouched;
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!(error = %e, "intake tag lookup unavailable — falling back to the token path");
                return IntakeCheck::Unavailable;
            }
        }
    }
    IntakeCheck::Unrecognised(if any_published {
        UnrecognisedReason::NoMatch
    } else {
        UnrecognisedReason::NothingPublished
    })
}

/// Does `presented` match any of `stored`? Every member is compared — no early return on a match
/// either — so the time taken says nothing about which device's key a tag came from.
pub(crate) fn any_tag_matches<'a>(
    presented: &[u8],
    stored: impl Iterator<Item = &'a Vec<u8>>,
) -> bool {
    stored.fold(false, |found, candidate| {
        tag_matches(presented, candidate) | found
    })
}

/// Redis key holding the account's key generation. Shared with identity-service, which deletes
/// it with the account; no TTL — see `construct_queue::intake_generation_key`.
pub(crate) fn generation_key(account_user_id: &str) -> String {
    construct_queue::intake_generation_key(account_user_id)
}

/// One publish, already validated: tags of the right length for epochs still live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishableTag {
    pub(crate) epoch: u64,
    pub(crate) tag: Vec<u8>,
    pub(crate) ttl: u64,
}

/// Keep the entries this server would store at all, at most `MAX_PUBLISHED_EPOCHS` of them.
///
/// Dropped individually rather than failing the call: an epoch past its grace or a tag of the
/// wrong length lands as a smaller `accepted` count, because refusing a publish costs the
/// caller's contacts tokens.
pub(crate) fn publishable_tags(
    entries: impl IntoIterator<Item = (u64, Vec<u8>)>,
    now_unix: u64,
) -> Vec<PublishableTag> {
    let now_epoch = intake_epoch(now_unix);
    entries
        .into_iter()
        .take(MAX_PUBLISHED_EPOCHS)
        .filter(|(_, tag)| tag.len() == INTAKE_TAG_LEN)
        .filter_map(|(epoch, tag)| {
            tag_ttl_seconds(epoch, now_epoch).map(|ttl| PublishableTag { epoch, tag, ttl })
        })
        .collect()
}

/// Generation check and store, in one step so two devices publishing at once cannot interleave a
/// replace with an add.
///
/// KEYS[1] = generation key; then, per entry, its set key and its legacy single-tag key.
/// ARGV: generation, cap, then per entry: tag, TTL.
/// Returns {generation after, accepted}.
const PUBLISH_SCRIPT: &str = r#"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local generation = tonumber(ARGV[1])
if generation < current then
  return {current, 0}
end
local replace = generation > current
if replace then
  redis.call('SET', KEYS[1], generation)
end
local cap = tonumber(ARGV[2])
local accepted = 0
local cleared = {}
local entries = (#KEYS - 1) / 2
for i = 1, entries do
  local set_key = KEYS[2 * i]
  local legacy_key = KEYS[2 * i + 1]
  local tag = ARGV[1 + 2 * i]
  local ttl = ARGV[2 + 2 * i]
  if replace and not cleared[set_key] then
    redis.call('DEL', set_key, legacy_key)
    cleared[set_key] = true
  end
  if redis.call('SISMEMBER', set_key, tag) == 1 or redis.call('SCARD', set_key) < cap then
    redis.call('SADD', set_key, tag)
    redis.call('EXPIRE', set_key, ttl)
    accepted = accepted + 1
  end
end
return {math.max(current, generation), accepted}
"#;

/// Store a publish under the account's key generation
/// (`decisions/intake-key-is-the-accounts-not-the-devices.md`, points 2-3):
///
/// - **higher** than the account's: the sets for these epochs are *replaced* — the previous key
///   stops being accepted now, not when its window runs out. That is what makes a rotation (after
///   a block, say) mean something; before generations the store only ever added.
/// - **equal**: added to the set, up to `MAX_TAGS_PER_EPOCH` — devices of one account publish
///   identical tags, and two that rotated to the same generation at once both stay valid until the
///   next rotation settles it.
/// - **lower**: nothing stored. The caller's key is behind; `current_generation` says so.
///
/// Generation 0 is a build from before generations: added while the account is at 0, refused as
/// lower once anything has published a generation. Returns `(generation after, accepted)`.
///
/// The account must be the *authenticated* one — a request-supplied id would make publishing a
/// way to vouch for someone else's incoming traffic.
pub(crate) async fn publish_tags(
    conn: &mut redis::aio::ConnectionManager,
    account_user_id: &str,
    generation: u32,
    tags: &[PublishableTag],
) -> Result<(u32, u32), redis::RedisError> {
    let script = redis::Script::new(PUBLISH_SCRIPT);
    let mut invocation = script.key(generation_key(account_user_id));
    for entry in tags {
        invocation
            .key(tag_key(account_user_id, entry.epoch))
            .key(legacy_tag_key(account_user_id, entry.epoch));
    }
    invocation.arg(generation).arg(MAX_TAGS_PER_EPOCH);
    for entry in tags {
        invocation.arg(entry.tag.as_slice()).arg(entry.ttl);
    }
    let (after, accepted): (u32, u32) = invocation.invoke_async(conn).await?;
    Ok((after, accepted))
}

/// The account's generation and whether any tag is live for the current epoch.
pub(crate) async fn intake_state(
    conn: &mut redis::aio::ConnectionManager,
    account_user_id: &str,
    now_unix: u64,
) -> Result<(u32, bool), redis::RedisError> {
    let epoch = intake_epoch(now_unix);
    let (generation, tags, legacy): (Option<u32>, usize, bool) = redis::pipe()
        .cmd("GET")
        .arg(generation_key(account_user_id))
        .cmd("SCARD")
        .arg(tag_key(account_user_id, epoch))
        .cmd("EXISTS")
        .arg(legacy_tag_key(account_user_id, epoch))
        .query_async(conn)
        .await?;
    Ok((generation.unwrap_or(0), tags > 0 || legacy))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential we could not check and a credential that was wrong have the same
    /// consequence and must not have the same name. They have opposite causes:
    /// `Unrecognised` means senders and this server disagree about which tags are live,
    /// `Unavailable` means the store is down. Counted as one label, an outage reads as a
    /// credential failure and sends the operator to the wrong place.
    #[test]
    fn an_unreachable_store_is_not_a_wrong_credential() {
        assert_ne!(
            IntakeCheck::Unavailable.as_label(),
            IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch).as_label()
        );
        let labels = [
            IntakeCheck::Vouched.as_label(),
            IntakeCheck::Absent.as_label(),
            IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch).as_label(),
            IntakeCheck::Unavailable.as_label(),
        ];
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(
            unique.len(),
            labels.len(),
            "every outcome needs its own label"
        );
    }

    /// Only a confirmed match skips the token. A credential that could not be checked is
    /// not a credential — if `Unavailable` ever stopped owing a token, one unreachable
    /// Redis would be free sending to every account on the server.
    #[test]
    fn only_a_confirmed_match_skips_the_token() {
        assert!(!IntakeCheck::Vouched.owes_token());
        assert!(IntakeCheck::Absent.owes_token());
        for reason in UnrecognisedReason::ALL {
            assert!(IntakeCheck::Unrecognised(reason).owes_token());
        }
        assert!(IntakeCheck::Unavailable.owes_token());
    }

    // ── publishable_tags: what a publish may store at all ──

    const NOW: u64 = 20_000 * INTAKE_EPOCH_SECONDS + 3_600;

    #[test]
    fn a_publish_keeps_live_epochs_of_the_right_length_only() {
        let now_epoch = intake_epoch(NOW);
        let kept = publishable_tags(
            [
                (now_epoch, vec![1u8; INTAKE_TAG_LEN]),
                (now_epoch - 1, vec![2u8; INTAKE_TAG_LEN]), // previous epoch: still in grace
                (now_epoch - 2, vec![3u8; INTAKE_TAG_LEN]), // past grace
                (now_epoch + 1, vec![4u8; INTAKE_TAG_LEN - 1]), // wrong length
                (now_epoch + 2, vec![5u8; INTAKE_TAG_LEN]),
            ],
            NOW,
        );
        let epochs: Vec<u64> = kept.iter().map(|t| t.epoch).collect();
        assert_eq!(epochs, vec![now_epoch, now_epoch - 1, now_epoch + 2]);
        assert!(kept.iter().all(|t| t.ttl > 0));
    }

    #[test]
    fn a_publish_carries_at_most_the_published_window() {
        let now_epoch = intake_epoch(NOW);
        let window = (0..40).map(|i| (now_epoch + i, vec![9u8; INTAKE_TAG_LEN]));
        assert_eq!(publishable_tags(window, NOW).len(), MAX_PUBLISHED_EPOCHS);
    }

    #[test]
    fn the_generation_key_is_per_account_and_does_not_leak_it() {
        let key = generation_key("ABCDEF00-0000-0000-0000-000000000000");
        assert_eq!(
            key,
            generation_key(" abcdef00-0000-0000-0000-000000000000 ")
        );
        assert_ne!(key, generation_key("abcdef00-0000-0000-0000-000000000001"));
        assert!(!key.contains("abcdef00"));
    }

    /// A client drops its use of a key only on `NotAccepted`, so that verdict must never come
    /// from the server's own trouble. Each reason is pinned, not just the ones that matter
    /// today: a new reason has to be placed on one side deliberately.
    #[test]
    fn only_a_statement_about_the_key_is_not_accepted() {
        use UnrecognisedReason as R;
        let expected = [
            (IntakeCheck::Vouched, IntakeVerdict::Accepted),
            (IntakeCheck::Absent, IntakeVerdict::None),
            (
                IntakeCheck::Unrecognised(R::NoMatch),
                IntakeVerdict::NotAccepted,
            ),
            (
                IntakeCheck::Unrecognised(R::NothingPublished),
                IntakeVerdict::NotAccepted,
            ),
            (
                IntakeCheck::Unrecognised(R::WrongLength),
                IntakeVerdict::NotAccepted,
            ),
            (
                IntakeCheck::Unrecognised(R::UnsealFailed),
                IntakeVerdict::Unchecked,
            ),
            (
                IntakeCheck::Unrecognised(R::NoServerKey),
                IntakeVerdict::Unchecked,
            ),
            (IntakeCheck::Unavailable, IntakeVerdict::Unchecked),
        ];
        for (check, verdict) in expected {
            assert_eq!(check.verdict(), verdict, "{check:?}");
        }
        assert_eq!(
            expected.len(),
            UnrecognisedReason::ALL.len() + 3,
            "every outcome is pinned"
        );
    }

    /// The reasons exist to say whose bug it is; two sharing a label would put two owners
    /// back on one line. And only `Unrecognised` carries one — a reason on `Vouched` or
    /// `Unavailable` would be counted against the wrong outcome.
    #[test]
    fn each_unrecognised_reason_names_one_cause() {
        let labels: std::collections::BTreeSet<&str> = UnrecognisedReason::ALL
            .iter()
            .map(|r| r.as_label())
            .collect();
        assert_eq!(labels.len(), UnrecognisedReason::ALL.len());
        for reason in UnrecognisedReason::ALL {
            assert_eq!(
                IntakeCheck::Unrecognised(reason).unrecognised_reason(),
                Some(reason)
            );
        }
        assert_eq!(IntakeCheck::Vouched.unrecognised_reason(), None);
        assert_eq!(IntakeCheck::Absent.unrecognised_reason(), None);
        assert_eq!(IntakeCheck::Unavailable.unrecognised_reason(), None);
    }

    #[test]
    fn an_epoch_is_a_utc_day() {
        assert_eq!(intake_epoch(0), 0);
        assert_eq!(intake_epoch(INTAKE_EPOCH_SECONDS - 1), 0);
        assert_eq!(intake_epoch(INTAKE_EPOCH_SECONDS), 1);
        // 2026-09-11T00:00:00Z — the same vector construct-core pins.
        assert_eq!(intake_epoch(1_789_084_800), 20_707);
    }

    #[test]
    fn the_key_is_bound_to_both_account_and_epoch() {
        let a = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";
        let b = "9a921fe2-2f50-44cf-ba68-ed10422de0bc";
        assert_ne!(tag_key(a, 20_707), tag_key(b, 20_707));
        assert_ne!(tag_key(a, 20_707), tag_key(a, 20_708));
    }

    #[test]
    fn the_key_normalises_the_account_like_the_derivation_does() {
        // construct-core lowercases and trims before hashing. If this side did not, a client that
        // published with one spelling and sent with another would look unvouched and be charged,
        // with nothing anywhere reporting a mismatch — the 2026-07-22 recovery bug's shape.
        let a = "FFEEDDC6-14F2-4D02-A66A-CAF0D8DFEDA8";
        let b = "  ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8 ";
        assert_eq!(tag_key(a, 20_707), tag_key(b, 20_707));
    }

    #[test]
    fn a_uuid_and_a_wire_string_land_on_the_same_key() {
        // The publisher's account arrives as a `Uuid` (from the auth token) and the sender's as a
        // wire `String` (SealedInner.recipient_user_id). They must meet at one key, or the
        // keyspace splits into one half nobody reads and one half nobody writes — and the only
        // symptom is that every contact keeps paying tokens.
        let id = uuid::Uuid::parse_str("ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8").unwrap();
        assert_eq!(
            tag_key(&id.to_string(), 20_707),
            tag_key("FFEEDDC6-14F2-4D02-A66A-CAF0D8DFEDA8", 20_707),
            "Uuid::to_string stopped being the canonical spelling tag_key normalises to"
        );
    }

    /// Two devices of one account publish two keys' tags; a contact holding either is vouched.
    /// Mutation: compare only the first member (the old single-value store) — this reddens.
    #[test]
    fn a_tag_from_any_device_of_the_account_is_vouched() {
        let first = vec![1u8; INTAKE_TAG_LEN];
        let second = vec![2u8; INTAKE_TAG_LEN];
        let stored = [first.clone(), second.clone()];
        assert!(any_tag_matches(&second, stored.iter()));
        assert!(any_tag_matches(&first, stored.iter()));
        assert!(!any_tag_matches(&[3u8; INTAKE_TAG_LEN], stored.iter()));
    }

    #[test]
    fn a_wrong_length_member_matches_nothing_even_itself() {
        let short = vec![7u8; INTAKE_TAG_LEN - 1];
        assert!(!any_tag_matches(&short, [short.clone()].iter()));
    }

    /// The set lives under its own key: `SADD` onto a pre-set string key is WRONGTYPE.
    #[test]
    fn the_set_key_is_not_the_legacy_string_key() {
        let a = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";
        assert_ne!(tag_key(a, 20_707), legacy_tag_key(a, 20_707));
        assert!(!legacy_tag_key(a, 20_707).contains("ffeeddc6"));
    }

    #[test]
    fn the_key_does_not_leak_the_account_id() {
        // A keyspace scan must not enumerate who has published.
        let a = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";
        assert!(!tag_key(a, 20_707).contains("ffeeddc6"));
    }

    #[test]
    fn the_previous_epoch_is_still_acceptable_but_the_one_before_is_not() {
        let e = acceptable_epochs(20_707);
        assert!(e.contains(&20_707), "the current epoch must be accepted");
        assert!(
            e.contains(&20_706),
            "a send crossing midnight must not be charged for the calendar"
        );
        assert!(
            !e.contains(&20_705),
            "every extra epoch is an epoch a leaked tag still works in"
        );
    }

    #[test]
    fn epoch_zero_does_not_underflow() {
        // `checked_sub` and not `- 1`: a test clock at the Unix epoch is not a reason to panic.
        assert_eq!(acceptable_epochs(0), vec![0]);
    }

    #[test]
    fn a_tag_for_a_future_epoch_lives_past_it() {
        // Published a week ahead, it must still be there a week later.
        let ttl = tag_ttl_seconds(20_714, 20_707).expect("future epoch is storable");
        assert!(
            ttl > 7 * INTAKE_EPOCH_SECONDS,
            "a tag published ahead expired before its epoch"
        );
    }

    #[test]
    fn a_tag_for_the_current_epoch_outlives_its_grace() {
        let ttl = tag_ttl_seconds(20_707, 20_707).expect("current epoch is storable");
        assert_eq!(ttl, 2 * INTAKE_EPOCH_SECONDS);
    }

    #[test]
    fn a_tag_past_its_grace_is_not_stored_at_all() {
        // 20_705 stopped being acceptable when now_epoch reached 20_707, so writing it would
        // create a key nothing can ever read.
        assert_eq!(tag_ttl_seconds(20_705, 20_707), None);
        // The boundary case is the one worth pinning: the previous epoch IS still storable.
        assert!(tag_ttl_seconds(20_706, 20_707).is_some());
    }

    #[test]
    fn a_matching_tag_matches() {
        let t = [9u8; INTAKE_TAG_LEN];
        assert!(tag_matches(&t, &t));
    }

    #[test]
    fn one_flipped_bit_does_not_match() {
        let a = [9u8; INTAKE_TAG_LEN];
        let mut b = a;
        b[INTAKE_TAG_LEN - 1] ^= 1;
        assert!(!tag_matches(&a, &b));
    }

    #[test]
    fn a_wrong_length_never_matches_even_as_a_prefix() {
        // A 32-byte Privacy Pass token moved into the intake field decrypts fine and must not be
        // accepted because its first 16 bytes happen to line up with something.
        let t = [9u8; INTAKE_TAG_LEN];
        assert!(!tag_matches(&[9u8; 32], &t));
        assert!(!tag_matches(&t, &[9u8; 32]));
        assert!(!tag_matches(&[], &t));
        assert!(!tag_matches(&t, &[]));
    }

    #[test]
    fn two_equal_but_wrong_length_values_do_not_match() {
        // The case the length guard exists for, and the only one — `subtle` handles mismatched
        // lengths on its own. A short value in Redis must not be openable by presenting the same
        // short value. Verified by mutation 2026-09-11: without the guard this is the one test
        // that goes red, and the wrong-length-prefix test below stays green on its own.
        let short = [9u8; 8];
        assert!(!tag_matches(&short, &short));
        let long = [9u8; 32];
        assert!(!tag_matches(&long, &long));
    }

    #[test]
    fn an_unrecognised_credential_still_owes_a_token() {
        // The three outcomes collapse to one question at the call site, and only "vouched" is free.
        assert!(!IntakeCheck::Vouched.owes_token());
        assert!(IntakeCheck::Absent.owes_token());
        assert!(IntakeCheck::Unrecognised(UnrecognisedReason::NoMatch).owes_token());
    }
}
