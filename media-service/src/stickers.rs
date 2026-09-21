// ============================================================================
// Sticker packs — content-addressed storage and the rules a pack must meet
// ============================================================================
//
// Shared by the StickerService handlers (`sticker_grpc.rs`) and the publish tool
// (`bin/sticker-publish.rs`). Everything that decides whether bytes are a pack lives
// here, once: the canonical encoding a pack_id is the hash of, the per-entry rules
// every client re-checks, and the WebP header check a blob must pass before it is
// stored.
//
// Storage is two content-addressed tables with no TTL (migration 070). Not the media
// store — see the migration for why a sticker must outlive MEDIA_FILE_TTL_SECONDS.
//
// Design: construct-docs/decisions/sticker-packs-content-addressed.md,
// backend/STICKER_SERVICE_SPEC.md.

use anyhow::{Context, Result, bail};
use prost::Message;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use construct_server_shared::shared::proto::messaging::v1::StickerPackManifest;

// ----------------------------------------------------------------------------
// Rules
// ----------------------------------------------------------------------------

/// What a pack and a sticker must be. The same numbers the clients hold
/// (`StickerImageRules`, `StickerWireRules` on iOS); a change here is a protocol change.
pub mod rules {
    pub const HASH_LEN: usize = 32;
    pub const CANVAS: u32 = 512;
    pub const MAX_BLOB_BYTES: usize = 100 * 1024;
    pub const MAX_STICKERS: usize = 120;
    /// UTF-8 bytes, not graphemes — the same measure as StickerRef.emoji on the wire.
    pub const EMOJI_MIN_BYTES: usize = 1;
    pub const EMOJI_MAX_BYTES: usize = 32;
    /// `have_sha256` longer than a pack can be is not a client; rejected, never truncated.
    pub const MAX_HAVE: usize = MAX_STICKERS;
    pub const DEFAULT_PAGE: u32 = 50;
    pub const MAX_PAGE: u32 = 200;
}

// ----------------------------------------------------------------------------
// Identity
// ----------------------------------------------------------------------------

/// The bytes a pack's identity is computed over: the manifest with `pack_id` and `signature`
/// cleared, in proto3 binary. prost writes fields in ascending number order, which is what
/// `conformance/knst_sticker_pack.json` fixes; `tests::fixture_pack_id_matches_vector` holds
/// this function to that file.
pub fn canonical_bytes(manifest: &StickerPackManifest) -> Vec<u8> {
    let mut m = manifest.clone();
    m.pack_id.clear();
    m.signature.clear();
    m.encode_to_vec()
}

pub fn pack_id(manifest: &StickerPackManifest) -> [u8; 32] {
    Sha256::digest(canonical_bytes(manifest)).into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Everything a manifest must satisfy before it is stored or served, signature aside. The
/// signature is the publish tool's to add and the client's to check; the service holds no key
/// and does not pretend to verify one.
pub fn validate_manifest(manifest: &StickerPackManifest) -> Result<()> {
    let n = manifest.stickers.len();
    if n == 0 || n > rules::MAX_STICKERS {
        bail!("{n} stickers, must be 1..={}", rules::MAX_STICKERS);
    }
    if manifest.title.trim().is_empty() {
        bail!("title is empty");
    }
    if manifest.publisher.trim().is_empty() {
        bail!("publisher is empty");
    }
    for (i, e) in manifest.stickers.iter().enumerate() {
        if e.sha256.len() != rules::HASH_LEN {
            bail!(
                "sticker {i}: sha256 is {} bytes, not {}",
                e.sha256.len(),
                rules::HASH_LEN
            );
        }
        let emoji_len = e.emoji.len();
        if !(rules::EMOJI_MIN_BYTES..=rules::EMOJI_MAX_BYTES).contains(&emoji_len) {
            bail!(
                "sticker {i}: emoji is {emoji_len} UTF-8 bytes, must be {}..={}",
                rules::EMOJI_MIN_BYTES,
                rules::EMOJI_MAX_BYTES
            );
        }
        if e.width != rules::CANVAS || e.height != rules::CANVAS {
            bail!(
                "sticker {i}: {}×{}, canvas is {c}×{c}",
                e.width,
                e.height,
                c = rules::CANVAS
            );
        }
        if e.byte_len == 0 || e.byte_len as usize > rules::MAX_BLOB_BYTES {
            bail!(
                "sticker {i}: byte_len {} outside 1..={}",
                e.byte_len,
                rules::MAX_BLOB_BYTES
            );
        }
    }
    if manifest.pack_id.len() != rules::HASH_LEN {
        bail!(
            "pack_id is {} bytes, not {}",
            manifest.pack_id.len(),
            rules::HASH_LEN
        );
    }
    if manifest.pack_id.as_slice() != pack_id(manifest) {
        bail!("pack_id is not the hash of the manifest's canonical bytes");
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// WebP header
// ----------------------------------------------------------------------------

/// A blob's dimensions and kind read from the container header — no decoder. The server
/// never decodes an image (see the security note in main.rs); this is a 30-byte structural
/// check, the same one the client makes before it writes a fetched blob to its cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebPHeader {
    pub width: u32,
    pub height: u32,
    pub animated: bool,
}

impl WebPHeader {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < 30 {
            bail!("too short to be a WebP");
        }
        if &b[0..4] != b"RIFF" || &b[8..12] != b"WEBP" {
            bail!("not a WebP container");
        }
        let p = 20; // first byte of the first chunk's payload
        match &b[12..16] {
            b"VP8 " => {
                // 3-byte frame tag, start code 9D 01 2A, then 14-bit width and height in
                // little-endian 16-bit words whose top two bits are scale.
                if b[p + 3..p + 6] != [0x9D, 0x01, 0x2A] {
                    bail!("bad VP8 bitstream");
                }
                let w = u32::from(b[p + 6]) | (u32::from(b[p + 7] & 0x3F) << 8);
                let h = u32::from(b[p + 8]) | (u32::from(b[p + 9] & 0x3F) << 8);
                Ok(Self {
                    width: w,
                    height: h,
                    animated: false,
                })
            }
            b"VP8L" => {
                // Signature 2F, then 14 bits width-1, 14 bits height-1, alpha, version.
                if b[p] != 0x2F {
                    bail!("bad VP8L bitstream");
                }
                let (b1, b2, b3, b4) = (
                    u32::from(b[p + 1]),
                    u32::from(b[p + 2]),
                    u32::from(b[p + 3]),
                    u32::from(b[p + 4]),
                );
                let w = 1 + (b1 | ((b2 & 0x3F) << 8));
                let h = 1 + ((b2 >> 6) | (b3 << 2) | ((b4 & 0x0F) << 10));
                Ok(Self {
                    width: w,
                    height: h,
                    animated: false,
                })
            }
            b"VP8X" => {
                // Flags byte, three reserved, then canvas width-1 and height-1 as 24-bit LE.
                let animated = b[p] & 0x02 != 0;
                let w = 1
                    + (u32::from(b[p + 4])
                        | (u32::from(b[p + 5]) << 8)
                        | (u32::from(b[p + 6]) << 16));
                let h = 1
                    + (u32::from(b[p + 7])
                        | (u32::from(b[p + 8]) << 8)
                        | (u32::from(b[p + 9]) << 16));
                Ok(Self {
                    width: w,
                    height: h,
                    animated,
                })
            }
            other => bail!("unknown first chunk {:?}", String::from_utf8_lossy(other)),
        }
    }

    /// A static image on the sticker canvas. Animation is a separate decision and is refused.
    pub fn is_sticker_canvas(&self) -> bool {
        !self.animated && self.width == rules::CANVAS && self.height == rules::CANVAS
    }
}

/// The check a blob passes before it is stored: size, then header. Returns the header so the
/// caller has the dimensions without parsing twice.
pub fn validate_blob(bytes: &[u8]) -> Result<WebPHeader> {
    if bytes.is_empty() || bytes.len() > rules::MAX_BLOB_BYTES {
        bail!(
            "{} bytes, must be 1..={}",
            bytes.len(),
            rules::MAX_BLOB_BYTES
        );
    }
    let header = WebPHeader::parse(bytes)?;
    if !header.is_sticker_canvas() {
        bail!(
            "{}×{}{}, must be a static {}×{}",
            header.width,
            header.height,
            if header.animated { " animated" } else { "" },
            rules::CANVAS,
            rules::CANVAS
        );
    }
    Ok(header)
}

// ----------------------------------------------------------------------------
// Catalog cursor
// ----------------------------------------------------------------------------

/// The catalog is ordered by (published_at DESC, pack_id DESC) and the page token is that
/// position: 8 bytes of microseconds since the epoch, big-endian, then the 32-byte pack_id.
/// Opaque to the client; any other length is a client error, not a first page.
pub struct PageCursor {
    pub published_at_micros: i64,
    pub pack_id: [u8; 32],
}

impl PageCursor {
    const LEN: usize = 8 + 32;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.published_at_micros.to_be_bytes());
        out.extend_from_slice(&self.pack_id);
        out
    }

    pub fn decode(token: &[u8]) -> Result<Self> {
        if token.len() != Self::LEN {
            bail!(
                "page token is {} bytes, expected {}",
                token.len(),
                Self::LEN
            );
        }
        let micros = i64::from_be_bytes(token[..8].try_into().expect("8 bytes"));
        let mut id = [0u8; 32];
        id.copy_from_slice(&token[8..]);
        Ok(Self {
            published_at_micros: micros,
            pack_id: id,
        })
    }
}

/// Clamp the requested page size into the service's range; 0 means the default.
pub fn page_size(requested: u32) -> u32 {
    if requested == 0 {
        rules::DEFAULT_PAGE
    } else {
        requested.min(rules::MAX_PAGE)
    }
}

// ----------------------------------------------------------------------------
// Storage
// ----------------------------------------------------------------------------
//
// Runtime queries rather than `sqlx::query!`: the macro checks against `.sqlx/`, which is
// regenerated only against a live database, and a new table has no cached entry. Same reason
// as `core::save_metadata`.

/// One catalog row as the query returns it, before it becomes a `PackSummaryRow`.
type PackSummaryTuple = (Vec<u8>, String, String, i32, Vec<u8>, i64, i64);

#[derive(Debug, Clone)]
pub struct PackSummaryRow {
    pub pack_id: Vec<u8>,
    pub title: String,
    pub publisher: String,
    pub sticker_count: i32,
    pub cover_sha256: Vec<u8>,
    pub total_bytes: i64,
    pub published_at_micros: i64,
}

pub async fn get_manifest_bytes(pool: &PgPool, pack_id: &[u8]) -> Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT manifest_bytes FROM sticker_packs WHERE pack_id = $1")
            .bind(pack_id)
            .fetch_optional(pool)
            .await
            .context("select sticker_packs")?;
    Ok(row.map(|r| r.0))
}

pub async fn get_blob(pool: &PgPool, sha256: &[u8]) -> Result<Option<Vec<u8>>> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT bytes FROM sticker_blobs WHERE sha256 = $1")
            .bind(sha256)
            .fetch_optional(pool)
            .await
            .context("select sticker_blobs")?;
    Ok(row.map(|r| r.0))
}

/// One page of listed packs, newest first, strictly after `after` when given.
pub async fn list_packs(
    pool: &PgPool,
    after: Option<&PageCursor>,
    limit: u32,
) -> Result<Vec<PackSummaryRow>> {
    let rows: Vec<PackSummaryTuple> = match after {
        None => {
            sqlx::query_as(
                r#"
                SELECT pack_id, title, publisher, sticker_count, cover_sha256, total_bytes,
                       (EXTRACT(EPOCH FROM published_at) * 1000000)::BIGINT
                FROM sticker_packs
                WHERE listed
                ORDER BY published_at DESC, pack_id DESC
                LIMIT $1
                "#,
            )
            .bind(i64::from(limit))
            .fetch_all(pool)
            .await
        }
        Some(cur) => {
            sqlx::query_as(
                r#"
                SELECT pack_id, title, publisher, sticker_count, cover_sha256, total_bytes,
                       (EXTRACT(EPOCH FROM published_at) * 1000000)::BIGINT
                FROM sticker_packs
                WHERE listed
                  AND ((EXTRACT(EPOCH FROM published_at) * 1000000)::BIGINT, pack_id) < ($2, $3)
                ORDER BY published_at DESC, pack_id DESC
                LIMIT $1
                "#,
            )
            .bind(i64::from(limit))
            .bind(cur.published_at_micros)
            .bind(cur.pack_id.as_slice())
            .fetch_all(pool)
            .await
        }
    }
    .context("select sticker_packs page")?;

    Ok(rows
        .into_iter()
        .map(|r| PackSummaryRow {
            pack_id: r.0,
            title: r.1,
            publisher: r.2,
            sticker_count: r.3,
            cover_sha256: r.4,
            total_bytes: r.5,
            published_at_micros: r.6,
        })
        .collect())
}

/// Idempotent by hash: a blob two packs share is one row, and a re-run of the publish tool
/// changes nothing.
pub async fn insert_blob(
    pool: &PgPool,
    sha256: &[u8],
    bytes: &[u8],
    header: WebPHeader,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sticker_blobs (sha256, bytes, width, height)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (sha256) DO NOTHING
        "#,
    )
    .bind(sha256)
    .bind(bytes)
    .bind(header.width as i32)
    .bind(header.height as i32)
    .execute(pool)
    .await
    .context("insert sticker_blobs")?;
    Ok(())
}

/// Insert a pack unlisted, or replace the manifest bytes of an existing one.
///
/// The replace path is key rotation: a re-signed manifest has the same pack_id (the signature
/// is outside the canonical bytes) and must land under it. Title, publisher, count, cover and
/// size are all inside the canonical bytes, so they cannot differ between the two — the upsert
/// rewrites only what can.
pub async fn upsert_pack_unlisted(
    pool: &PgPool,
    manifest: &StickerPackManifest,
    manifest_bytes: &[u8],
) -> Result<()> {
    validate_manifest(manifest)?;
    let total: i64 = manifest
        .stickers
        .iter()
        .map(|e| i64::from(e.byte_len))
        .sum();
    sqlx::query(
        r#"
        INSERT INTO sticker_packs
            (pack_id, manifest_bytes, title, publisher, sticker_count, total_bytes, cover_sha256, listed)
        VALUES ($1, $2, $3, $4, $5, $6, $7, false)
        ON CONFLICT (pack_id) DO UPDATE SET manifest_bytes = EXCLUDED.manifest_bytes
        "#,
    )
    .bind(manifest.pack_id.as_slice())
    .bind(manifest_bytes)
    .bind(&manifest.title)
    .bind(&manifest.publisher)
    .bind(manifest.stickers.len() as i32)
    .bind(total)
    .bind(manifest.stickers[0].sha256.as_slice())
    .execute(pool)
    .await
    .context("upsert sticker_packs")?;
    Ok(())
}

pub async fn set_listed(pool: &PgPool, pack_id: &[u8], listed: bool) -> Result<bool> {
    let result = sqlx::query("UPDATE sticker_packs SET listed = $2 WHERE pack_id = $1")
        .bind(pack_id)
        .bind(listed)
        .execute(pool)
        .await
        .context("update sticker_packs.listed")?;
    Ok(result.rows_affected() == 1)
}

// ============================================================================
// Tests
// ============================================================================

// ----------------------------------------------------------------------------
// Conformance
// ----------------------------------------------------------------------------

/// The fixture pack from construct-protos `conformance/knst_sticker_pack.json`, as fields, and
/// the `pack_id_hex` that file fixes for it. Every client holds its encoder to the same bytes,
/// so reproducing this id is the test that this crate and the clients agree on what a pack
/// *is*. The publish tool runs it before it will sign anything (`self_check`).
pub mod conformance {
    use super::*;
    use construct_server_shared::shared::proto::messaging::v1::StickerEntry;

    pub const FIXTURE_PACK_ID_HEX: &str =
        "2a205b125f4a87250007ff04a68d44a9b2d2c868b0443506b81ab52ac75e5ad1";

    pub fn fixture_manifest() -> StickerPackManifest {
        let entry = |sha: &str, emoji: &str, len: u32| StickerEntry {
            sha256: hex::decode(sha).expect("fixture hex"),
            emoji: emoji.to_string(),
            width: 512,
            height: 512,
            byte_len: len,
        };
        StickerPackManifest {
            pack_id: vec![],
            title: "Konstruct fixture".into(),
            publisher: "Konstruct".into(),
            stickers: vec![
                entry(
                    "398f9c2fa58b7c2c8f55ca8bd5b27ead054dd3412183f1033de53bc5802af91e",
                    "🔵",
                    9964,
                ),
                entry(
                    "578e7351323f018dd76a2b56ea1248925a4817b29e279511abe38e04348b67e3",
                    "🟥",
                    1286,
                ),
                entry(
                    "387ccee7a876ab7f231a868046d8cabfcdc02cf81c9f6fe25c80a19ac3e6ca67",
                    "🔺",
                    8154,
                ),
                entry(
                    "c2515dcc1915fed7d07c91744ff78057ac6b4b8214c2c93673434e724e5ea9bd",
                    "🟡",
                    16578,
                ),
            ],
            signature: vec![],
        }
    }

    /// `Err` means this binary's encoder disagrees with the vector, and any pack it published
    /// would be named differently by every client that fetched it.
    pub fn self_check() -> Result<()> {
        let got = hex::encode(pack_id(&fixture_manifest()));
        if got != FIXTURE_PACK_ID_HEX {
            bail!(
                "canonical encoder does not reproduce the conformance vector: got {got}, vector says {FIXTURE_PACK_ID_HEX}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::conformance::{FIXTURE_PACK_ID_HEX as FIXTURE_PACK_ID, fixture_manifest as fixture};
    use super::*;

    #[test]
    fn fixture_pack_id_matches_vector() {
        conformance::self_check().expect("encoder reproduces the vector");
        let m = fixture();
        assert_eq!(hex::encode(pack_id(&m)), FIXTURE_PACK_ID);
        // The canonical bytes must not depend on what pack_id / signature hold.
        let mut signed = m.clone();
        signed.pack_id = pack_id(&m).to_vec();
        signed.signature = vec![0xAB; 64];
        assert_eq!(canonical_bytes(&signed), canonical_bytes(&m));
        assert_eq!(hex::encode(pack_id(&signed)), FIXTURE_PACK_ID);
    }

    #[test]
    fn canonical_bytes_start_with_title_field() {
        // Field 2 (title), wire type 2: tag 0x12, then the length. The vector's canonical_hex
        // begins `12 11 4b 6f …` — "Konstruct fixture" is 17 bytes.
        let c = canonical_bytes(&fixture());
        assert_eq!(&c[..4], &[0x12, 0x11, 0x4b, 0x6f]);
    }

    #[test]
    fn validate_accepts_fixture_with_its_own_hash() {
        let mut m = fixture();
        m.pack_id = pack_id(&m).to_vec();
        validate_manifest(&m).expect("fixture is a valid pack");
    }

    #[test]
    fn validate_refuses_each_broken_field() {
        let good = {
            let mut m = fixture();
            m.pack_id = pack_id(&m).to_vec();
            m
        };

        let mut wrong_id = good.clone();
        wrong_id.pack_id[0] ^= 1;
        assert!(
            validate_manifest(&wrong_id).is_err(),
            "pack_id not the hash"
        );

        let mut short_id = good.clone();
        short_id.pack_id.pop();
        assert!(validate_manifest(&short_id).is_err(), "31-byte pack_id");

        let mut no_emoji = good.clone();
        no_emoji.stickers[1].emoji.clear();
        no_emoji.pack_id = pack_id(&no_emoji).to_vec();
        assert!(validate_manifest(&no_emoji).is_err(), "empty emoji");

        let mut long_emoji = good.clone();
        long_emoji.stickers[1].emoji = "🔵".repeat(9); // 36 bytes
        long_emoji.pack_id = pack_id(&long_emoji).to_vec();
        assert!(validate_manifest(&long_emoji).is_err(), "33+ byte emoji");

        let mut off_canvas = good.clone();
        off_canvas.stickers[2].width = 256;
        off_canvas.pack_id = pack_id(&off_canvas).to_vec();
        assert!(validate_manifest(&off_canvas).is_err(), "256 wide");

        let mut fat = good.clone();
        fat.stickers[3].byte_len = rules::MAX_BLOB_BYTES as u32 + 1;
        fat.pack_id = pack_id(&fat).to_vec();
        assert!(validate_manifest(&fat).is_err(), "over 100 KiB");

        let mut short_sha = good.clone();
        short_sha.stickers[0].sha256.pop();
        short_sha.pack_id = pack_id(&short_sha).to_vec();
        assert!(validate_manifest(&short_sha).is_err(), "31-byte sha256");

        let mut empty = good.clone();
        empty.stickers.clear();
        empty.pack_id = pack_id(&empty).to_vec();
        assert!(validate_manifest(&empty).is_err(), "no stickers");

        let mut crowded = good.clone();
        while crowded.stickers.len() <= rules::MAX_STICKERS {
            crowded.stickers.push(good.stickers[0].clone());
        }
        crowded.pack_id = pack_id(&crowded).to_vec();
        assert!(validate_manifest(&crowded).is_err(), "121 stickers");

        validate_manifest(&good).expect("the unmutated pack still passes");
    }

    /// Minimal headers of each kind, 30 bytes: RIFF size and chunk sizes are not checked, only
    /// the fourcc and the dimension fields.
    fn vp8l(width: u32, height: u32) -> Vec<u8> {
        let mut b = vec![0u8; 30];
        b[0..4].copy_from_slice(b"RIFF");
        b[8..12].copy_from_slice(b"WEBP");
        b[12..16].copy_from_slice(b"VP8L");
        b[20] = 0x2F;
        let w = width - 1;
        let h = height - 1;
        b[21] = (w & 0xFF) as u8;
        b[22] = ((w >> 8) & 0x3F) as u8 | ((h & 0x03) << 6) as u8;
        b[23] = ((h >> 2) & 0xFF) as u8;
        b[24] = ((h >> 10) & 0x0F) as u8;
        b
    }

    fn vp8x(width: u32, height: u32, animated: bool) -> Vec<u8> {
        let mut b = vec![0u8; 30];
        b[0..4].copy_from_slice(b"RIFF");
        b[8..12].copy_from_slice(b"WEBP");
        b[12..16].copy_from_slice(b"VP8X");
        b[20] = if animated { 0x02 } else { 0x00 };
        let w = width - 1;
        let h = height - 1;
        b[24..27].copy_from_slice(&w.to_le_bytes()[..3]);
        b[27..30].copy_from_slice(&h.to_le_bytes()[..3]);
        b
    }

    #[test]
    fn webp_header_reads_each_kind() {
        let l = WebPHeader::parse(&vp8l(512, 512)).unwrap();
        assert_eq!((l.width, l.height, l.animated), (512, 512, false));
        assert!(l.is_sticker_canvas());

        let x = WebPHeader::parse(&vp8x(512, 512, false)).unwrap();
        assert!(x.is_sticker_canvas());

        let anim = WebPHeader::parse(&vp8x(512, 512, true)).unwrap();
        assert!(anim.animated);
        assert!(!anim.is_sticker_canvas(), "animation is refused");

        let small = WebPHeader::parse(&vp8l(511, 512)).unwrap();
        assert!(!small.is_sticker_canvas());

        assert!(
            WebPHeader::parse(b"RIFF\0\0\0\0WEBPXXXX").is_err(),
            "too short"
        );
        assert!(WebPHeader::parse(&[0u8; 30]).is_err(), "not RIFF");
        let mut png = vp8l(512, 512);
        png[12..16].copy_from_slice(b"ALPH");
        assert!(WebPHeader::parse(&png).is_err(), "unknown first chunk");
    }

    #[test]
    fn validate_blob_checks_size_then_header() {
        assert!(validate_blob(&[]).is_err());
        assert!(validate_blob(&vec![0u8; rules::MAX_BLOB_BYTES + 1]).is_err());
        assert!(validate_blob(&vp8l(512, 512)).is_ok());
        assert!(validate_blob(&vp8x(512, 512, true)).is_err());
    }

    #[test]
    fn page_cursor_round_trips_and_rejects_other_lengths() {
        let c = PageCursor {
            published_at_micros: 1_758_400_000_123_456,
            pack_id: [7u8; 32],
        };
        let back = PageCursor::decode(&c.encode()).unwrap();
        assert_eq!(back.published_at_micros, c.published_at_micros);
        assert_eq!(back.pack_id, c.pack_id);
        assert!(PageCursor::decode(&[]).is_err());
        assert!(PageCursor::decode(&[0u8; 39]).is_err());
        assert!(PageCursor::decode(&[0u8; 41]).is_err());
    }

    #[test]
    fn page_size_defaults_and_clamps() {
        assert_eq!(page_size(0), rules::DEFAULT_PAGE);
        assert_eq!(page_size(10), 10);
        assert_eq!(page_size(10_000), rules::MAX_PAGE);
    }
}

// ============================================================================
// Storage tests — need a database
// ============================================================================
//
// `cargo test` does not reach these; like the Redis mailbox tests they are `#[ignore]`, and a
// green suite says nothing about the SQL above. Run them against a scratch database:
//
//   DATABASE_URL=postgresql://postgres@127.0.0.1:55432/construct_test \
//   cargo test -p media-service --lib -- --ignored stickers_db
//
// The migrations are applied by the test, so a fresh database is enough.

#[cfg(test)]
mod stickers_db {
    use super::conformance::fixture_manifest;
    use super::*;
    use prost::Message;

    /// The tests share one database and each starts by emptying the sticker tables, so they
    /// run one at a time. Held for the whole test through the guard `pool()` returns.
    static SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    async fn pool() -> (PgPool, tokio::sync::MutexGuard<'static, ()>) {
        let guard = SERIAL.lock().await;
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL for the ignored DB tests");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        sqlx::migrate!("../shared/migrations")
            .run(&pool)
            .await
            .expect("migrate");
        // Tests share the database; start from nothing so counts and pages are exact.
        sqlx::query("DELETE FROM sticker_packs")
            .execute(&pool)
            .await
            .expect("clear packs");
        sqlx::query("DELETE FROM sticker_blobs")
            .execute(&pool)
            .await
            .expect("clear blobs");
        (pool, guard)
    }

    /// A blob that passes `validate_blob`: a VP8L header on the canvas, padded. The bytes do
    /// not decode as an image and do not need to — the store never decodes.
    fn synthetic_blob(fill: u8) -> Vec<u8> {
        let mut b = vec![fill; 64];
        b[0..4].copy_from_slice(b"RIFF");
        b[8..12].copy_from_slice(b"WEBP");
        b[12..16].copy_from_slice(b"VP8L");
        b[20] = 0x2F;
        let w = 511u32;
        let h = 511u32;
        b[21] = (w & 0xFF) as u8;
        b[22] = ((w >> 8) & 0x3F) as u8 | ((h & 0x03) << 6) as u8;
        b[23] = ((h >> 2) & 0xFF) as u8;
        b[24] = ((h >> 10) & 0x0F) as u8;
        b
    }

    /// A pack whose entries name the synthetic blobs, so the blob table and the manifest agree.
    fn pack(title: &str, fills: &[u8]) -> (StickerPackManifest, Vec<u8>, Vec<Vec<u8>>) {
        let blobs: Vec<Vec<u8>> = fills.iter().map(|f| synthetic_blob(*f)).collect();
        let mut m = fixture_manifest();
        m.title = title.into();
        m.stickers = blobs
            .iter()
            .map(
                |b| construct_server_shared::shared::proto::messaging::v1::StickerEntry {
                    sha256: sha256(b).to_vec(),
                    emoji: "🐈".into(),
                    width: 512,
                    height: 512,
                    byte_len: b.len() as u32,
                },
            )
            .collect();
        m.pack_id = pack_id(&m).to_vec();
        let bytes = m.encode_to_vec();
        (m, bytes, blobs)
    }

    async fn publish(
        pool: &PgPool,
        m: &StickerPackManifest,
        bytes: &[u8],
        blobs: &[Vec<u8>],
        list: bool,
    ) {
        for b in blobs {
            let h = validate_blob(b).unwrap();
            insert_blob(pool, &sha256(b), b, h).await.unwrap();
        }
        upsert_pack_unlisted(pool, m, bytes).await.unwrap();
        if list {
            assert!(set_listed(pool, &m.pack_id, true).await.unwrap());
        }
    }

    #[tokio::test]
    #[ignore] // Requires Postgres
    async fn manifest_and_blobs_round_trip_byte_for_byte() {
        let (pool, _serial) = pool().await;
        let (m, bytes, blobs) = pack("Round trip", &[1, 2, 3]);
        publish(&pool, &m, &bytes, &blobs, true).await;

        assert_eq!(
            get_manifest_bytes(&pool, &m.pack_id)
                .await
                .unwrap()
                .as_deref(),
            Some(bytes.as_slice())
        );
        for b in &blobs {
            assert_eq!(
                get_blob(&pool, &sha256(b)).await.unwrap().as_deref(),
                Some(b.as_slice())
            );
        }
        assert!(
            get_manifest_bytes(&pool, &[0u8; 32])
                .await
                .unwrap()
                .is_none()
        );
        assert!(get_blob(&pool, &[0u8; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore] // Requires Postgres
    async fn republish_is_idempotent_and_replaces_only_manifest_bytes() {
        let (pool, _serial) = pool().await;
        let (m, bytes, blobs) = pack("Idempotent", &[4, 5]);
        publish(&pool, &m, &bytes, &blobs, true).await;
        // Second run: same blobs, a re-signed manifest under the same pack_id.
        let mut resigned = m.clone();
        resigned.signature = vec![0xEE; 64];
        let resigned_bytes = resigned.encode_to_vec();
        publish(&pool, &resigned, &resigned_bytes, &blobs, false).await;

        assert_eq!(
            get_manifest_bytes(&pool, &m.pack_id)
                .await
                .unwrap()
                .as_deref(),
            Some(resigned_bytes.as_slice()),
            "the re-signed bytes replace the old ones under the same id"
        );
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM sticker_blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count, 2,
            "blobs are one row per hash however often they are inserted"
        );
        let rows = list_packs(&pool, None, 10).await.unwrap();
        assert_eq!(rows.len(), 1, "a re-publish does not unlist the pack");
    }

    #[tokio::test]
    #[ignore] // Requires Postgres
    async fn catalog_lists_only_listed_and_pages_by_cursor() {
        let (pool, _serial) = pool().await;
        let mut ids = Vec::new();
        for i in 0..5u8 {
            let (m, bytes, blobs) = pack(&format!("Pack {i}"), &[10 + i]);
            publish(&pool, &m, &bytes, &blobs, i != 2).await; // Pack 2 stays unlisted
            ids.push(m.pack_id.clone());
        }

        let page1 = list_packs(&pool, None, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        let cur = PageCursor {
            published_at_micros: page1[1].published_at_micros,
            pack_id: page1[1].pack_id.clone().try_into().unwrap(),
        };
        let page2 = list_packs(&pool, Some(&cur), 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        let cur2 = PageCursor {
            published_at_micros: page2[1].published_at_micros,
            pack_id: page2[1].pack_id.clone().try_into().unwrap(),
        };
        let page3 = list_packs(&pool, Some(&cur2), 2).await.unwrap();
        assert!(page3.is_empty(), "four listed packs fit in two pages");

        let seen: Vec<&Vec<u8>> = page1
            .iter()
            .chain(page2.iter())
            .map(|r| &r.pack_id)
            .collect();
        assert_eq!(seen.len(), 4);
        assert!(
            !seen.contains(&&ids[2]),
            "the unlisted pack is not in the catalog"
        );
        let mut distinct = seen.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 4, "no pack appears on two pages");

        // Unlisted is still served: a message that references it must keep resolving.
        assert!(get_manifest_bytes(&pool, &ids[2]).await.unwrap().is_some());

        // Withdraw one and it leaves the catalog without leaving the store.
        assert!(set_listed(&pool, &ids[0], false).await.unwrap());
        let after = list_packs(&pool, None, 10).await.unwrap();
        assert_eq!(after.len(), 3);
        assert!(get_manifest_bytes(&pool, &ids[0]).await.unwrap().is_some());
        assert!(
            !set_listed(&pool, &[0u8; 32], true).await.unwrap(),
            "unknown pack flips nothing"
        );
    }

    #[tokio::test]
    #[ignore] // Requires Postgres
    async fn schema_refuses_what_the_rules_refuse() {
        let (pool, _serial) = pool().await;
        // A 31-byte hash and an oversized blob both die at the CHECK, whatever the code did.
        let r = sqlx::query(
            "INSERT INTO sticker_blobs (sha256, bytes, width, height) VALUES ($1, $2, 512, 512)",
        )
        .bind(&[0u8; 31][..])
        .bind(&[1u8; 10][..])
        .execute(&pool)
        .await;
        assert!(r.is_err(), "31-byte sha256");
        let r = sqlx::query(
            "INSERT INTO sticker_blobs (sha256, bytes, width, height) VALUES ($1, $2, 512, 512)",
        )
        .bind(&[0u8; 32][..])
        .bind(&vec![1u8; rules::MAX_BLOB_BYTES + 1][..])
        .execute(&pool)
        .await;
        assert!(r.is_err(), "over 100 KiB");
    }
}
