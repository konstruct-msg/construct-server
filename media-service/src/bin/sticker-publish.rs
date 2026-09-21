// ============================================================================
// sticker-publish — sign a built pack and put it in the store
// ============================================================================
//
// The second half of the pipeline. `construct-messenger/scripts/build_sticker_pack.py`
// normalises the art into content-addressed 512×512 WebP blobs and a `pack.json` a human
// fills the emoji into; this tool turns that directory into a signed StickerPackManifest and
// two tables' worth of rows.
//
//   sticker-publish <pack_dir> [--dry-run] [--unlisted] [--out <manifest.pb>]
//
//   <pack_dir>     pack.json + blobs/<sha256>.webp, as the build script wrote them
//   --dry-run      build, hash, sign, print — touch no database
//   --unlisted     insert but leave `listed = false` (withheld from the catalog)
//   --out PATH     also write the signed manifest bytes to PATH
//
//   BUNDLE_SIGNING_KEY          base64, 32-byte Ed25519 seed — the key key-service signs
//                               prekey bundles with and identity-service signs sender
//                               certificates with; clients pin its public half
//   BUNDLE_SIGNING_PUBLIC_KEY   optional, base64; when set the seed must derive it, as
//                               identity-service checks at boot
//   DATABASE_URL                unless --dry-run
//
// This tool holds the key; media-service never does. A compromised service can then hide
// packs but cannot mint one.
//
// Order of writes matters and is the reason `listed` exists: blobs first (idempotent by
// hash), then the pack row unlisted, then the flip. A run that dies half-way leaves a pack
// that GetStickerPackManifest can serve and the catalog does not show; re-running finishes
// it. The same pack_id published twice is a no-op except for the manifest bytes, which is
// how a re-signed manifest lands after a key rotation.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as b64;
use ed25519_compact::{KeyPair, Seed};
use prost::Message;
use serde::Deserialize;

use construct_server_shared::shared::proto::messaging::v1::{StickerEntry, StickerPackManifest};
use media_service::stickers::{self, conformance, rules};

/// `pack.json` as `build_sticker_pack.py` writes it. `canvas` is informational there and is
/// not read here: the blob header is what says how big a sticker is.
#[derive(Deserialize)]
struct PackJson {
    title: String,
    publisher: String,
    stickers: Vec<PackJsonEntry>,
}

#[derive(Deserialize)]
struct PackJsonEntry {
    index: usize,
    #[serde(default)]
    source: String,
    sha256: String,
    emoji: String,
    width: u32,
    height: u32,
    byte_len: u32,
}

struct Args {
    pack_dir: PathBuf,
    dry_run: bool,
    unlisted: bool,
    out: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut pack_dir = None;
    let mut dry_run = false;
    let mut unlisted = false;
    let mut out = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "--unlisted" => unlisted = true,
            "--out" => out = Some(PathBuf::from(it.next().context("--out needs a path")?)),
            "-h" | "--help" => {
                bail!(
                    "usage: sticker-publish <pack_dir> [--dry-run] [--unlisted] [--out <manifest.pb>]"
                )
            }
            s if s.starts_with('-') => bail!("unknown flag {s}"),
            s => {
                if pack_dir.replace(PathBuf::from(s)).is_some() {
                    bail!("one pack directory at a time");
                }
            }
        }
    }
    Ok(Args {
        pack_dir: pack_dir.context(
            "usage: sticker-publish <pack_dir> [--dry-run] [--unlisted] [--out <manifest.pb>]",
        )?,
        dry_run,
        unlisted,
        out,
    })
}

/// A blob read, checked against everything `pack.json` claims about it and against the rules.
struct LoadedBlob {
    sha256: [u8; 32],
    bytes: Vec<u8>,
    header: stickers::WebPHeader,
}

fn load_blob(dir: &Path, entry: &PackJsonEntry) -> Result<LoadedBlob> {
    let label = if entry.source.is_empty() {
        format!("sticker {}", entry.index)
    } else {
        format!("sticker {} ({})", entry.index, entry.source)
    };
    let claimed =
        hex::decode(&entry.sha256).with_context(|| format!("{label}: sha256 is not hex"))?;
    let claimed: [u8; 32] = claimed
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{label}: sha256 is {} bytes, not 32", v.len()))?;

    let path = dir.join("blobs").join(format!("{}.webp", entry.sha256));
    let bytes =
        std::fs::read(&path).with_context(|| format!("{label}: reading {}", path.display()))?;

    let header = stickers::validate_blob(&bytes).with_context(|| format!("{label}: refused"))?;
    let actual = stickers::sha256(&bytes);
    if actual != claimed {
        bail!(
            "{label}: file hashes to {}, pack.json says {}",
            hex::encode(actual),
            entry.sha256
        );
    }
    if bytes.len() != entry.byte_len as usize {
        bail!(
            "{label}: file is {} bytes, pack.json says {}",
            bytes.len(),
            entry.byte_len
        );
    }
    if (header.width, header.height) != (entry.width, entry.height) {
        bail!(
            "{label}: file is {}×{}, pack.json says {}×{}",
            header.width,
            header.height,
            entry.width,
            entry.height
        );
    }
    if entry.emoji.is_empty() {
        bail!("{label}: emoji is empty — fill it in pack.json; there is no way to derive it");
    }
    Ok(LoadedBlob {
        sha256: claimed,
        bytes,
        header,
    })
}

fn load_signing_key() -> Result<KeyPair> {
    let seed_b64 = std::env::var("BUNDLE_SIGNING_KEY").context(
        "BUNDLE_SIGNING_KEY not set — the publish step signs, and only the publish step",
    )?;
    let seed = b64
        .decode(seed_b64.trim())
        .context("BUNDLE_SIGNING_KEY is not base64")?;
    let seed: [u8; 32] = seed.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("BUNDLE_SIGNING_KEY must be 32 bytes, got {}", v.len())
    })?;
    let kp = KeyPair::from_seed(Seed::new(seed));

    // Same guard identity-service applies at boot: the key we sign with must be the key the
    // gateway publishes, or every client refuses every pack.
    if let Ok(published) = std::env::var("BUNDLE_SIGNING_PUBLIC_KEY") {
        let ours = b64.encode(kp.pk.as_ref());
        if ours != published.trim() {
            bail!(
                "BUNDLE_SIGNING_KEY derives public key {ours}, but BUNDLE_SIGNING_PUBLIC_KEY is {} — \
                 a pack signed with this key would fail verification on every client",
                published.trim()
            );
        }
    }
    Ok(kp)
}

fn build(args: &Args) -> Result<(StickerPackManifest, Vec<u8>, Vec<LoadedBlob>)> {
    let json_path = args.pack_dir.join("pack.json");
    let json: PackJson = serde_json::from_slice(
        &std::fs::read(&json_path).with_context(|| format!("reading {}", json_path.display()))?,
    )
    .with_context(|| format!("parsing {}", json_path.display()))?;

    // The order *is* the pack: StickerRef.index points into it. Require the indices to be
    // exactly 0..n in file order so a hand-edited pack.json cannot silently renumber.
    for (i, e) in json.stickers.iter().enumerate() {
        if e.index != i {
            bail!(
                "pack.json: entry at position {i} has index {} — indices must be 0..n in order",
                e.index
            );
        }
    }
    if json.stickers.is_empty() {
        bail!("pack.json: no stickers");
    }
    if json.stickers.len() > rules::MAX_STICKERS {
        bail!(
            "pack.json: {} stickers, ceiling is {}",
            json.stickers.len(),
            rules::MAX_STICKERS
        );
    }

    let mut blobs = Vec::with_capacity(json.stickers.len());
    let mut entries = Vec::with_capacity(json.stickers.len());
    for e in &json.stickers {
        let blob = load_blob(&args.pack_dir, e)?;
        entries.push(StickerEntry {
            sha256: blob.sha256.to_vec(),
            emoji: e.emoji.clone(),
            width: blob.header.width,
            height: blob.header.height,
            byte_len: blob.bytes.len() as u32,
        });
        blobs.push(blob);
    }

    let mut manifest = StickerPackManifest {
        pack_id: vec![],
        title: json.title,
        publisher: json.publisher,
        stickers: entries,
        signature: vec![],
    };
    manifest.pack_id = stickers::pack_id(&manifest).to_vec();
    stickers::validate_manifest(&manifest).context("manifest refused")?;

    let kp = load_signing_key()?;
    let canonical = stickers::canonical_bytes(&manifest);
    let signature = kp.sk.sign(&canonical, None);
    kp.pk
        .verify(&canonical, &signature)
        .context("freshly made signature does not verify — refusing to publish")?;
    manifest.signature = signature.to_vec();

    let manifest_bytes = manifest.encode_to_vec();
    // What we store is what the client re-hashes. Decode it back and re-derive the id from the
    // stored bytes, so the row and the name agree by construction, not by assumption.
    let back =
        StickerPackManifest::decode(manifest_bytes.as_slice()).context("re-decoding manifest")?;
    if stickers::pack_id(&back) != manifest.pack_id.as_slice() {
        bail!("manifest bytes do not round-trip to their own pack_id");
    }

    Ok((manifest, manifest_bytes, blobs))
}

async fn publish(
    manifest: &StickerPackManifest,
    manifest_bytes: &[u8],
    blobs: &[LoadedBlob],
    list: bool,
) -> Result<()> {
    let url = std::env::var("DATABASE_URL").context("DATABASE_URL not set (or use --dry-run)")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("connecting to DATABASE_URL")?;

    for b in blobs {
        stickers::insert_blob(&pool, &b.sha256, &b.bytes, b.header).await?;
    }
    stickers::upsert_pack_unlisted(&pool, manifest, manifest_bytes).await?;
    if list {
        let flipped = stickers::set_listed(&pool, &manifest.pack_id, true).await?;
        if !flipped {
            bail!("pack row vanished between insert and listing");
        }
    }
    Ok(())
}

async fn run() -> Result<()> {
    // Before anything is signed: this binary must name the fixture pack the way every client
    // does, or a real pack would be named differently on every device that fetched it.
    conformance::self_check()?;

    let args = parse_args()?;
    let (manifest, manifest_bytes, blobs) = build(&args)?;
    let total: u64 = blobs.iter().map(|b| b.bytes.len() as u64).sum();

    println!(
        "\n  {} — {} stickers, {} KB",
        manifest.title,
        manifest.stickers.len(),
        total / 1024
    );
    println!("  publisher  {}", manifest.publisher);
    println!("  pack_id    {}", hex::encode(&manifest.pack_id));
    println!("  signature  {}…", hex::encode(&manifest.signature[..8]));
    println!("  manifest   {} bytes", manifest_bytes.len());
    for (i, e) in manifest.stickers.iter().enumerate() {
        println!(
            "  {i:>3}  {}  {:>5} B  {}…",
            e.emoji,
            e.byte_len,
            hex::encode(&e.sha256[..8])
        );
    }

    if let Some(out) = &args.out {
        std::fs::write(out, &manifest_bytes)
            .with_context(|| format!("writing {}", out.display()))?;
        println!("\n  wrote {}", out.display());
    }

    if args.dry_run {
        println!("\n  dry run — nothing published\n");
        return Ok(());
    }

    publish(&manifest, &manifest_bytes, &blobs, !args.unlisted).await?;
    println!(
        "\n  published{}\n",
        if args.unlisted {
            " (unlisted)"
        } else {
            " and listed"
        }
    );
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\n  refused: {e:#}\n");
            ExitCode::FAILURE
        }
    }
}
