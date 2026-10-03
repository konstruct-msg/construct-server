//! `server-trust-key` — make a server key for the root to delegate, and see what is delegated.
//!
//! ```text
//! server-trust-key new --purpose sender-cert|kt-head [--dir DIR]
//!     writes <purpose>-<kid>.key (base64 seeds, 0600 — the value of SERVER_TRUST_<PURPOSE>_KEY)
//!     and <purpose>-<kid>.pub (hex — carried to the offline root, construct-docs
//!     manuals&instructions/server-root-key-ceremony.md §4)
//! server-trust-key list [--dir DIR]
//!     the delegations in SERVER_TRUST_DIR (or DIR): purpose, kid, window, days left, and whether
//!     a SERVER_TRUST_ROOTS root signed each
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use construct_crypto::pqc::hybrid::hybrid_signature_keypair_from_seeds;
use construct_crypto::server_trust::{
    Purpose, fingerprint, is_rooted, key_env, kid_of, load_delegations, roots_from_env, trust_dir,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = value(&args, "--dir").map(PathBuf::from);
    let result = match args.first().map(String::as_str) {
        Some("new") => new_key(&args, dir.unwrap_or_else(|| PathBuf::from("."))),
        Some("list") => list(&dir.unwrap_or_else(trust_dir)),
        _ => Err("usage: server-trust-key new --purpose sender-cert|kt-head [--dir DIR] | list [--dir DIR]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn new_key(args: &[String], dir: PathBuf) -> Result<(), String> {
    let name = value(args, "--purpose").ok_or("--purpose is required")?;
    let purpose = Purpose::from_name(name).ok_or_else(|| format!("unknown purpose {name}"))?;
    if purpose == Purpose::StickerManifest {
        return Err("sticker manifests are signed at publish time, not by a service".into());
    }
    let mut seeds = Zeroizing::new([0u8; 64]);
    OsRng.fill_bytes(seeds.as_mut());
    let (_, public) = hybrid_signature_keypair_from_seeds(
        seeds[..32].try_into().expect("32"),
        seeds[32..].try_into().expect("32"),
    );
    let kid = hex::encode(kid_of(&public));
    let stem = format!("{}-{}", purpose.name(), &kid[..8]);
    let key_path = dir.join(format!("{stem}.key"));
    let pub_path = dir.join(format!("{stem}.pub"));
    for p in [&key_path, &pub_path] {
        if p.exists() {
            return Err(format!("{} exists — refusing to overwrite", p.display()));
        }
    }
    write_secret(&key_path, &Zeroizing::new(BASE64.encode(seeds.as_ref())))?;
    std::fs::write(&pub_path, hex::encode(&public) + "\n")
        .map_err(|e| format!("{}: {e}", pub_path.display()))?;

    println!("Purpose:      {}", purpose.name());
    println!("Fingerprint:  {}", fingerprint(&public));
    println!("Key id (kid): {kid}");
    println!();
    println!(
        "{}  → the value of {} (0600; then delete the file)",
        key_path.display(),
        key_env(purpose)
    );
    println!(
        "{}  → carry to the offline root for `konstruct-root delegate`",
        pub_path.display()
    );
    Ok(())
}

fn list(dir: &Path) -> Result<(), String> {
    let delegations = load_delegations(dir).map_err(|e| format!("{e:#}"))?;
    let roots = roots_from_env().map_err(|e| format!("{e:#}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if delegations.is_empty() {
        println!("no delegations in {}", dir.display());
    }
    for d in delegations {
        let rooted = if roots.is_empty() {
            "roots not configured"
        } else if is_rooted(&d, &roots) {
            "rooted"
        } else {
            "NOT ROOTED"
        };
        println!(
            "{:<17} kid {}  {} → {}  days left {:>4}  {rooted}",
            d.purpose.name(),
            hex::encode(d.kid()),
            d.not_before,
            d.not_after,
            (d.not_after - now) / 86_400,
        );
    }
    Ok(())
}

fn write_secret(path: &Path, value: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(f, "{value}").map_err(|e| e.to_string())
}
