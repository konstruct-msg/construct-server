//! The server's half of server keys rooted offline: sign with a key the offline root delegated.
//!
//! Decision: construct-docs `decisions/server-keys-rooted-offline-and-hybrid.md`. Until it, sender
//! certificates and KT tree heads were signed with one Ed25519 key (`BUNDLE_SIGNING_KEY`) that
//! clients learned from this server's own `/.well-known`. Now each purpose has its own hybrid
//! (Ed25519 ‖ ML-DSA-65) key, and clients accept it only through a **delegation** the offline root
//! signed — a file this server serves but cannot have made.
//!
//! The bytes are not written here: what a key signs (`label ‖ kid ‖ body`), the bodies and the
//! delegation encoding are the `construct-server-trust` crate, shared with construct-core and the
//! root tool, and pinned by construct-protos `conformance/knst_server_trust.json`.
//!
//! ## Configuration
//!
//! - `SERVER_TRUST_<PURPOSE>_KEY` — base64 of the key's two 32-byte seeds (Ed25519 ‖ ML-DSA-65),
//!   made on this server by `server-trust-key`. `SENDER_CERT` in identity-service, `KT_HEAD` in
//!   key-service.
//! - `SERVER_TRUST_DIR` (default `/etc/construct/server-trust`) — the delegations, one hex
//!   `*.delegation` file each, as the root ceremony produced them. One directory for every
//!   service: a signer picks the delegation of its own key, the gateway serves them all.
//! - `SERVER_TRUST_ROOTS` (optional) — comma-separated hex of the pinned roots. When set, a
//!   delegation no root signed is refused at start, so a wrong file is found here rather than by
//!   every client.
//!
//! Absent key → no signer: the service keeps signing with the Ed25519 key alone, as before.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::Zeroizing;

pub use construct_server_trust::{
    Delegation, KID_LEN, Kid, Purpose, SENDER_CERT_MAX_LIFETIME_SECS, fingerprint, kid_of,
    kt_head_body, sender_cert_body, server_signable,
};

use crate::pqc::hybrid::{
    hybrid_sign, hybrid_signature_keypair_from_seeds, verify_hybrid_signature,
};

/// Where the delegations are when `SERVER_TRUST_DIR` is unset.
pub const DEFAULT_TRUST_DIR: &str = "/etc/construct/server-trust";

/// The env var holding the seeds of the key for `purpose`.
pub fn key_env(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::SenderCert => "SERVER_TRUST_SENDER_CERT_KEY",
        Purpose::KtHead => "SERVER_TRUST_KT_HEAD_KEY",
        Purpose::StickerManifest => "SERVER_TRUST_STICKER_MANIFEST_KEY",
    }
}

/// The configured delegation directory.
pub fn trust_dir() -> PathBuf {
    std::env::var("SERVER_TRUST_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TRUST_DIR))
}

/// Every `*.delegation` file in `dir`, decoded. A file that does not decode is an error: the
/// directory is written by hand from the ceremony, and a damaged file should stop the deploy.
pub fn load_delegations(dir: &Path) -> Result<Vec<Delegation>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "delegation"))
        .collect();
    paths.sort();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let bytes =
            hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?;
        let d = Delegation::decode(&bytes)
            .map_err(|_| anyhow!("{} is not a delegation", path.display()))?;
        out.push(d);
    }
    Ok(out)
}

/// The delegations a client may still need at `now`: those whose window has not closed longer
/// ago than their purpose's grace. What `/.well-known` serves — a certificate signed on a key's
/// last day still opens a session a week later, so its delegation is served that long too.
pub fn servable_delegations(delegations: Vec<Delegation>, now: i64) -> Vec<Delegation> {
    delegations
        .into_iter()
        .filter(|d| match d.purpose.grace_secs() {
            Some(grace) => now <= d.not_after.saturating_add(grace),
            None => true,
        })
        .collect()
}

/// The pinned roots from `SERVER_TRUST_ROOTS`, if set.
pub fn roots_from_env() -> Result<Vec<Vec<u8>>> {
    match std::env::var("SERVER_TRUST_ROOTS") {
        Ok(v) if !v.trim().is_empty() => v
            .split(',')
            .map(|h| hex::decode(h.trim()).context("SERVER_TRUST_ROOTS is not hex"))
            .collect(),
        _ => Ok(Vec::new()),
    }
}

/// Whether one of `roots` signed `delegation`.
pub fn is_rooted(delegation: &Delegation, roots: &[Vec<u8>]) -> bool {
    let message = delegation.signable();
    roots
        .iter()
        .any(|r| verify_hybrid_signature(r, &message, &delegation.root_signature).is_ok())
}

/// A server key the offline root delegated for one purpose, ready to sign.
pub struct DelegatedSigner {
    purpose: Purpose,
    private_key: Zeroizing<Vec<u8>>,
    kid: Kid,
    not_before: i64,
    not_after: i64,
}

impl std::fmt::Debug for DelegatedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedSigner")
            .field("purpose", &self.purpose.name())
            .field("kid", &hex::encode(self.kid))
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl DelegatedSigner {
    /// The signer for `seeds`, with the delegation among `delegations` that names its key for
    /// `purpose`. With `roots`, that delegation must also be signed by one of them.
    pub fn new(
        purpose: Purpose,
        seeds: &[u8; 64],
        delegations: &[Delegation],
        roots: &[Vec<u8>],
    ) -> Result<Self> {
        let (private_key, public_key) = hybrid_signature_keypair_from_seeds(
            seeds[..32].try_into().expect("32"),
            seeds[32..].try_into().expect("32"),
        );
        let private_key = Zeroizing::new(private_key);
        let kid = kid_of(&public_key);
        let d = delegations
            .iter()
            .filter(|d| d.purpose == purpose && d.public_key == public_key)
            .max_by_key(|d| d.not_after)
            .ok_or_else(|| {
                anyhow!(
                    "no delegation for the {} key {} (kid {}) — run the root ceremony for it",
                    purpose.name(),
                    fingerprint(&public_key),
                    hex::encode(kid)
                )
            })?;
        if !roots.is_empty() && !is_rooted(d, roots) {
            bail!(
                "the delegation of the {} key (kid {}) is not signed by any SERVER_TRUST_ROOTS root",
                purpose.name(),
                hex::encode(kid)
            );
        }
        Ok(Self {
            purpose,
            private_key,
            kid,
            not_before: d.not_before,
            not_after: d.not_after,
        })
    }

    /// The signer configured for `purpose`, or `None` when its key env var is unset.
    pub fn from_env(purpose: Purpose) -> Result<Option<Self>> {
        let name = key_env(purpose);
        let Some(value) = std::env::var(name).ok().filter(|v| !v.trim().is_empty()) else {
            return Ok(None);
        };
        let raw = Zeroizing::new(
            BASE64
                .decode(value.trim())
                .with_context(|| format!("{name} is not base64"))?,
        );
        let seeds: Zeroizing<[u8; 64]> = Zeroizing::new(
            raw.as_slice()
                .try_into()
                .map_err(|_| anyhow!("{name} must be 64 bytes (two 32-byte seeds)"))?,
        );
        let delegations = load_delegations(&trust_dir())?;
        Self::new(purpose, &seeds, &delegations, &roots_from_env()?).map(Some)
    }

    /// The id of the key, named in every signature it makes.
    pub fn kid(&self) -> Kid {
        self.kid
    }

    /// When the key's delegation ends; renew before it.
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// Sign `body` as made at `signed_at`. Refuses outside the delegation's window: a signature
    /// dated there would be refused by every client, so issuing it only hides the outage.
    pub fn sign(&self, body: &[u8], signed_at: i64) -> Result<Vec<u8>> {
        if signed_at < self.not_before || signed_at > self.not_after {
            bail!(
                "the {} key (kid {}) is delegated for {}..{}, not {signed_at} — renew it",
                self.purpose.name(),
                hex::encode(self.kid),
                self.not_before,
                self.not_after
            );
        }
        hybrid_sign(
            &self.private_key,
            &server_signable(self.purpose, &self.kid, body),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // construct-protos conformance/knst_server_trust.json — produced by construct-core. The server
    // key, the kid and the root here are rebuilt from the file's seeds; the root's signature over
    // the delegation and the core's signature over the certificate are checked as given.
    const ROOT_SEEDS: ([u8; 32], [u8; 32]) = ([0x11; 32], [0x12; 32]);
    const SERVER_SEEDS: [u8; 64] = {
        let mut s = [0x21; 64];
        let mut i = 32;
        while i < 64 {
            s[i] = 0x22;
            i += 1;
        }
        s
    };
    const VECTORS: &str = include_str!("../tests/knst_server_trust.json");
    const NOT_BEFORE: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn v() -> serde_json::Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn unhex(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    fn vector_delegations() -> Vec<Delegation> {
        v()["delegations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| Delegation::decode(&unhex(&d["encoded"])).unwrap())
            .collect()
    }

    fn root() -> Vec<u8> {
        hybrid_signature_keypair_from_seeds(&ROOT_SEEDS.0, &ROOT_SEEDS.1).1
    }

    #[test]
    fn the_seeds_rebuild_the_vectors_keys() {
        let v = v();
        assert_eq!(unhex(&v["root"]["public_key"]), root());
        let (_, server_pk) = hybrid_signature_keypair_from_seeds(
            SERVER_SEEDS[..32].try_into().unwrap(),
            SERVER_SEEDS[32..].try_into().unwrap(),
        );
        assert_eq!(unhex(&v["server_key"]["public_key"]), server_pk);
        assert_eq!(unhex(&v["server_key"]["kid"]), kid_of(&server_pk));
    }

    #[test]
    fn the_cores_signatures_verify_here() {
        let v = v();
        for d in vector_delegations() {
            assert!(is_rooted(&d, &[root()]), "{} delegation", d.purpose.name());
        }
        let key = unhex(&v["server_key"]["public_key"]);
        for s in v["signatures"].as_array().unwrap() {
            assert!(
                verify_hybrid_signature(&key, &unhex(&s["signable"]), &unhex(&s["signature"]))
                    .is_ok(),
                "{}",
                s["purpose"]
            );
        }
        let f = &v["signatures"][0]["fields"];
        let body = sender_cert_body(
            f["user_id"].as_str().unwrap(),
            f["domain"].as_str().unwrap(),
            &unhex(&f["identity_key"]),
            f["device_id"].as_str().unwrap(),
            f["issued_at"].as_i64().unwrap(),
            f["expires_at"].as_i64().unwrap(),
        )
        .unwrap();
        assert_eq!(body, unhex(&v["signatures"][0]["body"]));
    }

    #[test]
    fn a_signer_signs_what_the_core_accepts() {
        let signer = DelegatedSigner::new(
            Purpose::KtHead,
            &SERVER_SEEDS,
            &vector_delegations(),
            &[root()],
        )
        .unwrap();
        let body = kt_head_body(77, &[3; 32]);
        let sig = signer.sign(&body, NOT_BEFORE + DAY).unwrap();
        let key = unhex(&v()["server_key"]["public_key"]);
        assert!(
            verify_hybrid_signature(
                &key,
                &server_signable(Purpose::KtHead, &signer.kid(), &body),
                &sig
            )
            .is_ok()
        );
    }

    #[test]
    fn a_signer_refuses_outside_its_window() {
        let signer = DelegatedSigner::new(
            Purpose::SenderCert,
            &SERVER_SEEDS,
            &vector_delegations(),
            &[],
        )
        .unwrap();
        assert!(signer.sign(b"x", NOT_BEFORE - 1).is_err());
        assert!(signer.sign(b"x", NOT_BEFORE + 90 * DAY + 1).is_err());
        assert!(signer.sign(b"x", NOT_BEFORE + 90 * DAY).is_ok());
    }

    #[test]
    fn a_key_without_its_delegation_or_root_is_refused() {
        let other = [0x33; 64];
        assert!(DelegatedSigner::new(Purpose::KtHead, &other, &vector_delegations(), &[]).is_err());
        assert!(
            DelegatedSigner::new(
                Purpose::StickerManifest,
                &SERVER_SEEDS,
                &vector_delegations(),
                &[]
            )
            .is_err(),
            "no sticker delegation in the vectors"
        );
        let stranger = hybrid_signature_keypair_from_seeds(&[0x44; 32], &[0x45; 32]).1;
        assert!(
            DelegatedSigner::new(
                Purpose::KtHead,
                &SERVER_SEEDS,
                &vector_delegations(),
                &[stranger]
            )
            .is_err()
        );
    }

    #[test]
    fn a_lapsed_delegation_is_served_only_through_its_grace() {
        let ds = vector_delegations(); // sender-cert and kt-head, both closing at NOT_BEFORE + 90d
        let closed = NOT_BEFORE + 90 * DAY;
        assert_eq!(servable_delegations(ds.clone(), closed).len(), 2);
        let next_day = servable_delegations(ds.clone(), closed + 1);
        assert_eq!(next_day.len(), 1);
        assert_eq!(next_day[0].purpose, Purpose::SenderCert);
        assert!(servable_delegations(ds, closed + 8 * DAY + 1).is_empty());
    }

    #[test]
    fn delegations_load_from_a_directory() {
        let dir = std::env::temp_dir().join(format!("server-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (i, d) in vector_delegations().iter().enumerate() {
            std::fs::write(
                dir.join(format!("{i}.delegation")),
                hex::encode(d.encode()) + "\n",
            )
            .unwrap();
        }
        std::fs::write(dir.join("README"), "not a delegation").unwrap();
        let loaded = load_delegations(&dir).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(loaded, vector_delegations());
        assert!(
            load_delegations(Path::new("/nonexistent/server-trust"))
                .unwrap()
                .is_empty()
        );
    }
}
