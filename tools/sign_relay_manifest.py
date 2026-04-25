#!/usr/bin/env python3
"""
sign_relay_manifest.py — Construct relay manifest signing tool

Usage:
  # One-time: generate relay signing keypair
  python3 sign_relay_manifest.py keygen

  # Sign / update a manifest
  python3 sign_relay_manifest.py sign relays.json --key relay_signing_key.hex

  # Verify an existing manifest (no key required)
  python3 sign_relay_manifest.py verify .well-known/construct-server

The signed output goes to .well-known/construct-server (or --out path).
Deploy that file to:
  - construct-relay GitHub repo  (IceCertFetcher mirror)
  - konstructs.cc/.well-known/   (primary URL)

Private key (relay_signing_key.hex) must NEVER be committed or deployed to any server.
Store it in a password manager / offline backup.

Public key is hardcoded in the iOS app: ICEConfig.relayConfigSigningKey
"""

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )
except ImportError:
    print("ERROR: cryptography library not found.")
    print("Install with:  pip3 install cryptography")
    sys.exit(1)


# ── helpers ──────────────────────────────────────────────────────────────────

def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load Ed25519 private key from hex file (32-byte seed)."""
    hex_str = Path(path).read_text().strip()
    seed = bytes.fromhex(hex_str)
    if len(seed) != 32:
        raise ValueError(f"Expected 32-byte seed, got {len(seed)} bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_hex(sk: Ed25519PrivateKey) -> str:
    raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw.hex()


def sign_manifest(payload: dict, sk: Ed25519PrivateKey) -> dict:
    """
    Sign the manifest. Signature covers canonical JSON with 'signature' field absent.
    Canonical = sorted keys, no Unicode escaping, no whitespace.
    """
    payload_copy = {k: v for k, v in payload.items() if k != "signature"}
    canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    sig_bytes = sk.sign(canonical)
    # base64url, no padding
    sig_b64url = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    payload_copy["signature"] = f"ed25519:{sig_b64url}"
    return payload_copy


def verify_manifest(payload: dict, pubkey_hex: str) -> bool:
    """Verify an already-signed manifest. Returns True if valid."""
    sig_field = payload.get("signature", "")
    if not sig_field.startswith("ed25519:"):
        return False
    b64url = sig_field[len("ed25519:"):]
    # restore padding
    pad = 4 - len(b64url) % 4
    if pad != 4:
        b64url += "=" * pad
    sig_bytes = base64.urlsafe_b64decode(b64url)

    payload_copy = {k: v for k, v in payload.items() if k != "signature"}
    canonical = json.dumps(payload_copy, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")

    pub_bytes = bytes.fromhex(pubkey_hex)
    pubkey = Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        pubkey.verify(sig_bytes, canonical)
        return True
    except Exception:
        return False


# ── subcommands ──────────────────────────────────────────────────────────────

def cmd_keygen(args):
    """Generate a new relay manifest signing keypair."""
    out_path = Path(args.out) if args.out else Path("relay_signing_key.hex")
    if out_path.exists() and not args.force:
        print(f"ERROR: {out_path} already exists. Use --force to overwrite.")
        sys.exit(1)

    seed = os.urandom(32)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub_hex = public_key_hex(sk)

    out_path.write_text(seed.hex())
    print(f"✅ Private key (seed) written to: {out_path}")
    print(f"   Keep this file OFFLINE. Never commit or deploy it.\n")
    print(f"📢 Public key (hex) — hardcode in ICEConfig.relayConfigSigningKey:")
    print(f"   {pub_hex}")


def cmd_sign(args):
    """Sign a relays.json file and write the manifest."""
    sk = load_private_key(args.key)
    pub_hex = public_key_hex(sk)

    relays_path = Path(args.relays_json)
    if not relays_path.exists():
        print(f"ERROR: {relays_path} not found")
        sys.exit(1)

    relays_data = json.loads(relays_path.read_text())

    # relays_data can be either a list of relay objects OR a full manifest dict
    if isinstance(relays_data, list):
        relays = relays_data
    elif isinstance(relays_data, dict) and "relays" in relays_data:
        relays = relays_data["relays"]
    else:
        print("ERROR: relays.json must be a list of relay objects or {\"relays\": [...]}")
        sys.exit(1)

    # Validate required fields per relay
    required = {"id", "addr", "port", "domain", "sni", "spki_sha256"}
    for i, relay in enumerate(relays):
        missing = required - set(relay.keys())
        if missing:
            print(f"ERROR: relay[{i}] missing fields: {missing}")
            sys.exit(1)

    # Determine next version (increment from existing manifest if present)
    out_path = Path(args.out) if args.out else Path(".well-known/construct-server")
    current_version = 0
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text())
            current_version = int(existing.get("version", 0))
        except Exception:
            pass
    new_version = current_version + 1

    payload = {
        "version": new_version,
        "signed_at": int(time.time()),
        "bundle_signing_key": args.bundle_signing_key or None,
        "ice": {
            "relays": relays
        },
    }

    signed = sign_manifest(payload, sk)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n")

    print(f"✅ Signed manifest written to: {out_path}")
    print(f"   version={new_version}, relays={len(relays)}, signed_at={payload['signed_at']}")
    print(f"   bundle_signing_key={'set' if payload['bundle_signing_key'] else 'null'}")
    print(f"   Public key: {pub_hex}")
    print()
    print("Next steps:")
    print(f"  1. git add {out_path} && git commit -m 'relay: update manifest v{new_version}'")
    print(f"  2. Push to construct-relay GitHub repo (IceCertFetcher mirror)")
    print(f"  3. Copy to construct-landing/.well-known/construct-server and push")
    print()
    print("Tip: pass --bundle-signing-key <base64> to embed the server bundle verification key")
    print("     (get it from the current manifest or 'BUNDLE_SIGNING_PUBLIC_KEY' env var)")


def cmd_verify(args):
    """Verify a signed manifest file."""
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found")
        sys.exit(1)

    payload = json.loads(manifest_path.read_text())
    pubkey_hex = args.pubkey

    if not pubkey_hex:
        # Try to read from ICEConfig.relayConfigSigningKey hint
        print("Tip: pass --pubkey <hex> to verify the signature.")
        print("     ICEConfig.relayConfigSigningKey in Constants.swift")
        print()

    relays = payload.get("ice", {}).get("relays", [])
    version = payload.get("version", "?")
    signed_at = payload.get("signed_at")

    print(f"Manifest version : {version}")
    if signed_at:
        import datetime
        dt = datetime.datetime.utcfromtimestamp(signed_at).strftime("%Y-%m-%d %H:%M UTC")
        print(f"Signed at        : {dt}")
    print(f"Relays           : {len(relays)}")
    for r in relays:
        wt = f" [WebTunnel: {r.get('wt_path')}]" if r.get("wt_path") else ""
        print(f"  • {r.get('id')}: {r.get('addr')}:{r.get('port')} "
              f"sni={r.get('sni')}{wt}")

    if pubkey_hex:
        if verify_manifest(payload, pubkey_hex):
            print(f"\n✅ Signature VALID (pubkey: {pubkey_hex[:16]}…)")
        else:
            print(f"\n❌ Signature INVALID")
            sys.exit(1)
    else:
        print("\n⚠️  Signature not checked (no --pubkey provided)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Construct relay manifest signing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # keygen
    p_keygen = sub.add_parser("keygen", help="Generate a new relay signing keypair")
    p_keygen.add_argument("--out", help="Output path for private key (default: relay_signing_key.hex)")
    p_keygen.add_argument("--force", action="store_true", help="Overwrite existing key file")

    # sign
    p_sign = sub.add_parser("sign", help="Sign a relays.json and produce the manifest")
    p_sign.add_argument("relays_json", help="Path to relays.json (list of relay objects)")
    p_sign.add_argument("--key", required=True, help="Path to private key hex file")
    p_sign.add_argument("--out", help="Output path (default: .well-known/construct-server)")
    p_sign.add_argument(
        "--bundle-signing-key",
        dest="bundle_signing_key",
        default=None,
        help="Base64 Ed25519 public key to embed as bundle_signing_key (for client bundle verification)",
    )

    # verify
    p_verify = sub.add_parser("verify", help="Verify and inspect a signed manifest")
    p_verify.add_argument("manifest", help="Path to signed manifest file")
    p_verify.add_argument("--pubkey", help="Ed25519 public key hex to verify signature")

    args = parser.parse_args()
    {"keygen": cmd_keygen, "sign": cmd_sign, "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    main()
