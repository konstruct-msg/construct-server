#!/usr/bin/env python3
"""
Federation Integration Test — Two-Server Sealed Sender Delivery

Tests that server A can send a sealed sender message to server B via the
S2S federation protocol, and that server B delivers it locally.

Usage:
    ./scripts/test-federation.py \
        --server-a https://a.example.com \
        --server-b https://b.example.com \
        [--signing-key <base64>]

The signing key is the Ed25519 seed for server A. If not provided,
a new keypair is generated and the .well-known is fetched from server B
for the verification step.

Dependencies: pip install protobuf requests ed25519
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid

try:
    import requests
except ImportError:
    print("Missing requests. Install: pip install requests")
    sys.exit(1)

try:
    import ed25519
except ImportError:
    print("Missing ed25519. Install: pip install ed25519")
    sys.exit(1)


PASS = 0
FAIL = 0


def ok(msg: str):
    global PASS
    PASS += 1
    print(f"  ✅ {msg}")


def fail(msg: str):
    global FAIL
    FAIL += 1
    print(f"  ❌ {msg}")


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def main():
    parser = argparse.ArgumentParser(description="Federation two-VPS integration test")
    parser.add_argument("--server-a", required=True, help="URL of server A (origin)")
    parser.add_argument("--server-b", required=True, help="URL of server B (destination)")
    parser.add_argument("--signing-key", help="Base64 Ed25519 seed for server A")
    args = parser.parse_args()

    server_a = args.server_a.rstrip("/")
    server_b = args.server_b.rstrip("/")

    print(f"Testing federation: {server_a} → {server_b}")
    print()

    # ── Step 1: Verify .well-known/konstruct on both servers ─────────────
    print("1. Checking .well-known/konstruct...")

    for label, url in [("A", server_a), ("B", server_b)]:
        try:
            r = requests.get(f"{url}/.well-known/konstruct", timeout=10)
            r.raise_for_status()
            data = r.json()
            fed = data.get("federation", {})
            if fed.get("enabled"):
                ok(f"Server {label}: federation enabled, public_key={fed.get('public_key', '')[:16]}...")
            else:
                fail(f"Server {label}: federation NOT enabled")
        except Exception as e:
            fail(f"Server {label}: .well-known fetch failed: {e}")

    # ── Step 2: Fetch server B's public key ──────────────────────────────
    print("\n2. Fetching server B's public key...")
    try:
        r = requests.get(f"{server_b}/.well-known/konstruct", timeout=10)
        r.raise_for_status()
        data = r.json()
        server_b_pubkey_b64 = data.get("public_key") or data.get("federation", {}).get("public_key")
        if server_b_pubkey_b64:
            ok(f"Server B public key: {server_b_pubkey_b64[:16]}...")
        else:
            fail("No public_key in server B .well-known")
            sys.exit(1)
    except Exception as e:
        fail(f"Failed to fetch server B .well-known: {e}")
        sys.exit(1)

    # ── Step 3: Generate signing key for server A ─────────────────────────
    print("\n3. Preparing signing key for server A...")
    if args.signing_key:
        seed_b64 = args.signing_key
        seed_bytes = base64.b64decode(seed_b64)
        sk = ed25519.SigningKey(seed_bytes)
        vk = sk.get_verifying_key()
        server_a_pubkey_b64 = base64.b64encode(vk.to_bytes()).decode()
        ok(f"Using provided signing key, public_key={server_a_pubkey_b64[:16]}...")
    else:
        # Generate ephemeral keypair
        seed_bytes = os.urandom(32)
        sk = ed25519.SigningKey(seed_bytes)
        vk = sk.get_verifying_key()
        server_a_pubkey_b64 = base64.b64encode(vk.to_bytes()).decode()
        ok(f"Generated ephemeral key, public_key={server_a_pubkey_b64[:16]}...")
        print("  ⚠️  Using ephemeral key — server B will reject without the correct .well-known config")

    # ── Step 4: Build sealed sender payload ───────────────────────────────
    print("\n4. Building sealed sender payload...")

    # Build a minimal SealedInner (custom binary format for test — in production
    # this would use protobuf serialization of shared.proto.core.v1.SealedInner)
    recipient_user_id = "00000000-0000-0000-0000-000000000000"  # placeholder
    delivery_tag = os.urandom(32)
    sealed_inner = {
        "recipient_user_id": recipient_user_id,
        "delivery_tag": delivery_tag.hex(),
        "sender_certificate": base64.b64encode(b"test-sender-cert").decode(),
        "ciphertext": base64.b64encode(b"hello from alice — E2E encrypted").decode(),
    }
    # For test purposes, use JSON as opaque blob (in production this is protobuf)
    sealed_inner_json = json.dumps(sealed_inner).encode()
    sealed_inner_b64 = base64.b64encode(sealed_inner_json).decode()

    message_id = str(uuid.uuid4())
    timestamp = int(time.time())

    # Compute payload_hash = SHA-256 of base64(sealed_inner)
    payload_hash = sha256_b64(sealed_inner_b64.encode())

    ok(f"Message ID: {message_id}")
    ok(f"Payload hash: {payload_hash[:16]}...")

    # ── Step 5: Sign the FederatedEnvelope ───────────────────────────────
    print("\n5. Signing FederatedEnvelope with server A's key...")

    # Canonical: message_id:from:to:origin:dest:timestamp:payload_hash
    canonical = f"{message_id}:::a.example:{server_b.replace('https://', '')}:{timestamp}:{payload_hash}"
    signature = sk.sign(canonical.encode())
    signature_b64 = base64.b64encode(signature).decode()
    ok(f"Signature: {signature_b64[:16]}...")

    # ── Step 6: POST /federation/v1/sealed to server B ───────────────────
    print(f"\n6. Sending sealed message to {server_b}/federation/v1/sealed...")

    request_body = {
        "messageId": message_id,
        "sealedInner": sealed_inner_b64,
        "originServer": "a.example",
        "timestamp": timestamp,
        "payloadHash": payload_hash,
        "serverSignature": signature_b64,
    }

    try:
        r = requests.post(
            f"{server_b}/federation/v1/sealed",
            json=request_body,
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        if r.status_code == 200:
            resp = r.json()
            ok(f"Accepted! local message_id={resp.get('messageId', 'unknown')}")
        else:
            fail(f"Server returned HTTP {r.status_code}: {r.text}")
    except Exception as e:
        fail(f"HTTP request failed: {e}")

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print(f"Results: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
