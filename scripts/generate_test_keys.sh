#!/usr/bin/env bash
set -euo pipefail

# Generate ephemeral PASETO v4.public (Ed25519) test keys for CI/CD and local testing.
# These keys must never be committed to git.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../prkeys"

echo "Generating test keys..."

mkdir -p "$KEYS_DIR"

openssl genpkey -algorithm ed25519 -out "$KEYS_DIR/paseto_private_key.pem" 2>/dev/null
openssl pkey -in "$KEYS_DIR/paseto_private_key.pem" -pubout -out "$KEYS_DIR/paseto_public_key.pem" 2>/dev/null

chmod 600 "$KEYS_DIR/paseto_private_key.pem"
chmod 644 "$KEYS_DIR/paseto_public_key.pem"

echo "Test keys generated in $KEYS_DIR:"
echo "   - paseto_private_key.pem (Ed25519)"
echo "   - paseto_public_key.pem"
