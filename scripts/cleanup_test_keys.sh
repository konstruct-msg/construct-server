#!/usr/bin/env bash
set -euo pipefail

# Clean up ephemeral test keys after testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../prkeys"

echo "Cleaning up test keys..."

if [ -d "$KEYS_DIR" ]; then
    rm -f "$KEYS_DIR/paseto_private_key.pem"
    rm -f "$KEYS_DIR/paseto_public_key.pem"
fi

echo "Test keys removed"
