#!/usr/bin/env bash
set -euo pipefail

# Clean up ephemeral test keys after testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../shared/tests/keys"
JWT_KEYS_DIR="$SCRIPT_DIR/../prkeys"

echo "🧹 Cleaning up test keys..."

# Clean auth test keys
if [ -d "$KEYS_DIR" ]; then
    rm -f "$KEYS_DIR/test_private.pem"
    rm -f "$KEYS_DIR/test_public.pem"
fi

# Clean JWT test keys
if [ -d "$JWT_KEYS_DIR" ]; then
    rm -f "$JWT_KEYS_DIR/jwt_private_key.pem"
    rm -f "$JWT_KEYS_DIR/jwt_public_key.pem"
fi

echo "✅ Test keys removed"
