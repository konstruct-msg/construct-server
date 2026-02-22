#!/usr/bin/env bash
set -euo pipefail

# Generate test RSA keys for CI/CD and local testing
# These keys are ephemeral and should never be committed to git

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../shared/tests/keys"
JWT_KEYS_DIR="$SCRIPT_DIR/../prkeys"

echo "🔑 Generating test keys..."

# Create keys directories if they don't exist
mkdir -p "$KEYS_DIR"
mkdir -p "$JWT_KEYS_DIR"

# Generate 2048-bit RSA private key for auth tests
openssl genrsa -out "$KEYS_DIR/test_private.pem" 2048 2>/dev/null

# Extract public key
openssl rsa -in "$KEYS_DIR/test_private.pem" -pubout -out "$KEYS_DIR/test_public.pem" 2>/dev/null

# Generate 4096-bit RSA keys for JWT (production-grade)
openssl genrsa -out "$JWT_KEYS_DIR/jwt_private_key.pem" 4096 2>/dev/null

# Extract JWT public key
openssl rsa -in "$JWT_KEYS_DIR/jwt_private_key.pem" -pubout -out "$JWT_KEYS_DIR/jwt_public_key.pem" 2>/dev/null

# Set restrictive permissions
chmod 600 "$KEYS_DIR/test_private.pem"
chmod 644 "$KEYS_DIR/test_public.pem"
chmod 600 "$JWT_KEYS_DIR/jwt_private_key.pem"
chmod 644 "$JWT_KEYS_DIR/jwt_public_key.pem"

echo "✅ Test keys generated:"
echo "   Auth keys: $KEYS_DIR"
echo "      - test_private.pem (2048-bit RSA)"
echo "      - test_public.pem"
echo "   JWT keys: $JWT_KEYS_DIR"
echo "      - jwt_private_key.pem (4096-bit RSA)"
echo "      - jwt_public_key.pem"
