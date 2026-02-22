#!/bin/bash
#
# Generate a new DELIVERY_SECRET_KEY for the server
#
# Usage: ./scripts/generate_delivery_key.sh
#

set -e

echo "Generating new DELIVERY_SECRET_KEY..."
echo ""

KEY=$(openssl rand -hex 32)

echo "DELIVERY_SECRET_KEY=$KEY"
echo ""
echo "Add this to your .env file:"
echo "DELIVERY_SECRET_KEY=$KEY"
echo ""
echo "IMPORTANT SECURITY NOTES:"
echo "- NEVER commit this key to git"
echo "- Store it securely (use secrets manager in production)"
echo "- Use different keys for dev/staging/prod environments"
echo "- Rotate the key periodically (e.g., every 6-12 months)"
echo ""
