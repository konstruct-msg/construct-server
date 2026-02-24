#!/bin/bash
# =============================================================================
# Load secrets from local .env into Vault
# Run this on the VPS AFTER vault-setup.sh has been executed.
#
# Usage:
#   # 1. Copy your local .env to VPS:
#   #    scp .env user@VPS_IP:/tmp/construct.env
#   #
#   # 2. SSH into VPS and run:
#   #    bash construct-server/ops/scripts/load-secrets-to-vault.sh /tmp/construct.env
#   #
#   # 3. Script deletes /tmp/construct.env when done.
# =============================================================================
set -e

ENV_FILE=${1:-/tmp/construct.env}
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: env file not found at $ENV_FILE"
  echo "Usage: $0 /path/to/.env"
  exit 1
fi

echo "==> Reading secrets from $ENV_FILE..."

# Helper: extract value from .env file
get_val() {
  grep -E "^${1}=" "$ENV_FILE" | cut -d'=' -f2- | sed 's/^"\(.*\)"$/\1/' | sed "s/^'\(.*\)'$/\1/"
}

# Extract all secrets
DATABASE_URL=$(get_val DATABASE_URL)
REDIS_URL=$(get_val REDIS_URL)
JWT_PRIVATE_KEY=$(get_val JWT_PRIVATE_KEY)
JWT_PUBLIC_KEY=$(get_val JWT_PUBLIC_KEY)
JWT_ISSUER=$(get_val JWT_ISSUER)
SERVER_SIGNING_KEY=$(get_val SERVER_SIGNING_KEY)
CSRF_SECRET=$(get_val CSRF_SECRET)
MEDIA_HMAC_SECRET=$(get_val MEDIA_HMAC_SECRET)
LOG_HASH_SALT=$(get_val LOG_HASH_SALT)
DELIVERY_SECRET_KEY=$(get_val DELIVERY_SECRET_KEY)
APNS_BUNDLE_ID=$(get_val APNS_BUNDLE_ID)
APNS_KEY_ID=$(get_val APNS_KEY_ID)
APNS_TEAM_ID=$(get_val APNS_TEAM_ID)
APNS_TOPIC=$(get_val APNS_TOPIC)
APNS_DEVICE_TOKEN_ENCRYPTION_KEY=$(get_val APNS_DEVICE_TOKEN_ENCRYPTION_KEY)

echo "==> Writing secrets to Vault at $VAULT_ADDR..."
echo "    (Make sure you are logged in: vault login)"

docker exec construct-vault vault kv put \
  -address="$VAULT_ADDR" \
  secret/construct \
  DATABASE_URL="$DATABASE_URL" \
  REDIS_URL="$REDIS_URL" \
  JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
  JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
  JWT_ISSUER="${JWT_ISSUER:-construct-auth}" \
  SERVER_SIGNING_KEY="$SERVER_SIGNING_KEY" \
  CSRF_SECRET="$CSRF_SECRET" \
  MEDIA_HMAC_SECRET="$MEDIA_HMAC_SECRET" \
  LOG_HASH_SALT="$LOG_HASH_SALT" \
  DELIVERY_SECRET_KEY="$DELIVERY_SECRET_KEY" \
  APNS_BUNDLE_ID="${APNS_BUNDLE_ID:-}" \
  APNS_KEY_ID="${APNS_KEY_ID:-}" \
  APNS_TEAM_ID="${APNS_TEAM_ID:-}" \
  APNS_TOPIC="${APNS_TOPIC:-}" \
  APNS_DEVICE_TOKEN_ENCRYPTION_KEY="${APNS_DEVICE_TOKEN_ENCRYPTION_KEY:-}"

echo ""
echo "==> Verifying secrets were written..."
docker exec construct-vault vault kv get -address="$VAULT_ADDR" -field=DATABASE_URL secret/construct \
  | sed 's/.\{20\}$/...HIDDEN/' && echo " (DATABASE_URL present ✓)"

echo ""
echo "==> Deleting temp env file..."
rm -f "$ENV_FILE"
echo "    $ENV_FILE deleted ✓"

echo ""
echo "==> Done! Secrets loaded into Vault."
echo "    Next: run vault-setup.sh to create AppRole, then start all services."
