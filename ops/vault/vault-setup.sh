#!/bin/bash
# =============================================================================
# Vault initialization script — run ONCE after first deploy
# Sets up: KV secrets engine, AppRole auth, policies
#
# Usage (from repo root on VPS):
#   docker compose -f ops/docker-compose.prod.yml exec vault sh /vault/scripts/vault-setup.sh
#
# Prerequisites:
#   - Vault container is running and unsealed
#   - VAULT_TOKEN env var set to the root token (shown during vault operator init)
# =============================================================================
set -e

VAULT_ADDR=${VAULT_ADDR:-http://localhost:8200}

echo "==> Enabling KV v2 secrets engine..."
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "Already enabled"

echo "==> Writing construct app secrets..."
echo "NOTE: Edit this section with your actual secrets, or use vault kv put manually"
echo ""
echo "Run the following command with your actual secrets:"
cat << 'EXAMPLE'
vault kv put secret/construct \
  DATABASE_URL="postgresql://user:pass@db.supabase.co:5432/postgres?sslmode=require" \
  REDIS_URL="rediss://default:pass@host.upstash.io:6379" \
  JWT_PRIVATE_KEY="$(cat /path/to/private.pem)" \
  JWT_PUBLIC_KEY="$(cat /path/to/public.pem)" \
  JWT_ISSUER="construct-auth" \
  SERVER_SIGNING_KEY="$(openssl rand -hex 32)" \
  CSRF_SECRET="$(openssl rand -hex 24)" \
  MEDIA_HMAC_SECRET="$(openssl rand -hex 24)" \
  LOG_HASH_SALT="$(openssl rand -hex 16)" \
  DELIVERY_SECRET_KEY="$(openssl rand -hex 32)" \
  APNS_BUNDLE_ID="com.yourcompany.construct" \
  APNS_KEY_ID="YOUR_KEY_ID" \
  APNS_TEAM_ID="YOUR_TEAM_ID" \
  APNS_TOPIC="com.yourcompany.construct" \
  APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$(openssl rand -hex 32)"
EXAMPLE

echo ""
echo "==> Creating policy for construct services..."
vault policy write construct-services - << 'POLICY'
path "secret/data/construct" {
  capabilities = ["read"]
}
path "secret/metadata/construct" {
  capabilities = ["read"]
}
POLICY

echo "==> Enabling AppRole authentication..."
vault auth enable approle 2>/dev/null || echo "Already enabled"

echo "==> Creating AppRole for construct services..."
vault write auth/approle/role/construct-services \
  token_policies="construct-services" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="0"   # never expires (rotate manually)

echo ""
echo "==> Fetching AppRole credentials..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/construct-services/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/construct-services/secret-id)

echo ""
echo "======================================================"
echo "  AppRole credentials (save these securely!):"
echo "======================================================"
echo "  role_id:   $ROLE_ID"
echo "  secret_id: $SECRET_ID"
echo "======================================================"
echo ""
echo "==> Writing credentials for vault-agent..."
mkdir -p /vault/auth
echo "$ROLE_ID" > /vault/auth/role_id
echo "$SECRET_ID" > /vault/auth/secret_id
chmod 600 /vault/auth/role_id /vault/auth/secret_id

echo "==> Done! Vault is configured."
echo "    Next: restart the vault-agent service to fetch secrets."
echo "    docker compose -f ops/docker-compose.prod.yml restart vault-agent"
