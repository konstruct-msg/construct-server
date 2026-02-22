#!/bin/bash
# Create all production secrets for Construct Server
# Usage: ./scripts/create-secrets.sh [environment]
#   environment: production, staging (default: staging)

set -e

ENV="${1:-staging}"
SECRETS_DIR="/tmp/construct-secrets-${ENV}"

echo "🔐 Creating secrets for environment: $ENV"
echo ""

# Validate Docker Swarm is initialized
if ! docker info | grep -q "Swarm: active"; then
    echo "❌ Docker Swarm not initialized!"
    echo "Run: docker swarm init"
    exit 1
fi

# Create temporary directory for secrets
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

echo "Generating secrets..."

# 1. CSRF Secret
echo "$(openssl rand -hex 32)" > "$SECRETS_DIR/csrf_secret"
echo "✓ Generated CSRF_SECRET"

# 2. Delivery Secret Key
echo "$(openssl rand -hex 32)" > "$SECRETS_DIR/delivery_secret_key"
echo "✓ Generated DELIVERY_SECRET_KEY"

# 3. Media HMAC Secret
echo "$(openssl rand -hex 32)" > "$SECRETS_DIR/media_hmac_secret"
echo "✓ Generated MEDIA_HMAC_SECRET"

# 4. Server Signing Key
echo "$(openssl rand -base64 32)" > "$SECRETS_DIR/server_signing_key"
echo "✓ Generated SERVER_SIGNING_KEY"

# 5. Log Hash Salt
echo "$(openssl rand -hex 32)" > "$SECRETS_DIR/log_hash_salt"
echo "✓ Generated LOG_HASH_SALT"

echo ""
echo "Creating Docker secrets..."

# Create Docker secrets with versioning (v1, v2, etc.)
VERSION="v1"

docker secret create construct_${ENV}_csrf_secret_${VERSION} "$SECRETS_DIR/csrf_secret" 2>/dev/null || echo "Secret already exists"
docker secret create construct_${ENV}_delivery_secret_key_${VERSION} "$SECRETS_DIR/delivery_secret_key" 2>/dev/null || echo "Secret already exists"
docker secret create construct_${ENV}_media_hmac_secret_${VERSION} "$SECRETS_DIR/media_hmac_secret" 2>/dev/null || echo "Secret already exists"
docker secret create construct_${ENV}_server_signing_key_${VERSION} "$SECRETS_DIR/server_signing_key" 2>/dev/null || echo "Secret already exists"
docker secret create construct_${ENV}_log_hash_salt_${VERSION} "$SECRETS_DIR/log_hash_salt" 2>/dev/null || echo "Secret already exists"

echo ""
echo "✅ Secrets created! Summary:"
docker secret ls | grep "construct_${ENV}"

echo ""
echo "⚠️  IMPORTANT: Save these values to your password manager:"
echo ""
echo "Environment: $ENV"
echo "Created: $(date)"
echo ""
echo "CSRF_SECRET=$(cat $SECRETS_DIR/csrf_secret)"
echo "DELIVERY_SECRET_KEY=$(cat $SECRETS_DIR/delivery_secret_key)"
echo "MEDIA_HMAC_SECRET=$(cat $SECRETS_DIR/media_hmac_secret)"
echo "SERVER_SIGNING_KEY=$(cat $SECRETS_DIR/server_signing_key)"
echo "LOG_HASH_SALT=$(cat $SECRETS_DIR/log_hash_salt)"

echo ""
echo "🔥 Cleaning up temporary files..."
rm -rf "$SECRETS_DIR"

echo ""
echo "Next steps:"
echo "  1. Add DATABASE_URL and REDIS_URL manually:"
echo "     echo 'postgresql://...' | docker secret create construct_${ENV}_database_url_${VERSION} -"
echo "     echo 'redis://...' | docker secret create construct_${ENV}_redis_url_${VERSION} -"
echo ""
echo "  2. Add JWT keys:"
echo "     docker secret create construct_${ENV}_jwt_private_key_${VERSION} prkeys/jwt_private_key.pem"
echo "     docker secret create construct_${ENV}_jwt_public_key_${VERSION} prkeys/jwt_public_key.pem"
echo ""
echo "  3. Update docker-compose to use these secrets"
