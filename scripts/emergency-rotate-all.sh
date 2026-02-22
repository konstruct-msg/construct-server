#!/bin/bash
# Emergency rotation of ALL secrets
# Use when server is compromised or secrets leaked

set -e

ENV="${1:-production}"

echo "🚨 EMERGENCY SECRET ROTATION"
echo "Environment: $ENV"
echo ""
echo "⚠️  WARNING: This will:"
echo "  - Generate new values for ALL secrets"
echo "  - Restart all services (brief downtime)"
echo "  - Invalidate all existing sessions"
echo ""
echo "Continue? (type 'yes' to confirm)"
read -r CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "Starting emergency rotation..."
echo ""

# 1. Rotate all generated secrets
./scripts/rotate-secret.sh csrf_secret $ENV
sleep 5
./scripts/rotate-secret.sh delivery_secret_key $ENV
sleep 5
./scripts/rotate-secret.sh media_hmac_secret $ENV
sleep 5
./scripts/rotate-secret.sh server_signing_key $ENV
sleep 5
./scripts/rotate-secret.sh log_hash_salt $ENV

echo ""
echo "✅ All auto-generated secrets rotated!"
echo ""
echo "⚠️  MANUAL STEPS REQUIRED:"
echo ""
echo "1. Rotate database password:"
echo "   - Go to Supabase dashboard → Settings → Database"
echo "   - Click 'Reset database password'"
echo "   - Update Docker secret:"
echo "     echo 'new_connection_string' | docker secret create construct_${ENV}_database_url_v2 -"
echo ""
echo "2. Rotate Redis password:"
echo "   - Go to Upstash dashboard → Database → Reset password"
echo "   - Update Docker secret:"
echo "     echo 'new_redis_url' | docker secret create construct_${ENV}_redis_url_v2 -"
echo ""
echo "3. Generate new JWT keys:"
echo "   openssl genpkey -algorithm RSA -out jwt_private_key_new.pem -pkeyopt rsa_keygen_bits:4096"
echo "   openssl rsa -pubout -in jwt_private_key_new.pem -out jwt_public_key_new.pem"
echo "   docker secret create construct_${ENV}_jwt_private_key_v2 jwt_private_key_new.pem"
echo "   docker secret create construct_${ENV}_jwt_public_key_v2 jwt_public_key_new.pem"
echo ""
echo "4. Force restart all services:"
echo "   docker stack rm construct_${ENV}"
echo "   docker stack deploy -c ops/docker-compose.prod.yml construct_${ENV}"
echo ""
echo "5. Clear Redis (logs out all users):"
echo "   redis-cli -u \$REDIS_URL FLUSHDB"
echo ""
echo "6. Notify team and users of security incident"
echo ""
echo "📝 Document this incident in security log!"
