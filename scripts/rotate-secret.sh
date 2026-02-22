#!/bin/bash
# Rotate a Docker secret with zero downtime
# Usage: ./scripts/rotate-secret.sh <secret_type>
#   secret_type: csrf_secret, delivery_secret_key, media_hmac_secret, etc.

set -e

SECRET_TYPE="${1}"
ENV="${2:-production}"

if [ -z "$SECRET_TYPE" ]; then
    echo "Usage: $0 <secret_type> [environment]"
    echo ""
    echo "Available secret types:"
    echo "  - csrf_secret"
    echo "  - delivery_secret_key"
    echo "  - media_hmac_secret"
    echo "  - server_signing_key"
    echo "  - log_hash_salt"
    echo ""
    echo "Example: $0 csrf_secret production"
    exit 1
fi

echo "🔄 Rotating secret: $SECRET_TYPE (environment: $ENV)"
echo ""

# Validate Docker Swarm is initialized
if ! docker info | grep -q "Swarm: active"; then
    echo "❌ Docker Swarm not initialized!"
    echo "This script requires Docker Swarm for zero-downtime updates"
    exit 1
fi

# Find current version
OLD_SECRET="construct_${ENV}_${SECRET_TYPE}_v1"
if ! docker secret inspect "$OLD_SECRET" >/dev/null 2>&1; then
    echo "❌ Secret $OLD_SECRET not found!"
    echo "Available secrets:"
    docker secret ls | grep "construct_${ENV}"
    exit 1
fi

# Generate new secret
echo "Generating new secret value..."
case "$SECRET_TYPE" in
    csrf_secret|delivery_secret_key|media_hmac_secret|log_hash_salt)
        NEW_VALUE=$(openssl rand -hex 32)
        ;;
    server_signing_key)
        NEW_VALUE=$(openssl rand -base64 32)
        ;;
    *)
        echo "❌ Unknown secret type: $SECRET_TYPE"
        exit 1
        ;;
esac

# Create new version (v2)
NEW_SECRET="construct_${ENV}_${SECRET_TYPE}_v2"
echo "$NEW_VALUE" | docker secret create "$NEW_SECRET" - 2>/dev/null || {
    echo "❌ Failed to create new secret. It may already exist."
    exit 1
}

echo "✅ Created new secret: $NEW_SECRET"
echo ""

# Find all services using this secret
SERVICES=$(docker service ls --format '{{.Name}}' | grep "construct_${ENV}" || true)

if [ -z "$SERVICES" ]; then
    echo "⚠️  No services found. Make sure services are deployed."
    exit 1
fi

echo "Updating services with new secret..."
for SERVICE in $SERVICES; do
    # Check if service uses this secret
    if docker service inspect "$SERVICE" | grep -q "$OLD_SECRET"; then
        echo "  - Updating $SERVICE..."
        docker service update \
            --secret-rm "$OLD_SECRET" \
            --secret-add "source=$NEW_SECRET,target=${SECRET_TYPE}" \
            "$SERVICE" \
            --detach=false
        echo "    ✓ Updated"
    fi
done

echo ""
echo "⏳ Waiting 30 seconds for services to stabilize..."
sleep 30

# Verify services are healthy
echo "Checking service health..."
for SERVICE in $SERVICES; do
    REPLICAS=$(docker service ls --filter "name=$SERVICE" --format "{{.Replicas}}")
    if echo "$REPLICAS" | grep -q "0/"; then
        echo "❌ Service $SERVICE has no running replicas!"
        echo "Rollback? (y/n)"
        read -r ROLLBACK
        if [ "$ROLLBACK" = "y" ]; then
            docker service update --rollback "$SERVICE"
        fi
        exit 1
    fi
    echo "  ✓ $SERVICE is healthy"
done

echo ""
echo "✅ Rotation complete!"
echo ""
echo "⚠️  IMPORTANT: Save new secret value to password manager:"
echo ""
echo "Secret: $SECRET_TYPE"
echo "Environment: $ENV"
echo "Value: $NEW_VALUE"
echo "Rotated: $(date)"
echo ""
echo "🗑️  Old secret can be removed after verification:"
echo "  docker secret rm $OLD_SECRET"
echo ""
echo "Then rename v2 to v1:"
echo "  # This requires recreating the secret (no rename command in Docker)"
echo "  # Keep v2 suffix for now, or delete and recreate as v1"
