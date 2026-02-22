#!/bin/bash
# ============================================================================
# Deploy MediaService to Fly.io
# ============================================================================
# Usage: ./scripts/deploy-media.sh [staging|production]
# ============================================================================

set -e

ENVIRONMENT="${1:-staging}"

case "$ENVIRONMENT" in
  staging)
    APP_NAME="construct-media-staging"
    ;;
  production)
    APP_NAME="construct-media"
    echo "⚠️  Production deployment - are you sure? (y/N)"
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      echo "Aborted."
      exit 1
    fi
    ;;
  *)
    echo "Usage: $0 [staging|production]"
    exit 1
    ;;
esac

echo "=== Deploying MediaService to Fly.io ==="
echo "App: $APP_NAME"
echo "Environment: $ENVIRONMENT"
echo ""

# Check if app exists
if ! flyctl apps list | grep -q "$APP_NAME"; then
  echo "Creating app $APP_NAME..."
  flyctl apps create "$APP_NAME" --org personal
  
  echo ""
  echo "Creating volume for media storage..."
  flyctl volumes create media_storage \
    --app "$APP_NAME" \
    --region ams \
    --size 10 \
    --no-encryption
  
  echo ""
  echo "⚠️  Set secrets before first deploy:"
  echo "  flyctl secrets set DATABASE_URL='postgres://...' --app $APP_NAME"
  echo "  flyctl secrets set MEDIA_HMAC_SECRET=\$(openssl rand -hex 32) --app $APP_NAME"
  echo ""
  echo "Then run this script again."
  exit 0
fi

# Deploy
echo "Deploying..."
flyctl deploy \
  --config ops/fly.media.toml \
  --app "$APP_NAME" \
  --remote-only

echo ""
echo "=== Deployment complete ==="
echo "Health: https://$APP_NAME.fly.dev/health"
echo "gRPC:   $APP_NAME.fly.dev:443 (TLS)"
echo ""
echo "Test with grpcurl:"
echo "  grpcurl $APP_NAME.fly.dev:443 shared.proto.services.v1.MediaService/GenerateUploadToken"
