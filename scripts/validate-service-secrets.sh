#!/bin/bash
# Validates that Fly.io secrets are correctly set for a specific service
# Usage: ./scripts/validate-service-secrets.sh <service-name>
#
# Example:
#   ./scripts/validate-service-secrets.sh messaging-service
#   ./scripts/validate-service-secrets.sh auth-service

set -e

SERVICE="$1"

if [ -z "$SERVICE" ]; then
  echo "Usage: $0 <service-name>"
  echo ""
  echo "Available services:"
  echo "  - api-gateway"
  echo "  - auth-service"
  echo "  - user-service"
  echo "  - messaging-service"
  echo "  - notification-service"
  echo "  - media-service"
  echo "  - worker"
  exit 1
fi

# Map service name to Fly.io app name
case "$SERVICE" in
  api-gateway)
    APP_NAME="construct-api-gateway"
    ;;
  auth-service)
    APP_NAME="construct-auth-service"
    ;;
  user-service)
    APP_NAME="construct-user-service"
    ;;
  messaging-service)
    APP_NAME="construct-messaging-service"
    ;;
  notification-service)
    APP_NAME="construct-notification-service"
    ;;
  media-service)
    APP_NAME="construct-media-service"
    ;;
  worker)
    APP_NAME="construct-delivery-worker"
    ;;
  *)
    echo "❌ Unknown service: $SERVICE"
    exit 1
    ;;
esac

echo "🔍 Validating secrets for $SERVICE ($APP_NAME)..."

# Check if flyctl is installed
if ! command -v flyctl &> /dev/null; then
  echo "❌ flyctl is not installed"
  echo "   Install: https://fly.io/docs/hands-on/install-flyctl/"
  exit 1
fi

# Check if app exists
if ! flyctl status --app "$APP_NAME" >/dev/null 2>&1; then
  echo "❌ Fly.io app not found: $APP_NAME"
  echo "   Create with: fly apps create $APP_NAME"
  exit 1
fi

# Get secrets list
SECRETS=$(flyctl secrets list --app "$APP_NAME" 2>&1)
if [ $? -ne 0 ]; then
  echo "❌ Failed to fetch secrets for $APP_NAME"
  echo "$SECRETS"
  exit 1
fi

# Define required secrets per service
declare -a REQUIRED_SECRETS

case "$SERVICE" in
  api-gateway)
    REQUIRED_SECRETS=(
      "DATABASE_URL"
      "REDIS_URL"
      "JWT_PRIVATE_KEY"
      "JWT_PUBLIC_KEY"
      "JWT_ISSUER"
      "LOG_HASH_SALT"
      "ONLINE_CHANNEL"
      "DELIVERY_QUEUE_PREFIX"
      "OFFLINE_QUEUE_PREFIX"
      "CSRF_SECRET"
    )
    ;;
  auth-service)
    REQUIRED_SECRETS=(
      "DATABASE_URL"
      "REDIS_URL"
      "JWT_PRIVATE_KEY"
      "JWT_PUBLIC_KEY"
      "JWT_ISSUER"
      "LOG_HASH_SALT"
      "ONLINE_CHANNEL"
      "DELIVERY_QUEUE_PREFIX"
      "OFFLINE_QUEUE_PREFIX"
      "CSRF_ENABLED"
    )
    ;;
  user-service)
    REQUIRED_SECRETS=(
      "DATABASE_URL"
      "REDIS_URL"
      "JWT_PUBLIC_KEY"
      "JWT_ISSUER"
      "LOG_HASH_SALT"
      "ONLINE_CHANNEL"
      "DELIVERY_QUEUE_PREFIX"
      "OFFLINE_QUEUE_PREFIX"
      "CSRF_ENABLED"
    )
    ;;
  messaging-service)
    REQUIRED_SECRETS=(
      "DATABASE_URL"
      "REDIS_URL"
      "JWT_PUBLIC_KEY"
      "JWT_ISSUER"
      "LOG_HASH_SALT"
      "ONLINE_CHANNEL"
      "DELIVERY_QUEUE_PREFIX"
      "OFFLINE_QUEUE_PREFIX"
      "CSRF_ENABLED"
    )
    # Kafka secrets are conditional - will check separately
    ;;
  notification-service)
    REQUIRED_SECRETS=(
      "DATABASE_URL"
      "REDIS_URL"
      "JWT_PUBLIC_KEY"
      "JWT_ISSUER"
      "LOG_HASH_SALT"
      "ONLINE_CHANNEL"
      "DELIVERY_QUEUE_PREFIX"
      "OFFLINE_QUEUE_PREFIX"
      "CSRF_ENABLED"
      "APNS_DEVICE_TOKEN_ENCRYPTION_KEY"
    )
    ;;
  media-service)
    REQUIRED_SECRETS=(
      "MEDIA_HMAC_SECRET"
    )
    ;;
  worker)
    REQUIRED_SECRETS=(
      "DATABASE_URL"
      "REDIS_URL"
      "JWT_PUBLIC_KEY"
      "JWT_ISSUER"
      "LOG_HASH_SALT"
      "ONLINE_CHANNEL"
      "DELIVERY_QUEUE_PREFIX"
      "OFFLINE_QUEUE_PREFIX"
      "CSRF_ENABLED"
    )
    ;;
esac

# Validate required secrets
MISSING_SECRETS=()
for SECRET in "${REQUIRED_SECRETS[@]}"; do
  if ! echo "$SECRETS" | grep -q "^$SECRET"; then
    MISSING_SECRETS+=("$SECRET")
  fi
done

# Check for JWT key format (must be PEM, not file path)
if echo "$SECRETS" | grep -q "^JWT_PUBLIC_KEY"; then
  JWT_VALUE=$(flyctl secrets list --app "$APP_NAME" --json 2>/dev/null | jq -r '.[] | select(.Name == "JWT_PUBLIC_KEY") | .Value' 2>/dev/null || echo "")
  
  # If we can get the value, check if it's a path (contains .pem)
  if [ -n "$JWT_VALUE" ] && [[ "$JWT_VALUE" == *".pem"* ]]; then
    echo "⚠️  WARNING: JWT_PUBLIC_KEY looks like a file path, not PEM content!"
    echo "   Value: ${JWT_VALUE:0:50}..."
    echo ""
    echo "   This will cause InvalidKeyFormat errors in production."
    echo "   Fix with:"
    echo "     fly secrets set JWT_PUBLIC_KEY=\"\$(cat prkeys/jwt_public_key.pem)\" -a $APP_NAME"
    echo ""
  fi
fi

# Report results
if [ ${#MISSING_SECRETS[@]} -eq 0 ]; then
  echo "✅ All required secrets are set for $SERVICE"
  echo ""
  echo "Secrets found:"
  echo "$SECRETS" | grep -E "^($(IFS='|'; echo "${REQUIRED_SECRETS[*]}"))" | awk '{print "  ✓ " $1}'
  echo ""
else
  echo "❌ Missing required secrets for $SERVICE:"
  for SECRET in "${MISSING_SECRETS[@]}"; do
    echo "  ✗ $SECRET"
  done
  echo ""
  echo "Set missing secrets with:"
  echo "  make secrets-$(echo $SERVICE | sed 's/-service//')"
  exit 1
fi

# Additional checks for specific services
if [ "$SERVICE" = "messaging-service" ] || [ "$SERVICE" = "worker" ]; then
  # Check if Kafka is enabled
  if echo "$SECRETS" | grep -q "^KAFKA_ENABLED"; then
    KAFKA_ENABLED=$(flyctl secrets list --app "$APP_NAME" --json 2>/dev/null | jq -r '.[] | select(.Name == "KAFKA_ENABLED") | .Value' 2>/dev/null || echo "false")
    
    if [ "$KAFKA_ENABLED" = "true" ]; then
      echo "ℹ️  Kafka is enabled, checking Kafka secrets..."
      
      KAFKA_SECRETS=(
        "KAFKA_BROKERS"
        "KAFKA_TOPIC"
        "KAFKA_CONSUMER_GROUP"
        "KAFKA_SSL_ENABLED"
        "KAFKA_SASL_MECHANISM"
        "KAFKA_SASL_USERNAME"
        "KAFKA_SASL_PASSWORD"
      )
      
      MISSING_KAFKA=()
      for SECRET in "${KAFKA_SECRETS[@]}"; do
        if ! echo "$SECRETS" | grep -q "^$SECRET"; then
          MISSING_KAFKA+=("$SECRET")
        fi
      done
      
      if [ ${#MISSING_KAFKA[@]} -eq 0 ]; then
        echo "  ✅ Kafka secrets configured"
      else
        echo "  ⚠️  Missing Kafka secrets:"
        for SECRET in "${MISSING_KAFKA[@]}"; do
          echo "    ✗ $SECRET"
        done
      fi
      echo ""
    fi
  fi
fi

echo "✅ Secret validation passed for $SERVICE"
exit 0
