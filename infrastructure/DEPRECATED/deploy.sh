#!/bin/bash
# Construct Server - Production Deployment Script
# Run this on your VPS after Terraform creates the infrastructure
# Usage: ./infrastructure/deploy.sh [gateway|core|message|media]

set -e

# Determine server role based on argument or hostname
if [[ $# -eq 1 ]]; then
    SERVER_ROLE="$1"
else
    # Auto-detect based on hostname
    if [[ "$(hostname)" == *"gateway"* ]]; then
        SERVER_ROLE="gateway"
    elif [[ "$(hostname)" == *"app"* ]]; then
        SERVER_ROLE="app"
    elif [[ "$(hostname)" == *"db"* ]]; then
        SERVER_ROLE="db"
    elif [[ "$(hostname)" == *"message"* ]]; then
        SERVER_ROLE="message"
    elif [[ "$(hostname)" == *"media"* ]]; then
        SERVER_ROLE="media"
    else
        echo "❌ Cannot determine server role. Please specify: gateway, app, db, message, or media"
        echo "   Usage: $0 [gateway|app|db|message|media]"
        exit 1
    fi
fi

echo "=== Construct Server Production Deployment ==="
echo "Server: $(hostname -I | awk '{print $1}')"
echo "Role: $SERVER_ROLE"
echo "Date: $(date)"
echo ""

# Check if we're running as the construct user
if [[ "$USER" != "construct" ]]; then
    echo "❌ Please run this script as the 'construct' user"
    echo "   sudo su - construct"
    exit 1
fi

# Check if we're in the correct directory
if [[ ! -f "infrastructure/docker-compose.${SERVER_ROLE}.yml" ]]; then
    echo "❌ Docker compose file not found: infrastructure/docker-compose.${SERVER_ROLE}.yml"
    exit 1
fi

echo "📦 Pulling latest code..."
git pull origin main || echo "⚠️  Git pull failed, continuing with local code"

echo "🔧 Setting up environment..."
if [[ ! -f "infrastructure/.env.prod" ]]; then
    echo "❌ .env.prod file not found!"
    echo "   Please copy infrastructure/.env.prod.example to infrastructure/.env.prod"
    echo "   and configure your production environment variables."
    exit 1
fi

COMPOSE_FILE="infrastructure/docker-compose.${SERVER_ROLE}.yml"

echo "🐳 Stopping existing services..."
docker-compose -f "$COMPOSE_FILE" down || true

echo "🏗️  Building services..."
docker-compose -f "$COMPOSE_FILE" build --no-cache

echo "🚀 Starting services..."
docker-compose -f "$COMPOSE_FILE" up -d

echo "⏳ Waiting for services to be healthy..."
sleep 30

echo "🏥 Checking service health..."

# Define services to check based on server role
case $SERVER_ROLE in
    gateway)
        SERVICES=("gateway")
        ;;
    app)
        SERVICES=("auth-service" "user-service" "notification-service")
        ;;
    db)
        SERVICES=("postgres" "redis")
        ;;
    message)
        SERVICES=("redis" "redpanda" "messaging-service" "delivery-worker")
        ;;
    media)
        SERVICES=("media-service")
        ;;
    *)
        echo "❌ Unknown server role: $SERVER_ROLE"
        exit 1
        ;;
esac

for service in "${SERVICES[@]}"; do
    echo -n "  $service: "

    # Different health check logic for different service types
    case $service in
        postgres)
            if docker-compose -f "$COMPOSE_FILE" exec -T "$service" pg_isready -U construct -d construct 2>/dev/null; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        redis)
            if docker-compose -f "$COMPOSE_FILE" exec -T "$service" redis-cli ping 2>/dev/null | grep -q PONG; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        redpanda)
            if docker-compose -f "$COMPOSE_FILE" exec -T "$service" rpk cluster info 2>/dev/null; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
        delivery-worker)
            # Worker doesn't have HTTP health endpoint, check if container is running
            if docker-compose -f "$COMPOSE_FILE" ps "$service" 2>/dev/null | grep -q "Up"; then
                echo "✅ Running"
            else
                echo "❌ Not running"
            fi
            ;;
        *)
            # Standard HTTP health check for other services
            if docker-compose -f "$COMPOSE_FILE" exec -T "$service" curl -f http://localhost:8080/health 2>/dev/null; then
                echo "✅ Healthy"
            else
                echo "❌ Unhealthy"
            fi
            ;;
    esac
done

echo ""
echo "📊 Service Status:"
docker-compose -f "$COMPOSE_FILE" ps

echo ""
echo "🔗 Useful commands:"
echo "  View logs: docker-compose -f $COMPOSE_FILE logs -f"
echo "  Restart service: docker-compose -f $COMPOSE_FILE restart <service>"
echo "  Update: docker-compose -f $COMPOSE_FILE pull && docker-compose -f $COMPOSE_FILE up -d"

echo ""
echo "🎉 Deployment completed for $SERVER_ROLE server!"
case $SERVER_ROLE in
    gateway)
        echo "   API Gateway: https://$DOMAIN_NAME"
        echo "   Health Check: https://$DOMAIN_NAME/health"
        ;;
    app)
        echo "   Auth Service: localhost:8001"
        echo "   User Service: localhost:8002"
        echo "   Notification Service: localhost:8003"
        ;;
    db)
        echo "   Database: postgres://construct:***@localhost:5432/construct"
        echo "   Redis: redis://:***@localhost:6379"
        ;;
    message)
        echo "   Redpanda: localhost:9092"
        echo "   Redis Replica: localhost:6379"
        ;;
    media)
        echo "   Media Service: localhost:8005"
        ;;
esac