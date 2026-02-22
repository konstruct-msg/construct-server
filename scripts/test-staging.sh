#!/bin/bash
# Test script for local staging environment

set -e

echo "🧪 Testing Construct Staging Environment"
echo ""

# Check if services are running
echo "1. Checking services..."
docker-compose -f ops/docker-compose.staging.yml ps

echo ""
echo "2. Testing Envoy admin interface..."
curl -s http://localhost:9901/stats | head -5 || echo "⚠️  Envoy admin not accessible"

echo ""
echo "3. Testing gRPC services (requires grpcurl)..."

if ! command -v grpcurl &> /dev/null; then
    echo "⚠️  grpcurl not installed. Install: brew install grpcurl"
else
    echo ""
    echo "3a. List available services:"
    grpcurl -plaintext localhost:50051 list || echo "❌ Auth service not responding"
    
    echo ""
    echo "3b. Test auth service - GetChallenge:"
    grpcurl -plaintext -d '{"device_id":"test-device-123"}' \
        localhost:50051 auth.AuthService/GetChallenge || echo "❌ GetChallenge failed"
    
    echo ""
    echo "3c. Test through Envoy (port 443 with TLS):"
    echo "TODO: Requires valid TLS cert"
    # grpcurl -insecure localhost:443 list
fi

echo ""
echo "4. Viewing logs (last 20 lines per service)..."
echo "--- Auth Service ---"
docker logs construct-auth --tail 20

echo ""
echo "--- Envoy ---"
docker logs construct-envoy --tail 20

echo ""
echo "✅ Tests complete!"
echo ""
echo "Useful commands:"
echo "  - View all logs: docker-compose -f ops/docker-compose.staging.yml logs -f"
echo "  - Restart service: docker-compose -f ops/docker-compose.staging.yml restart auth-service"
echo "  - Stop all: docker-compose -f ops/docker-compose.staging.yml down"
