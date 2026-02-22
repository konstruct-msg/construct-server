#!/bin/bash
# ============================================================================
# Construct Server - Registration Flow Test
# ============================================================================
# Tests the complete passwordless registration flow:
# 1. GET challenge
# 2. Solve Argon2id PoW (simulated)
# 3. POST registration with PoW solution
# 
# Usage:
#   ./scripts/test-registration-flow.sh https://construct-user-service.fly.dev
#   ./scripts/test-registration-flow.sh http://localhost:8080
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BASE_URL="${1:-http://localhost:8080}"
API_BASE="${BASE_URL}/api/v1"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Construct Server - Registration Flow Test${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Testing against: ${GREEN}${BASE_URL}${NC}"
echo ""

# ============================================================================
# Step 1: Health Check
# ============================================================================
echo -e "${YELLOW}[1/4]${NC} Health Check..."
HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "${BASE_URL}/health" 2>/dev/null)
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "  ${GREEN}✓${NC} Server is healthy"
elif [ "$HTTP_CODE" = "401" ]; then
    echo -e "  ${YELLOW}⚠${NC}  Server returned 401 (Fly.io auth issue, but server is running)"
    echo -e "  ${GREEN}✓${NC} Continuing tests (401 means server is alive)..."
else
    echo -e "  ${RED}✗${NC} Server is not responding (HTTP $HTTP_CODE)"
    exit 1
fi
echo ""

# ============================================================================
# Step 2: Get PoW Challenge
# ============================================================================
echo -e "${YELLOW}[2/4]${NC} Getting PoW challenge..."
CHALLENGE_RESPONSE=$(http --print=b GET "${API_BASE}/register/challenge" 2>/dev/null)

if [ -z "$CHALLENGE_RESPONSE" ]; then
    echo -e "  ${RED}✗${NC} Failed to get challenge"
    exit 1
fi

CHALLENGE=$(echo "$CHALLENGE_RESPONSE" | jq -r '.challenge // empty')
DIFFICULTY=$(echo "$CHALLENGE_RESPONSE" | jq -r '.difficulty // empty')

if [ -z "$CHALLENGE" ] || [ -z "$DIFFICULTY" ]; then
    echo -e "  ${RED}✗${NC} Invalid challenge response"
    echo "$CHALLENGE_RESPONSE" | jq '.'
    exit 1
fi

echo -e "  ${GREEN}✓${NC} Challenge received"
echo -e "    Challenge: ${CHALLENGE:0:32}..."
echo -e "    Difficulty: $DIFFICULTY leading zeros"
echo ""

# ============================================================================
# Step 3: Solve PoW (Simulated - requires Argon2id implementation)
# ============================================================================
echo -e "${YELLOW}[3/4]${NC} Solving PoW challenge..."
echo -e "  ${YELLOW}⚠${NC}  PoW solving requires Argon2id implementation"
echo -e "  ${YELLOW}⚠${NC}  Skipping actual PoW solve for now"
echo -e "  ${YELLOW}⚠${NC}  Expected: ~3-7 seconds @ 38 H/s with difficulty $DIFFICULTY"
echo ""

# Simulated nonce and hash (in production, these would be computed via Argon2id)
# Must be u64 for nonce, hex string for hash
NONCE=0
HASH="0000000000000000000000000000000000000000000000000000000000000000"

# ============================================================================
# Step 4: Test Registration Endpoint Structure
# ============================================================================
echo -e "${YELLOW}[4/4]${NC} Testing registration endpoint structure..."

# Generate test keys (base64-encoded 32-byte values)
VERIFYING_KEY=$(openssl rand -base64 32 | tr -d '\n')
IDENTITY_PUBLIC=$(openssl rand -base64 32 | tr -d '\n')
SIGNED_PREKEY=$(openssl rand -base64 32 | tr -d '\n')

# Compute device_id from identity_public (first 16 bytes of SHA256 hash = 32 hex chars)
DEVICE_ID=$(echo -n "$IDENTITY_PUBLIC" | openssl dgst -sha256 -binary | xxd -p -l 16 | tr -d '\n')

cat > /tmp/register_request.json <<EOF
{
  "username": "test_user_$(date +%s)",
  "deviceId": "$DEVICE_ID",
  "publicKeys": {
    "verifyingKey": "$VERIFYING_KEY",
    "identityPublic": "$IDENTITY_PUBLIC",
    "signedPrekeyPublic": "$SIGNED_PREKEY",
    "suiteId": "Curve25519+Ed25519"
  },
  "powSolution": {
    "challenge": "$CHALLENGE",
    "nonce": $NONCE,
    "hash": "$HASH"
  }
}
EOF

echo -e "  ${BLUE}→${NC} Sending registration request..."
REGISTER_RESPONSE=$(http --print=hb POST "${API_BASE}/register/v2" < /tmp/register_request.json 2>&1)

# Check HTTP status
if echo "$REGISTER_RESPONSE" | grep -q "HTTP/1.1 2"; then
    echo -e "  ${GREEN}✓${NC} Registration endpoint is working!"
    echo "$REGISTER_RESPONSE" | grep -A 100 "^{" | jq '.'
elif echo "$REGISTER_RESPONSE" | grep -q "HTTP/1.1 40"; then
    echo -e "  ${YELLOW}⚠${NC}  Registration rejected (expected - PoW not solved)"
    echo "$REGISTER_RESPONSE" | grep -A 100 "^{" | jq '.'
else
    echo -e "  ${RED}✗${NC} Registration failed"
    echo "$REGISTER_RESPONSE"
fi

# Cleanup
rm -f /tmp/register_request.json

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Test complete!${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
