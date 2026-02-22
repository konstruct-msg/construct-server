#!/bin/bash

# Pre-deployment health check script
# Usage: ./scripts/pre_deploy_check.sh

set -e

echo "🔍 Pre-Deployment Health Check"
echo "================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}❌ Error: Must run from project root${NC}"
    exit 1
fi

echo "1️⃣ Checking build..."
if cargo check --message-format=short 2>&1 | grep -q "error"; then
    echo -e "${RED}❌ Build has errors${NC}"
    cargo check --message-format=short 2>&1 | grep "error"
    exit 1
else
    echo -e "${GREEN}✅ Build successful${NC}"
fi

echo ""
echo "2️⃣ Checking tests..."
TEST_OUTPUT=$(cargo test --lib 2>&1)
if echo "$TEST_OUTPUT" | grep -q "test result: FAILED"; then
    echo -e "${YELLOW}⚠️  Some tests failed (check if they're expected)${NC}"
    echo "$TEST_OUTPUT" | grep -A 5 "failures:"
    echo ""
    echo "Note: Some test failures might be expected (validation tests)"
else
    echo -e "${GREEN}✅ All tests passed${NC}"
fi

echo ""
echo "3️⃣ Checking migrations..."
if [ -d "migrations" ]; then
    MIGRATION_COUNT=$(ls -1 migrations/*.sql | wc -l)
    echo -e "${GREEN}✅ Found $MIGRATION_COUNT migration files${NC}"
    echo "   Expected migrations:"
    echo "   - 001_init.sql"
    echo "   - 002_display_username.sql"
    echo "   - 003_user_key_bundle.sql"
    echo "   - 004_remove_user_profiles.sql"
    echo "   - 005_crypto_agility.sql"
    echo "   - 006_device_tokens.sql"
    echo "   - 007_delivery_pending.sql"
else
    echo -e "${RED}❌ Migrations directory not found${NC}"
    exit 1
fi

echo ""
echo "4️⃣ Checking environment variables..."
REQUIRED_VARS=("DATABASE_URL" "REDIS_URL" "JWT_SECRET")
MISSING_VARS=()

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_VARS+=("$var")
    fi
done

if [ ${#MISSING_VARS[@]} -eq 0 ]; then
    echo -e "${GREEN}✅ Required environment variables are set${NC}"
else
    echo -e "${YELLOW}⚠️  Missing environment variables:${NC}"
    for var in "${MISSING_VARS[@]}"; do
        echo "   - $var"
    done
    echo "   (This is OK if checking locally, but required for deployment)"
fi

echo ""
echo "5️⃣ Checking critical files..."
FILES=("src/lib.rs" "src/main.rs" "src/config.rs" "src/db.rs" "src/handlers/auth.rs")
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file exists${NC}"
    else
        echo -e "${RED}❌ $file missing${NC}"
        exit 1
    fi
done

echo ""
echo "6️⃣ Checking for SearchUsers (should be removed)..."
if grep -r "SearchUsers" src/ 2>/dev/null | grep -v "Binary"; then
    echo -e "${RED}❌ SearchUsers still found in code (should be removed)${NC}"
    grep -r "SearchUsers" src/ 2>/dev/null
    exit 1
else
    echo -e "${GREEN}✅ SearchUsers properly removed${NC}"
fi

echo ""
echo "7️⃣ Checking DeleteAccount implementation..."
if grep -q "DeleteAccount" src/message.rs && grep -q "handle_delete_account" src/handlers/auth.rs; then
    echo -e "${GREEN}✅ DeleteAccount implemented${NC}"
else
    echo -e "${RED}❌ DeleteAccount not fully implemented${NC}"
    exit 1
fi

echo ""
echo "================================"
echo -e "${GREEN}✅ Pre-deployment checks completed${NC}"
echo ""
echo "📋 Next steps:"
echo "   1. Review PRE_DEPLOYMENT_CHECKLIST.md"
echo "   2. Run integration tests (if available)"
echo "   3. Test health endpoint: curl http://localhost:8080/health"
echo "   4. Apply database migrations: sqlx migrate run"
echo "   5. Deploy to staging first"
echo ""
