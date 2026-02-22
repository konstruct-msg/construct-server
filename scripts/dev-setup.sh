#!/bin/bash
# Quick setup script for local development environment
# This script sets up everything needed for local development

set -e

COLOR_INFO="\033[0;36m"
COLOR_SUCCESS="\033[0;32m"
COLOR_ERROR="\033[0;31m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_INFO}╔══════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_INFO}║     🚀 Construct Server - Local Development Setup               ║${COLOR_RESET}"
echo -e "${COLOR_INFO}╚══════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
echo ""

# ============================================================================
# Step 1: Check prerequisites
# ============================================================================
echo -e "${COLOR_INFO}📋 Step 1: Checking prerequisites...${COLOR_RESET}"

if ! command -v docker &> /dev/null; then
    echo -e "${COLOR_ERROR}❌ Docker is not installed${COLOR_RESET}"
    echo "   Install from: https://www.docker.com/get-started"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${COLOR_ERROR}❌ docker-compose is not installed${COLOR_RESET}"
    echo "   Install from: https://docs.docker.com/compose/install/"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${COLOR_ERROR}❌ Rust/Cargo is not installed${COLOR_RESET}"
    echo "   Install from: https://rustup.rs/"
    exit 1
fi

echo -e "${COLOR_SUCCESS}   ✅ All prerequisites installed${COLOR_RESET}"
echo ""

# ============================================================================
# Step 2: Create .env.local if needed
# ============================================================================
echo -e "${COLOR_INFO}📝 Step 2: Setting up .env.local...${COLOR_RESET}"

if [ ! -f .env.local ]; then
    echo -e "${COLOR_INFO}   Creating .env.local from example...${COLOR_RESET}"
    cp .env.local.example .env.local
    echo -e "${COLOR_SUCCESS}   ✅ .env.local created${COLOR_RESET}"
    echo -e "${COLOR_INFO}   💡 Edit .env.local to customize your environment${COLOR_RESET}"
else
    echo -e "${COLOR_SUCCESS}   ✅ .env.local already exists${COLOR_RESET}"
fi
echo ""

# ============================================================================
# Step 3: Check JWT keys
# ============================================================================
echo -e "${COLOR_INFO}🔑 Step 3: Checking JWT keys...${COLOR_RESET}"

if [ ! -f prkeys/jwt_private_key.pem ] || [ ! -f prkeys/jwt_public_key.pem ]; then
    echo -e "${COLOR_INFO}   Generating RSA keypair for JWT...${COLOR_RESET}"
    mkdir -p prkeys
    openssl genrsa -out prkeys/jwt_private_key.pem 4096 2>/dev/null
    openssl rsa -in prkeys/jwt_private_key.pem -pubout -out prkeys/jwt_public_key.pem 2>/dev/null
    echo -e "${COLOR_SUCCESS}   ✅ JWT keys generated${COLOR_RESET}"
else
    echo -e "${COLOR_SUCCESS}   ✅ JWT keys exist${COLOR_RESET}"
fi
echo ""

# ============================================================================
# Step 4: Start infrastructure
# ============================================================================
echo -e "${COLOR_INFO}🐳 Step 4: Starting infrastructure (PostgreSQL + Redis + Kafka)...${COLOR_RESET}"

make dev >/dev/null 2>&1 &
MAKE_PID=$!

# Wait for make dev to complete
wait $MAKE_PID

echo ""
echo -e "${COLOR_INFO}⏳ Waiting for services to be healthy...${COLOR_RESET}"
sleep 5

# Check PostgreSQL
echo -e "${COLOR_INFO}   Checking PostgreSQL...${COLOR_RESET}"
for i in {1..30}; do
    if docker exec construct-db pg_isready -U construct >/dev/null 2>&1; then
        echo -e "${COLOR_SUCCESS}   ✅ PostgreSQL is ready${COLOR_RESET}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${COLOR_ERROR}   ❌ PostgreSQL failed to start${COLOR_RESET}"
        exit 1
    fi
    sleep 1
done

# Check Redis
echo -e "${COLOR_INFO}   Checking Redis...${COLOR_RESET}"
if docker exec construct-redis redis-cli ping >/dev/null 2>&1; then
    echo -e "${COLOR_SUCCESS}   ✅ Redis is ready${COLOR_RESET}"
else
    echo -e "${COLOR_ERROR}   ❌ Redis failed to start${COLOR_RESET}"
    exit 1
fi

echo ""

# ============================================================================
# Step 5: Run migrations
# ============================================================================
echo -e "${COLOR_INFO}🗄️  Step 5: Running database migrations...${COLOR_RESET}"

if [ -d "shared/migrations" ]; then
    # Check if sqlx-cli is installed
    if command -v sqlx &> /dev/null; then
        DATABASE_URL="postgresql://construct:construct_dev_password@localhost:5432/construct"
        sqlx migrate run --source shared/migrations >/dev/null 2>&1 || true
        echo -e "${COLOR_SUCCESS}   ✅ Migrations applied${COLOR_RESET}"
    else
        echo -e "${COLOR_INFO}   ⚠️  sqlx-cli not installed, skipping migrations${COLOR_RESET}"
        echo -e "${COLOR_INFO}      Install: cargo install sqlx-cli --no-default-features --features postgres${COLOR_RESET}"
    fi
else
    echo -e "${COLOR_INFO}   ⚠️  No migrations found${COLOR_RESET}"
fi
echo ""

# ============================================================================
# Done!
# ============================================================================
echo -e "${COLOR_SUCCESS}╔══════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_SUCCESS}║     ✅ LOCAL DEVELOPMENT ENVIRONMENT READY!                      ║${COLOR_RESET}"
echo -e "${COLOR_SUCCESS}╚══════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
echo ""
echo -e "${COLOR_INFO}🎯 Infrastructure running:${COLOR_RESET}"
echo "   PostgreSQL: localhost:5432 (user: construct, password: construct_dev_password)"
echo "   Redis: localhost:6379"
echo "   Kafka: localhost:9092"
echo "   Kafka UI: http://localhost:8080"
echo ""
echo -e "${COLOR_INFO}🚀 Next steps:${COLOR_RESET}"
echo ""
echo -e "${COLOR_INFO}Option 1: Run services locally (native)${COLOR_RESET}"
echo "   cargo run --bin messaging-service"
echo "   cargo run --bin auth-service"
echo "   cargo run --bin delivery-worker"
echo "   (etc.)"
echo ""
echo -e "${COLOR_INFO}Option 2: Run services in Docker${COLOR_RESET}"
echo "   make dev-services         # Start all services"
echo "   make dev-services-logs    # View logs"
echo "   make dev-services-down    # Stop services"
echo ""
echo -e "${COLOR_INFO}📊 Monitoring:${COLOR_RESET}"
echo "   make dev-logs             # Infrastructure logs"
echo "   docker ps                 # Check running containers"
echo ""
echo -e "${COLOR_INFO}🛑 Cleanup:${COLOR_RESET}"
echo "   make dev-down             # Stop infrastructure"
echo "   make dev-services-down    # Stop microservices"
echo ""
