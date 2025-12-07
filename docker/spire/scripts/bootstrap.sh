#!/bin/bash
# SPIRE Infrastructure Bootstrap Script
#
# This script sets up the complete SPIRE infrastructure:
# 1. Starts SPIRE Server
# 2. Generates join token for agent
# 3. Starts SPIRE Agent with join token
# 4. Registers all workloads
#
# Usage: ./bootstrap.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$DOCKER_DIR")"

echo "============================================"
echo "SPIRE Infrastructure Bootstrap"
echo "Trust Domain: spiffe://protocolsoup.com"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    log_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Navigate to docker directory
cd "$PROJECT_DIR/docker"

# Step 1: Build and start SPIRE Server
echo ""
log_info "Step 1: Starting SPIRE Server..."
docker compose -f docker-compose.spire.yml up -d spire-server

# Wait for server to be healthy
log_info "Waiting for SPIRE Server to be healthy..."
for i in {1..30}; do
    if docker compose -f docker-compose.spire.yml exec spire-server \
        /opt/spire/bin/spire-server healthcheck -socketPath /run/spire/sockets/server.sock >/dev/null 2>&1; then
        log_info "SPIRE Server is healthy!"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "SPIRE Server failed to become healthy"
        exit 1
    fi
    echo -n "."
    sleep 2
done

# Step 2: Generate join token for agent
echo ""
log_info "Step 2: Generating join token for SPIRE Agent..."
JOIN_TOKEN=$(docker compose -f docker-compose.spire.yml exec -T spire-server \
    /opt/spire/bin/spire-server token generate \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://protocolsoup.com/agent/main \
    -ttl 3600 | grep "Token:" | awk '{print $2}')

if [ -z "$JOIN_TOKEN" ]; then
    log_error "Failed to generate join token"
    exit 1
fi

log_info "Join token generated: ${JOIN_TOKEN:0:20}..."

# Step 3: Start SPIRE Agent with join token
echo ""
log_info "Step 3: Starting SPIRE Agent..."
export SPIRE_JOIN_TOKEN="$JOIN_TOKEN"
docker compose -f docker-compose.spire.yml up -d spire-agent

# Wait for agent to be healthy
log_info "Waiting for SPIRE Agent to be healthy..."
for i in {1..30}; do
    if docker compose -f docker-compose.spire.yml exec spire-agent \
        /opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock >/dev/null 2>&1; then
        log_info "SPIRE Agent is healthy!"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "SPIRE Agent failed to become healthy"
        exit 1
    fi
    echo -n "."
    sleep 2
done

# Step 4: Register workloads
echo ""
log_info "Step 4: Registering workloads..."
docker compose -f docker-compose.spire.yml up spire-registration

# Step 5: Show registered entries
echo ""
log_info "Step 5: Verifying registration..."
echo ""
docker compose -f docker-compose.spire.yml exec spire-server \
    /opt/spire/bin/spire-server entry show \
    -socketPath /run/spire/sockets/server.sock

echo ""
echo "============================================"
log_info "SPIRE Infrastructure Bootstrap Complete!"
echo "============================================"
echo ""
echo "You can now start the main application with SPIFFE enabled:"
echo "  docker compose -f docker-compose.yml -f docker-compose.spire.yml up -d"
echo ""
echo "To verify SPIFFE is working:"
echo "  curl http://localhost:8080/spiffe/status"
echo ""
echo "Useful commands:"
echo "  # View registered entries"
echo "  docker compose -f docker-compose.spire.yml exec spire-server \\"
echo "      /opt/spire/bin/spire-server entry show -socketPath /run/spire/sockets/server.sock"
echo ""
echo "  # Generate a new join token"
echo "  docker compose -f docker-compose.spire.yml exec spire-server \\"
echo "      /opt/spire/bin/spire-server token generate -socketPath /run/spire/sockets/server.sock \\"
echo "      -spiffeID spiffe://protocolsoup.com/agent/main -ttl 3600"
echo ""
echo "  # View agent status"
echo "  docker compose -f docker-compose.spire.yml exec spire-agent \\"
echo "      /opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock"
echo ""

