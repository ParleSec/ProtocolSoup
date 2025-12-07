#!/bin/sh
# SPIRE Workload Registration Script
# 
# This script registers workload entries with the SPIRE Server.
# Registration entries define which SPIFFE IDs can be issued to which workloads.
#
# Run this script after the SPIRE Server and Agent are healthy.

set -e

SOCKET_PATH="/run/spire/sockets/server.sock"

echo "============================================"
echo "SPIRE Workload Registration"
echo "Trust Domain: spiffe://protocolsoup.com"
echo "============================================"

# Wait for server socket to be available
echo "Waiting for SPIRE Server socket..."
while [ ! -S "$SOCKET_PATH" ]; do
    sleep 1
done
echo "Server socket available."

# Function to create or update an entry
create_entry() {
    local spiffe_id="$1"
    local parent_id="$2"
    shift 2
    local selectors="$@"
    
    echo ""
    echo "Creating entry: $spiffe_id"
    echo "  Parent: $parent_id"
    echo "  Selectors: $selectors"
    
    # Build selector arguments
    selector_args=""
    for selector in $selectors; do
        selector_args="$selector_args -selector $selector"
    done
    
    # Create the entry (will fail if exists, which is fine)
    /opt/spire/bin/spire-server entry create \
        -socketPath "$SOCKET_PATH" \
        -spiffeID "$spiffe_id" \
        -parentID "$parent_id" \
        $selector_args \
        -ttl 3600 \
        2>/dev/null || echo "  Entry may already exist, skipping..."
}

# ============================================
# Create Agent Node Entry
# ============================================
echo ""
echo ">>> Registering SPIRE Agent..."

# First, we need to generate a join token for the agent
echo "Generating join token for agent..."
JOIN_TOKEN=$(/opt/spire/bin/spire-server token generate \
    -socketPath "$SOCKET_PATH" \
    -spiffeID "spiffe://protocolsoup.com/agent/main" \
    -ttl 3600 | grep "Token:" | awk '{print $2}')

if [ -n "$JOIN_TOKEN" ]; then
    echo "Join token generated: ${JOIN_TOKEN:0:10}..."
    echo "$JOIN_TOKEN" > /opt/spire/data/agent-join-token
else
    echo "Warning: Could not generate join token (agent may already be attested)"
fi

# ============================================
# Backend Workload Entry (using Unix attestor)
# ============================================
echo ""
echo ">>> Registering Backend Workload..."
create_entry \
    "spiffe://protocolsoup.com/workload/backend" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

# ============================================
# Demo Client Workload Entry
# ============================================
echo ""
echo ">>> Registering Demo Client Workload..."
create_entry \
    "spiffe://protocolsoup.com/workload/demo-client" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

# ============================================
# Demo Service Workload Entry
# ============================================
echo ""
echo ">>> Registering Demo Service Workload..."
create_entry \
    "spiffe://protocolsoup.com/workload/demo-service" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

# ============================================
# Admin/Debug Workload Entry (for development)
# ============================================
echo ""
echo ">>> Registering Admin Workload..."
create_entry \
    "spiffe://protocolsoup.com/workload/admin" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

# ============================================
# List all registered entries
# ============================================
echo ""
echo "============================================"
echo "Registered Workload Entries:"
echo "============================================"
/opt/spire/bin/spire-server entry show -socketPath "$SOCKET_PATH"

# ============================================
# Display Trust Bundle
# ============================================
echo ""
echo "============================================"
echo "Trust Bundle (Root CA):"
echo "============================================"
/opt/spire/bin/spire-server bundle show -socketPath "$SOCKET_PATH" | head -20
echo "... (truncated)"

echo ""
echo "============================================"
echo "Registration Complete!"
echo "============================================"
echo ""
echo "Workloads can now request SVIDs by connecting to:"
echo "  Socket: /run/spire/sockets/agent.sock"
echo ""
echo "Trust Bundle endpoint available at:"
echo "  https://spire-server:8443/bundle"
echo ""

