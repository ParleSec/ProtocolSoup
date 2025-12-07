#!/bin/sh
# SPIRE Workload Registration Script

set -e

SOCKET_PATH="/run/spire/sockets/server.sock"

echo "============================================"
echo "SPIRE Workload Registration"
echo "Trust Domain: spiffe://protocolsoup.com"
echo "============================================"

# Wait for server socket
echo "Waiting for SPIRE Server socket..."
max_wait=30
waited=0
while [ ! -S "$SOCKET_PATH" ] && [ $waited -lt $max_wait ]; do
    sleep 1
    waited=$((waited + 1))
done

if [ ! -S "$SOCKET_PATH" ]; then
    echo "ERROR: Server socket not available"
    exit 1
fi

echo "Server socket available!"

# Function to create entry
create_entry() {
    local spiffe_id="$1"
    local parent_id="$2"
    shift 2
    local selectors="$@"
    
    echo ""
    echo "Creating entry: $spiffe_id"
    
    selector_args=""
    for selector in $selectors; do
        selector_args="$selector_args -selector $selector"
    done
    
    /opt/spire/bin/spire-server entry create \
        -socketPath "$SOCKET_PATH" \
        -spiffeID "$spiffe_id" \
        -parentID "$parent_id" \
        $selector_args \
        -ttl 3600 \
        2>/dev/null || echo "  Entry may already exist"
}

# Register workloads
echo ""
echo ">>> Registering Backend..."
create_entry \
    "spiffe://protocolsoup.com/workload/backend" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

echo ""
echo ">>> Registering Demo Client..."
create_entry \
    "spiffe://protocolsoup.com/workload/demo-client" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

echo ""
echo ">>> Registering Demo Service..."
create_entry \
    "spiffe://protocolsoup.com/workload/demo-service" \
    "spiffe://protocolsoup.com/agent/main" \
    "unix:uid:0"

echo ""
echo "============================================"
echo "Registered Entries:"
echo "============================================"
/opt/spire/bin/spire-server entry show -socketPath "$SOCKET_PATH"

echo ""
echo "Registration Complete!"

