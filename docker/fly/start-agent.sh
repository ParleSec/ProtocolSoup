#!/bin/sh
# SPIRE Agent startup script with intelligent recovery
# Prioritizes reconnection with cached identity, falls back to join token

set -e

# Use consolidated volume at /data/spire
AGENT_DATA_DIR="/data/spire"
AGENT_CONF="/opt/spire/conf/agent/agent.conf"

# Ensure data directories exist
mkdir -p "$AGENT_DATA_DIR"
mkdir -p /data/scim

# Wait for network to be ready
sleep 2

# Check if server address is set
if [ -z "$SPIRE_SERVER_ADDRESS" ]; then
    echo "SPIRE Agent: No server address (SPIRE_SERVER_ADDRESS), using default"
    export SPIRE_SERVER_ADDRESS="protocolsoup-spire.internal"
fi

# Update config with actual server address
sed -i "s/SPIRE_SERVER_PLACEHOLDER/$SPIRE_SERVER_ADDRESS/g" "$AGENT_CONF"

echo "SPIRE Agent: Connecting to $SPIRE_SERVER_ADDRESS:8081"

# Check for join token
if [ -z "$SPIRE_JOIN_TOKEN" ]; then
    echo "SPIRE Agent: No join token provided (SPIRE_JOIN_TOKEN), agent disabled"
    echo "SPIRE Agent: Running in disabled mode - SPIFFE features will use demo data"
    while true; do sleep 3600; done
fi

# Check if we have valid cached data
AGENT_DATA="$AGENT_DATA_DIR/agent-data.json"
HAS_CACHED_DATA="false"

if [ -f "$AGENT_DATA" ]; then
    echo "SPIRE Agent: Found cached data, checking validity..."
    
    # Check file age - if older than 60 days, clear it (CA TTL is 90 days)
    # This gives us a buffer before the trust bundle becomes invalid
    if [ "$(find "$AGENT_DATA" -mtime -60 2>/dev/null)" ]; then
        echo "SPIRE Agent: Cached data is recent (< 60 days old)"
        HAS_CACHED_DATA="true"
    else
        echo "SPIRE Agent: Cached data is stale (> 60 days old), clearing..."
        rm -f "$AGENT_DATA_DIR/agent-data.json"
        rm -f "$AGENT_DATA_DIR/keys.json"
        rm -f "$AGENT_DATA_DIR/svid.key"
        rm -f "$AGENT_DATA_DIR/bundle.der"
    fi
fi

if [ "$HAS_CACHED_DATA" = "true" ]; then
    echo "SPIRE Agent: Attempting reconnection with cached identity..."
    
    # Start agent WITHOUT join token - it will use cached identity
    exec /opt/spire/bin/spire-agent run -config "$AGENT_CONF"
else
    echo "SPIRE Agent: Starting fresh attestation with join token..."
    
    # Start agent WITH join token for fresh attestation
    exec /opt/spire/bin/spire-agent run \
        -config "$AGENT_CONF" \
        -joinToken "$SPIRE_JOIN_TOKEN"
fi
