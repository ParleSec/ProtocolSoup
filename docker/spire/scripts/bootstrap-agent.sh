#!/bin/sh
# SPIRE Agent Bootstrap Script
# Generates a join token from the server and starts the agent with it

set -e

SERVER_SOCKET="/run/spire/sockets/server/server.sock"
TOKEN_FILE="/run/spire/bootstrap/join-token"
AGENT_ID="spiffe://protocolsoup.com/agent/main"

echo "============================================"
echo "SPIRE Agent Bootstrap"
echo "============================================"

# Wait for server socket
echo "Waiting for SPIRE Server socket at ${SERVER_SOCKET}..."
max_wait=60
waited=0
while [ ! -S "$SERVER_SOCKET" ] && [ $waited -lt $max_wait ]; do
    sleep 1
    waited=$((waited + 1))
    echo "  Waiting... (${waited}s)"
done

if [ ! -S "$SERVER_SOCKET" ]; then
    echo "ERROR: Server socket not available after ${max_wait}s"
    exit 1
fi

echo "Server socket available!"

# Check if we already have a valid SVID (agent already attested)
if [ -f "/opt/spire/data/agent/agent_svid.der" ]; then
    echo "Agent SVID found - agent may already be attested"
    echo "Skipping token generation, starting agent..."
    exec /opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf
fi

# Generate join token
echo "Generating join token for agent..."
TOKEN=$(/opt/spire/bin/spire-server token generate \
    -socketPath "$SERVER_SOCKET" \
    -spiffeID "$AGENT_ID" \
    -ttl 600 2>&1 | grep -o 'Token: [^ ]*' | cut -d' ' -f2)

if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to generate join token"
    exit 1
fi

echo "Join token generated successfully!"
echo "Token (first 10 chars): ${TOKEN:0:10}..."

# Save token for debugging (optional)
mkdir -p /run/spire/bootstrap
echo "$TOKEN" > "$TOKEN_FILE"

# Start agent with the join token
echo "Starting SPIRE Agent with join token..."
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "$TOKEN"

