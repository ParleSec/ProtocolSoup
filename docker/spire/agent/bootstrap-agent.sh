#!/bin/sh
set -e

SERVER_SOCKET="/run/spire/sockets/server/server.sock"
TOKEN_FILE="/run/spire/bootstrap/join-token"
AGENT_ID="spiffe://protocolsoup.com/agent/main"

echo "============================================"
echo "SPIRE Agent Bootstrap"
echo "============================================"

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

if [ -f "/opt/spire/data/agent/agent_svid.der" ]; then
    echo "Agent SVID found - agent may already be attested"
    echo "Starting agent..."
    exec /opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf
fi

echo "Generating join token for agent..."
TOKEN=$(/opt/spire/bin/spire-server token generate \
    -socketPath "$SERVER_SOCKET" \
    -spiffeID "$AGENT_ID" \
    -ttl 600 2>&1 | grep -o 'Token: [^ ]*' | cut -d' ' -f2)

if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to generate join token"
    exit 1
fi

echo "Join token generated!"
echo "Starting SPIRE Agent..."
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "$TOKEN"
