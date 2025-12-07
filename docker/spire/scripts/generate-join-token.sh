#!/bin/sh
# Generate a join token for SPIRE Agent attestation
#
# Usage: ./generate-join-token.sh
#
# This script should be run on a machine with access to the SPIRE Server socket.

set -e

SOCKET_PATH="${SPIRE_SERVER_SOCKET:-/run/spire/sockets/server.sock}"
SPIFFE_ID="${AGENT_SPIFFE_ID:-spiffe://protocolsoup.com/agent/main}"
TTL="${TOKEN_TTL:-3600}"

echo "Generating join token..."
echo "  SPIFFE ID: $SPIFFE_ID"
echo "  TTL: ${TTL}s"

TOKEN=$(/opt/spire/bin/spire-server token generate \
    -socketPath "$SOCKET_PATH" \
    -spiffeID "$SPIFFE_ID" \
    -ttl "$TTL" | grep "Token:" | awk '{print $2}')

if [ -n "$TOKEN" ]; then
    echo ""
    echo "Join Token: $TOKEN"
    echo ""
    echo "Use this token to start the SPIRE Agent:"
    echo "  spire-agent run -joinToken $TOKEN -config /path/to/agent.conf"
    echo ""
    echo "Or set the environment variable:"
    echo "  export SPIRE_JOIN_TOKEN=$TOKEN"
else
    echo "Error: Failed to generate join token"
    exit 1
fi

