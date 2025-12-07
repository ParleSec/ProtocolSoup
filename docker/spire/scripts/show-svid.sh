#!/bin/sh
# Display current SVID information from the SPIRE Agent Workload API
#
# Usage: ./show-svid.sh
#
# This script connects to the Workload API and displays the current SVID.

set -e

SOCKET_PATH="${SPIFFE_ENDPOINT_SOCKET:-/run/spire/sockets/agent.sock}"

echo "============================================"
echo "SVID Information"
echo "============================================"

# Check if socket exists
if [ ! -S "$SOCKET_PATH" ]; then
    echo "Error: Workload API socket not found at $SOCKET_PATH"
    exit 1
fi

echo "Socket: $SOCKET_PATH"
echo ""

# Use the spire-agent api command if available
if command -v spire-agent >/dev/null 2>&1; then
    echo "X.509 SVID:"
    echo "-----------"
    spire-agent api fetch x509 -socketPath "$SOCKET_PATH" -write /tmp/svid || true
    
    if [ -f /tmp/svid.0.pem ]; then
        openssl x509 -in /tmp/svid.0.pem -text -noout 2>/dev/null | head -30
        rm -f /tmp/svid.*.pem /tmp/bundle.*.pem
    fi
    
    echo ""
    echo "JWT SVID:"
    echo "---------"
    spire-agent api fetch jwt -audience "protocolsoup" -socketPath "$SOCKET_PATH" 2>/dev/null || echo "Could not fetch JWT-SVID"
else
    echo "Note: spire-agent binary not available"
    echo "Install go-spiffe tools or use the SDK to fetch SVIDs"
fi

