#!/bin/sh
set -e

# Wait for network to be ready
sleep 2

# Check if we have a join token
if [ -z "$SPIRE_JOIN_TOKEN" ]; then
    echo "SPIRE Agent: No join token provided (SPIRE_JOIN_TOKEN), agent disabled"
    # Keep running to not crash supervisor
    while true; do sleep 3600; done
fi

# Check if server address is set
if [ -z "$SPIRE_SERVER_ADDRESS" ]; then
    echo "SPIRE Agent: No server address (SPIRE_SERVER_ADDRESS), using default"
    export SPIRE_SERVER_ADDRESS="protocolsoup-spire.internal"
fi

# Update config with actual server address
sed -i "s/SPIRE_SERVER_PLACEHOLDER/$SPIRE_SERVER_ADDRESS/g" /opt/spire/conf/agent/agent.conf

echo "SPIRE Agent: Connecting to $SPIRE_SERVER_ADDRESS:8081"
echo "SPIRE Agent: Starting with join token..."

# Start the agent
exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent/agent.conf \
    -joinToken "$SPIRE_JOIN_TOKEN"

