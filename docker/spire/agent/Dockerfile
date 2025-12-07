# SPIRE Agent Dockerfile with Shell Support
# Uses Alpine base with SPIRE binaries for bootstrap capability

FROM ghcr.io/spiffe/spire-agent:1.9.6 AS spire-agent
FROM ghcr.io/spiffe/spire-server:1.9.6 AS spire-server

FROM alpine:3.19

# Install required utilities
RUN apk add --no-cache ca-certificates

# Copy SPIRE binaries from official images
COPY --from=spire-agent /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
COPY --from=spire-server /opt/spire/bin/spire-server /opt/spire/bin/spire-server

# Create directories
RUN mkdir -p /opt/spire/conf/agent /opt/spire/data/agent /run/spire/sockets

# Copy agent configuration
COPY agent.conf /opt/spire/conf/agent/agent.conf

# Copy bootstrap script
COPY bootstrap-agent.sh /opt/spire/bin/bootstrap-agent.sh
RUN chmod +x /opt/spire/bin/bootstrap-agent.sh && \
    sed -i 's/\r$//' /opt/spire/bin/bootstrap-agent.sh

# Health check - verify agent is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD /opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock || exit 1

# Run bootstrap script
ENTRYPOINT ["/opt/spire/bin/bootstrap-agent.sh"]
