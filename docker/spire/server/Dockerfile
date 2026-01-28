# SPIRE Server Dockerfile
# Production-ready SPIRE Server for workload identity management

FROM ghcr.io/spiffe/spire-server:1.14.0

# Copy server configuration
COPY server.conf /opt/spire/conf/server/server.conf

# Expose SPIRE Server ports
# 8081 - Server API (agent connections, registration API)
# 8443 - Federation bundle endpoint (HTTPS)
EXPOSE 8081 8443

# Health check - verify server is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD /opt/spire/bin/spire-server healthcheck -socketPath /run/spire/sockets/server.sock || exit 1

# Run SPIRE Server
ENTRYPOINT ["/opt/spire/bin/spire-server", "run", "-config", "/opt/spire/conf/server/server.conf"]
