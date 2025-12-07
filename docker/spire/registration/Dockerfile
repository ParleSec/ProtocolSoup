# SPIRE Registration Dockerfile
# Registers workload entries with SPIRE Server

FROM ghcr.io/spiffe/spire-server:1.9.6 AS spire

FROM alpine:3.19

# Copy SPIRE server binary for registration commands
COPY --from=spire /opt/spire/bin/spire-server /opt/spire/bin/spire-server

# Create directories
RUN mkdir -p /run/spire/sockets

# Copy registration script
COPY register-workloads.sh /opt/spire/bin/register-workloads.sh
RUN chmod +x /opt/spire/bin/register-workloads.sh && \
    sed -i 's/\r$//' /opt/spire/bin/register-workloads.sh

ENTRYPOINT ["/opt/spire/bin/register-workloads.sh"]

