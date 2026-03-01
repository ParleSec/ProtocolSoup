# ProtocolSoup Container Images

Documentation for all ProtocolSoup container images available on GitHub Container Registry.

## Core Services

| Image | Description | Docs |
|-------|-------------|------|
| [protocolsoup-gateway](https://ghcr.io/parlesec/protocolsoup-gateway) | API Gateway | [gateway.md](gateway.md) |
| [protocolsoup-federation](https://ghcr.io/parlesec/protocolsoup-federation) | OAuth/OIDC/SAML | [federation.md](federation.md) |
| [protocolsoup-vc](https://ghcr.io/parlesec/protocolsoup-vc) | OID4VCI + OID4VP APIs | [vc.md](vc.md) |
| [protocolsoup-scim](https://ghcr.io/parlesec/protocolsoup-scim) | SCIM 2.0 | [scim.md](scim.md) |
| [protocolsoup-ssf](https://ghcr.io/parlesec/protocolsoup-ssf) | Shared Signals | [ssf.md](ssf.md) |
| [protocolsoup-spiffe](https://ghcr.io/parlesec/protocolsoup-spiffe) | SPIFFE/SPIRE | [spiffe.md](spiffe.md) |
| [protocolsoup-frontend](https://ghcr.io/parlesec/protocolsoup-frontend) | React UI | [frontend.md](frontend.md) |
| [protocolsoup-wallet](https://ghcr.io/parlesec/protocolsoup-wallet) | OID4VP wallet harness | [wallet.md](wallet.md) |

## VC Protocol Modules

The federation and VC images expose these module-level protocol docs.

| Module | Description | Docs |
|--------|-------------|------|
| OID4VCI | Verifiable credential issuance (pre-authorized, `tx_code`, deferred) | [oid4vci.md](oid4vci.md) |
| OID4VP | Verifiable presentation verification (`direct_post`, `direct_post.jwt`) | [oid4vp.md](oid4vp.md) |

## SPIRE Infrastructure

| Image | Description | Docs |
|-------|-------------|------|
| [protocolsoup-spire-server](https://ghcr.io/parlesec/protocolsoup-spire-server) | SPIRE Server (CA) | [spire-server.md](spire-server.md) |
| [protocolsoup-spire-agent](https://ghcr.io/parlesec/protocolsoup-spire-agent) | SPIRE Agent | [spire-agent.md](spire-agent.md) |
| [protocolsoup-spire-registration](https://ghcr.io/parlesec/protocolsoup-spire-registration) | Bootstrap entries | [spire-registration.md](spire-registration.md) |

> **Note:** SPIRE containers require Unix socket sharing. On **Windows Docker**, use Docker Compose instead of standalone `docker run` commands. See individual package docs for details.

## Quick Start

### Single Service

```bash
# Run SCIM server
docker run -p 8080:8080 ghcr.io/parlesec/protocolsoup-scim

# Run Federation server (OAuth/OIDC/SAML)
docker run -p 8080:8080 ghcr.io/parlesec/protocolsoup-federation

# Run standalone VC API server (OID4VCI + OID4VP)
docker run -p 8080:8080 ghcr.io/parlesec/protocolsoup-vc

# Run wallet harness against local VC API server
docker run -p 8081:8080 \
  -e WALLET_TARGET_BASE_URL=http://host.docker.internal:8080 \
  ghcr.io/parlesec/protocolsoup-wallet

# Run SSF server (Shared Signals)
docker run -p 8080:8080 -p 8081:8081 ghcr.io/parlesec/protocolsoup-ssf
```

### Full Stack

```bash
git clone https://github.com/ParleSec/ProtocolLens
cd ProtocolLens/docker
docker compose up -d
```

### With SPIFFE

```bash
docker compose -f docker-compose.yml -f docker-compose.spiffe.yml up -d
```

## Pulling Images

All images are public and don't require authentication:

```bash
docker pull ghcr.io/parlesec/protocolsoup-<name>:latest
```
