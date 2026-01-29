# protocolsoup-frontend

**React UI for ProtocolSoup**

Interactive dashboard for exploring authentication protocols with Looking Glass visualization.

## Quick Start

```bash
docker run -p 3000:3000 \
  ghcr.io/parlesec/protocolsoup-frontend
```

**Requires:** Backend service(s) running on port 8080 (Gateway or individual services)

## Features

- **Protocol Explorer** - Browse OAuth 2.0, OIDC, SAML, SCIM, SSF, SPIFFE
- **Looking Glass** - Real-time protocol flow visualization
- **Token Inspector** - Decode and inspect JWTs, SAML assertions
- **SSF Sandbox** - Interactive security event testing
- **Flow Diagrams** - Step-by-step protocol animations

## Architecture

```
┌─────────────────┐      ┌─────────────────┐
│    Frontend     │----->│     Gateway     │
│   (port 3000)   │      │   (port 8080)   │
└─────────────────┘      └─────────────────┘
```

The frontend expects backend APIs at `http://localhost:8080` by default.

## Full Stack Example

```bash
# Start backend services
docker run -d -p 8080:8080 --name federation \
  ghcr.io/parlesec/protocolsoup-federation

# Start frontend
docker run -d -p 3000:3000 --name frontend \
  ghcr.io/parlesec/protocolsoup-frontend

# Open browser
open http://localhost:3000
```

## Docker Compose

```yaml
services:
  frontend:
    image: ghcr.io/parlesec/protocolsoup-frontend
    ports:
      - "3000:3000"
    depends_on:
      - gateway

  gateway:
    image: ghcr.io/parlesec/protocolsoup-gateway
    ports:
      - "8080:8080"
    environment:
      - FEDERATION_SERVICE_URL=http://federation:8080
    depends_on:
      - federation

  federation:
    image: ghcr.io/parlesec/protocolsoup-federation
```

## Environment Variables

The frontend is pre-built and doesn't require runtime configuration. API URL is determined by the browser's location.
