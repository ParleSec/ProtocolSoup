# protocolsoup-ssf

**Shared Signals Framework - Security Event Transmitter & Receiver**

Real-time security event sharing with CAEP and RISC support. Generates and validates Security Event Tokens (SETs) per RFC 8417.

## Quick Start

```bash
docker run -p 8080:8080 -p 8081:8081 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -v ssf-data:/app/data \
  ghcr.io/parlesec/protocolsoup-ssf
```

**Runs standalone** - generates own signing keys.

## Ports

| Port | Description |
|------|-------------|
| `8080` | Main API (transmitter, discovery) |
| `8081` | Standalone receiver for external push delivery |

## Endpoints

### Discovery
| Endpoint | Description |
|----------|-------------|
| `GET /ssf/.well-known/ssf-configuration` | SSF Discovery |
| `GET /ssf/jwks` | Signing keys (JWKS) |

### Stream Management
| Endpoint | Description |
|----------|-------------|
| `POST /ssf/stream` | Create event stream |
| `GET /ssf/stream/{id}` | Get stream config |
| `PUT /ssf/stream/{id}` | Update stream |
| `DELETE /ssf/stream/{id}` | Delete stream |
| `POST /ssf/stream/{id}/subjects` | Add subject to stream |
| `DELETE /ssf/stream/{id}/subjects/{subject}` | Remove subject |
| `POST /ssf/stream/{id}/events` | Emit event to stream |
| `GET /ssf/stream/{id}/events` | List stream events |

### Events
| Endpoint | Description |
|----------|-------------|
| `POST /ssf/actions/{event-type}` | Trigger security event (demo) |
| `GET /ssf/security-state/{email}` | User security state |

### Receiver (Port 8081)

The standalone receiver runs on a separate port for external transmitters to push events.

| Endpoint | Description |
|----------|-------------|
| `POST /ssf/receiver/push` | SET push delivery endpoint |
| `GET /ssf/receiver/events` | List received events |
| `POST /ssf/receiver/events/{id}/ack` | Acknowledge event |

## Supported Event Types

### CAEP (Continuous Access Evaluation Protocol)
- `session-revoked` - User session terminated
- `token-claims-change` - Token claims updated
- `credential-change` - Password/credential changed

### RISC (Risk Incident Sharing and Coordination)
- `account-disabled` - Account suspended
- `account-enabled` - Account reactivated
- `identifier-changed` - Email/username changed

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | Issuer in SETs |
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Main API listen address |
| `SSF_DATA_DIR` | `/app/data` | SQLite storage |
| `SSF_RECEIVER_PORT` | `8081` | Standalone receiver port |
| `SSF_RECEIVER_TOKEN` | (auto) | Bearer token for push auth |

## Example: Create a Stream

```bash
curl -X POST http://localhost:8080/ssf/stream \
  -H "Content-Type: application/json" \
  -d '{
    "delivery": {
      "method": "https://schemas.openid.net/secevent/risc/delivery-method/push",
      "url": "http://localhost:8081/ssf/receiver/push"
    },
    "events_requested": [
      "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
      "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    ]
  }'
```

## Example: Trigger a Security Event

```bash
curl -X POST http://localhost:8080/ssf/actions/session-revoked \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "alice@example.com",
    "reason": "User requested logout from all devices"
  }'
```
