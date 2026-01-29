# protocolsoup-scim

**SCIM 2.0 Server for User and Group Provisioning**

RFC 7642/7643/7644 compliant. Connect Okta, Azure AD, SailPoint, or any SCIM client for user lifecycle management.

## Quick Start

```bash
docker run -p 8080:8080 \
  -e SHOWCASE_BASE_URL=http://localhost:8080 \
  -e SCIM_API_TOKEN=your-secure-token \
  -v scim-data:/app/data \
  ghcr.io/parlesec/protocolsoup-scim
```

**Runs standalone** - SQLite storage included.

## Endpoints

### Discovery
| Endpoint | Description |
|----------|-------------|
| `GET /scim/v2/ServiceProviderConfig` | Server capabilities |
| `GET /scim/v2/ResourceTypes` | Available resource types |
| `GET /scim/v2/Schemas` | Schema definitions |

### Users
| Endpoint | Description |
|----------|-------------|
| `GET /scim/v2/Users` | List/filter users |
| `POST /scim/v2/Users` | Create user |
| `GET /scim/v2/Users/{id}` | Get user |
| `PUT /scim/v2/Users/{id}` | Replace user |
| `PATCH /scim/v2/Users/{id}` | Update user |
| `DELETE /scim/v2/Users/{id}` | Delete user |

### Groups
| Endpoint | Description |
|----------|-------------|
| `GET /scim/v2/Groups` | List groups |
| `POST /scim/v2/Groups` | Create group |
| `GET /scim/v2/Groups/{id}` | Get group by ID |
| `PATCH /scim/v2/Groups/{id}` | Update membership |
| `DELETE /scim/v2/Groups/{id}` | Delete group |

### Bulk
| Endpoint | Description |
|----------|-------------|
| `POST /scim/v2/Bulk` | Bulk operations |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOWCASE_BASE_URL` | `http://localhost:8080` | URL in resource metadata |
| `SHOWCASE_LISTEN_ADDR` | `:8080` | Listen address |
| `SCIM_API_TOKEN` | (none) | Bearer token for auth (open if unset) |
| `SCIM_DATA_DIR` | `/app/data` | SQLite storage path |

## Example IdP Integration

### Okta Setup

1. Create App → SCIM 2.0 Test App (OAuth Bearer Token)
2. Configure:
   - **Base URL:** `http://your-host:8080/scim/v2`
   - **Auth:** HTTP Header → `Bearer <SCIM_API_TOKEN>`
3. Enable provisioning features

### SailPoint ISC Setup

1. Create Source → SCIM 2.0 connector
2. Configure:
   - **Base URL:** `http://your-host:8080/scim/v2`
   - **Auth:** Bearer Token → `<SCIM_API_TOKEN>`
3. Discover schema and enable provisioning

### Azure AD Setup

1. Enterprise App → Provisioning → Automatic
2. Configure:
   - **Tenant URL:** `http://your-host:8080/scim/v2`
   - **Secret Token:** `<SCIM_API_TOKEN>`

## Demo Data

The container starts with demo users and groups:

**Users:**
| User | Department | Groups |
|------|------------|--------|
| `alice@example.com` | Engineering | Engineering, All Users |
| `bob@example.com` | Security | Engineering, All Users |
| `carol@example.com` | Product | All Users |

**Groups:**
- Engineering (Alice, Bob)
- All Users (Alice, Bob, Carol)

## Example: Create a User

```bash
curl -X POST http://localhost:8080/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "newuser@example.com",
    "name": {"givenName": "New", "familyName": "User"},
    "emails": [{"value": "newuser@example.com", "primary": true}],
    "active": true
  }'
```
